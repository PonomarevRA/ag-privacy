using System.Text;
using System.Xml;

namespace AgPrivacy;

public sealed partial class StructuredPrivacyMasker
{
    private const string XmlNamespace = "http://www.w3.org/XML/1998/namespace";
    private const string XmlnsNamespace = "http://www.w3.org/2000/xmlns/";

    /// <summary>Process an XML document incrementally, using local element and attribute names as field names.</summary>
    public async Task<StreamMaskResult> MaskXmlAsync(Stream input, Stream output,
        TextWriter? journal = null, CancellationToken cancellationToken = default)
    {
        using var source = new StreamReader(input, InputUtf8, detectEncodingFromByteOrderMarks: false, leaveOpen: true);
        using var reader = XmlReader.Create(source, new XmlReaderSettings
        {
            Async = true, DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null,
            IgnoreComments = true, IgnoreProcessingInstructions = true
        });
        await using var writer = XmlWriter.Create(output, new XmlWriterSettings
        {
            Async = true, Encoding = Utf8, NewLineHandling = NewLineHandling.Entitize,
            WriteEndDocumentOnClose = false, OmitXmlDeclaration = false
        });
        var state = new State(this, journal);
        var elements = new Stack<XmlContext>();
        var value = new StringBuilder();
        var buffer = new char[4096];

        while (await reader.ReadAsync().ConfigureAwait(false))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var context = elements.Count == 0 ? default : elements.Peek();
            if (reader.NodeType is XmlNodeType.Text or XmlNodeType.CDATA or XmlNodeType.Whitespace or XmlNodeType.SignificantWhitespace)
            {
                await ReadXmlValueAsync(reader, value, buffer, cancellationToken).ConfigureAwait(false);
                continue;
            }
            if (value.Length > 0)
            {
                string text = value.ToString();
                if (elements.Count == 0) await writer.WriteWhitespaceAsync(text).ConfigureAwait(false);
                else await writer.WriteStringAsync(state.Mask(text, context.Rule, context.PreserveGuid)).ConfigureAwait(false);
                value.Clear();
                await state.WriteJournalAsync(cancellationToken).ConfigureAwait(false);
            }

            if (reader.NodeType == XmlNodeType.Element)
            {
                if (elements.Count >= PrivacyLimits.Depth) throw new InvalidDataException("xml-depth-limit");
                string? rule = context.Rule ?? FieldRule(reader.LocalName);
                string name = reader.LocalName;
                var element = new XmlContext(rule,
                    name.Equals("trace", StringComparison.OrdinalIgnoreCase),
                    IsCorrelation(name) || context.IsTrace && name.Equals("id", StringComparison.OrdinalIgnoreCase));
                bool empty = reader.IsEmptyElement;
                await writer.WriteStartElementAsync(reader.Prefix, reader.LocalName, reader.NamespaceURI).ConfigureAwait(false);
                await WriteAttributesAsync(reader, writer, state, element, value, buffer, cancellationToken).ConfigureAwait(false);
                await state.WriteJournalAsync(cancellationToken).ConfigureAwait(false);
                if (empty) await writer.WriteEndElementAsync().ConfigureAwait(false);
                else elements.Push(element);
            }
            else if (reader.NodeType == XmlNodeType.EndElement)
            {
                elements.Pop();
                await writer.WriteFullEndElementAsync().ConfigureAwait(false);
                if (state.ShouldFlush()) await writer.FlushAsync().ConfigureAwait(false);
            }
        }

        if (value.Length > 0) await writer.WriteWhitespaceAsync(value.ToString()).ConfigureAwait(false);
        await writer.FlushAsync().ConfigureAwait(false);
        return state.Result();
    }

    /// <summary>Retain namespace and XML control attributes and evaluate data attributes by name.</summary>
    private async Task WriteAttributesAsync(XmlReader reader, XmlWriter writer, State state, XmlContext element,
        StringBuilder value, char[] buffer, CancellationToken cancellationToken)
    {
        if (reader.AttributeCount > FieldLimit) throw new InvalidDataException("xml-attribute-limit");
        while (reader.MoveToNextAttribute())
        {
            await ReadXmlValueAsync(reader, value, buffer, cancellationToken).ConfigureAwait(false);
            string text = value.ToString();
            value.Clear();
            if (reader.NamespaceURI != XmlnsNamespace && (reader.NamespaceURI != XmlNamespace || reader.LocalName != "space"))
            {
                string field = reader.LocalName;
                bool preserveGuid = IsCorrelation(field) || element.IsTrace && field.Equals("id", StringComparison.OrdinalIgnoreCase);
                text = state.Mask(text, FieldRule(field) ?? element.Rule, preserveGuid);
            }
            await writer.WriteAttributeStringAsync(reader.Prefix, reader.LocalName, reader.NamespaceURI, text).ConfigureAwait(false);
        }
        reader.MoveToElement();
    }

    private readonly record struct XmlContext(string? Rule, bool IsTrace, bool PreserveGuid);

    /// <summary>Bound the size of a logical text run, including adjacent escaped text and CDATA.</summary>
    private static async Task ReadXmlValueAsync(XmlReader reader, StringBuilder value, char[] buffer, CancellationToken cancellationToken)
    {
        int count;
        while ((count = await reader.ReadValueChunkAsync(buffer, 0, buffer.Length).ConfigureAwait(false)) != 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (value.Length + count > UnitChars) throw new InvalidDataException("xml-value-limit");
            value.Append(buffer, 0, count);
        }
    }
}
