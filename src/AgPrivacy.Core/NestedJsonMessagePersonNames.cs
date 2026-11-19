using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace AgPrivacy;

/// <summary>Find message strings in JSON carried inside one or more JSON strings.</summary>
internal static partial class NestedJsonMessagePersonNames
{
    private const int MaxWrappers = 8;

    /// <summary>Read structured payloads in a log and project nested sensitive spans onto the original text.</summary>
    internal static bool Add(string text, List<EntitySpan> spans, DisplayFieldExceptions exceptions)
    {
        if (!text.Contains("\\\"", StringComparison.Ordinal) && !text.Contains("\\u0022", StringComparison.Ordinal))
            return false;

        bool foundStructure = false;
        int consumed = 0;
        var watch = Stopwatch.StartNew();
        foreach (Match candidate in JsonStarts().Matches(text))
        {
            if (candidate.Index < consumed) continue;
            var frame = new Frame(text, candidate.Index, null);
            foundStructure |= Walk(frame, 0, spans, exceptions, watch, out int length);
            consumed = candidate.Index + length;
        }
        return foundStructure;
    }

    /// <summary>Validate one complete JSON value before reading its strings. A log suffix may follow the value.</summary>
    private static bool Walk(Frame frame, int wrappers, List<EntitySpan> spans, DisplayFieldExceptions exceptions,
        Stopwatch watch, out int consumed)
    {
        consumed = 0;
        if (watch.ElapsedMilliseconds > 250 || spans.Count >= PrivacyLimits.Entities)
            throw new InvalidOperationException("analysis-limit");

        byte[] utf8 = Encoding.UTF8.GetBytes(frame.Start == 0 ? frame.Text : frame.Text[frame.Start..]);
        var reader = new Utf8JsonReader(utf8);
        long bytes;
        try
        {
            if (!reader.Read()) return false;
            var end = reader;
            if (!end.TrySkip()) return false;
            bytes = end.BytesConsumed;
        }
        catch (JsonException) { return false; }
        consumed = Encoding.UTF8.GetCharCount(utf8.AsSpan(0, (int)bytes));

        string? property = null;
        int lastByte = 0;
        int charOffset = 0;
        bool foundStructure = wrappers > 0 && reader.TokenType is (JsonTokenType.StartObject or JsonTokenType.StartArray);
        while (true)
        {
            if (reader.TokenType == JsonTokenType.PropertyName)
                property = reader.GetString();
            else
            {
                if (reader.TokenType == JsonTokenType.String && ReadString(reader, property, wrappers,
                    out string decoded, out bool message, out bool container))
                {
                    int tokenByte = (int)reader.TokenStartIndex;
                    charOffset += Encoding.UTF8.GetCharCount(utf8.AsSpan(lastByte, tokenByte - lastByte));
                    lastByte = tokenByte;
                    int rawStart = frame.Start + charOffset + 1;
                    int rawLength = Encoding.UTF8.GetCharCount(reader.ValueSpan);
                    Frame child = frame.Decode(rawStart, rawLength, decoded);
                    if (container)
                    {
                        bool childFound = Walk(child, wrappers + 1, spans, exceptions, watch, out int childLength);
                        foundStructure |= childFound;
                        // A quoted name can look like a string wrapper. Treat it as message text
                        // unless the decoded value led to a structured payload.
                        if (childFound || (childLength > 0 && decoded.AsSpan().TrimStart()[0] is ('{' or '[')))
                        {
                            if (message) AddMessageSpans(child, wrappers + 1, spans, exceptions, loginOnly: true);
                            message = false;
                        }
                    }
                    if (message)
                    {
                        foundStructure = true;
                        AddMessageSpans(child, wrappers + 1, spans, exceptions);
                    }
                }
                property = null;
            }
            if (reader.BytesConsumed >= bytes || !reader.Read()) break;
        }
        return foundStructure;
    }

    /// <summary>Inspect only nested message values and strings with a possible JSON container prefix.</summary>
    private static bool ReadString(Utf8JsonReader reader, string? property, int wrappers,
        out string decoded, out bool message, out bool container)
    {
        decoded = string.Empty;
        message = wrappers > 0 && property is ("message" or "event.original");
        container = false;
        if (!message && wrappers >= MaxWrappers) return false;
        ReadOnlySpan<byte> raw = reader.ValueSpan.TrimStart((byte)' ');
        if (raw.IsEmpty || (!message && raw[0] is not ((byte)'{' or (byte)'[' or (byte)'\\' or (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n')))
            return false;
        decoded = reader.GetString()!;
        ReadOnlySpan<char> trimmed = decoded.AsSpan().TrimStart();
        container = wrappers < MaxWrappers && !trimmed.IsEmpty && trimmed[0] is ('{' or '[' or '"');
        return message || container;
    }

    /// <summary>Record each detected value in original coordinates and remember how to re-encode it.</summary>
    private static void AddMessageSpans(Frame child, int layers, List<EntitySpan> spans, DisplayFieldExceptions exceptions,
        bool loginOnly = false)
    {
        List<EntitySpan> detected;
        if (loginOnly)
        {
            detected = [];
            TransliteratedPersonNames.AddContextualLogins(child.Text, 0, child.Text.Length, detected);
        }
        else detected = JsonMessagePersonNames.FindDecodedSpans(child.Text, exceptions);
        foreach (var span in detected)
        {
            int start = child.SourceOffset(span.Start);
            int length = child.SourceOffset(span.Start + span.Length) - start;
            spans.Add(span with { Start = start, Length = length, JsonEscapeLayers = length == span.Length ? 0 : layers });
        }
    }

    // A wrapper can start with an escaped quote, bracket or leading JSON whitespace.
    [GeneratedRegex("""\{(?=\s*["}])|\[(?=\s*[\[{"\]])|(?<!\\)"(?=\s*(?:[\[{]|\\+(?:"|[nrt]|u00(?:09|0[aAdD]|20|22|5[bB]|7[bB]))))""",
        RegexOptions.CultureInvariant, 100)]
    private static partial Regex JsonStarts();

    /// <summary>Map UTF-16 boundaries in one decoded value to the original log.</summary>
    private readonly record struct Frame(string Text, int Start, int[]? SourceOffsets)
    {
        internal int SourceOffset(int index) => SourceOffsets is null ? index : SourceOffsets[index];

        /// <summary>Compose this value's JSON escape boundaries with its parent's source offsets.</summary>
        internal Frame Decode(int start, int length, string decoded)
        {
            int[] offsets = JsonMessagePersonNames.BuildOffsetMap(Text.AsSpan(start, length), decoded.Length);
            for (int i = 0; i < offsets.Length; i++) offsets[i] = SourceOffset(start + offsets[i]);
            return new(decoded, 0, offsets);
        }
    }
}
