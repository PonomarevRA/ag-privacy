using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace AgPrivacy;

/// <summary>Find named person fields and message strings in structured or escaped JSON.</summary>
internal static partial class NestedJsonMessagePersonNames
{
    private const int MaxWrappers = 8;
    internal const int NamedPersonPriority = 210;

    /// <summary>Read structured payloads in a log and project nested sensitive spans onto the original text.</summary>
    internal static bool Add(string text, List<EntitySpan> spans, PrivacyPolicy policy)
    {
        if (!text.Contains("\\\"", StringComparison.Ordinal) && !text.Contains("\\u", StringComparison.Ordinal))
            return false;

        bool foundStructure = false;
        int consumed = 0;
        var watch = Stopwatch.StartNew();
        foreach (Match candidate in JsonStarts().Matches(text))
        {
            if (candidate.Index < consumed) continue;
            var frame = new Frame(text, candidate.Index, null);
            foundStructure |= Walk(frame, 0, spans, policy, watch, out int length);
            consumed = candidate.Index + length;
        }
        return foundStructure;
    }

    /// <summary>Same walk as <see cref="Add"/>, plus source ranges and decoded leaves for explicit analysis routing.</summary>
    internal static void Map(string text, List<EntitySpan> spans, PrivacyPolicy policy, Sink sink)
    {
        if (text.IndexOf('{') < 0 && text.IndexOf('[') < 0
            && !text.Contains("\\\"", StringComparison.Ordinal)
            && !text.Contains("\\u0022", StringComparison.Ordinal))
            return;

        int consumed = 0;
        var watch = Stopwatch.StartNew();
        foreach (Match candidate in JsonStarts().Matches(text))
        {
            if (candidate.Index < consumed) continue;
            var frame = new Frame(text, candidate.Index, null);
            bool isContainer = Walk(frame, 0, spans, policy, watch, out int length, sink);
            if (!isContainer) continue;
            sink.Ranges.Add((candidate.Index, length));
            consumed = candidate.Index + length;
        }
    }

    /// <summary>Validate one complete JSON value before reading its strings. A log suffix may follow the value.</summary>
    private static bool Walk(Frame frame, int wrappers, List<EntitySpan> spans, PrivacyPolicy policy,
        Stopwatch watch, out int consumed, Sink? sink = null, bool requireWhole = false)
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
        int length = Encoding.UTF8.GetCharCount(utf8.AsSpan(0, (int)bytes));
        if (requireWhole && !frame.Text.AsSpan(frame.Start + length).Trim().IsEmpty) return false;
        consumed = length;
        string? property = null;
        int lastByte = 0;
        int charOffset = 0;
        bool foundStructure = (sink is not null || wrappers > 0)
            && reader.TokenType is (JsonTokenType.StartObject or JsonTokenType.StartArray);
        while (true)
        {
            if (reader.TokenType == JsonTokenType.PropertyName)
                property = reader.GetString();
            else
            {
                if (reader.TokenType == JsonTokenType.String)
                {
                    bool read = ReadString(reader, property, wrappers, out string decoded, out bool message, out bool container, sink is not null);
                    bool namedPerson = IsNamedPersonField(property, policy);
                    bool wantQuery = !namedPerson && sink is not null && QueryHint(reader.ValueSpan);
                    if ((namedPerson && !reader.ValueSpan.IsEmpty) || read || wantQuery)
                    {
                        if (!read) decoded = reader.GetString() ?? "";
                        int tokenByte = (int)reader.TokenStartIndex;
                        charOffset += Encoding.UTF8.GetCharCount(utf8.AsSpan(lastByte, tokenByte - lastByte));
                        lastByte = tokenByte;
                        int rawStart = frame.Start + charOffset + 1;
                        int rawLength = Encoding.UTF8.GetCharCount(reader.ValueSpan);
                        Frame child = frame.Decode(rawStart, rawLength, decoded);
                        bool childFound = false;
                        if (namedPerson)
                        {
                            AddNamedPerson(child, spans);
                            foundStructure = true;
                        }
                        else if (read)
                        {
                            if (container)
                            {
                                childFound = Walk(child, wrappers + 1, spans, policy, watch, out int childLength, sink,
                                    requireWhole: sink is not null);
                                foundStructure |= childFound;
                                // A quoted name can look like a string wrapper. Treat it as message text
                                // unless the decoded value led to a structured payload.
                                if (childFound || (childLength > 0 && decoded.AsSpan().TrimStart()[0] is ('{' or '[')))
                                {
                                    if (message && wrappers > 0)
                                        AddMessageSpans(child, wrappers + 1, spans, policy.DisplayFieldExceptions, loginOnly: true);
                                    message = false;
                                }
                            }
                            if (message)
                            {
                                foundStructure = true;
                                if (wrappers > 0)
                                    AddMessageSpans(child, wrappers + 1, spans, policy.DisplayFieldExceptions);
                                sink?.Leaves.Add(ToMapped(child));
                            }
                        }
                        if (sink is not null && !namedPerson && !message && !childFound && (wantQuery || decoded.Contains('?')))
                            sink.Queries.Add(ToMapped(child));
                    }
                }
                property = null;
            }
            if (reader.BytesConsumed >= bytes || !reader.Read()) break;
        }
        return foundStructure;
    }

    /// <summary>Match decoded property names using the same field policy as the log's quoted-field rules.</summary>
    private static bool IsNamedPersonField(string? property, PrivacyPolicy policy)
    {
        if (property is null) return false;
        string? type = policy.FieldType(property);
        return type != "SECRET" && DisplayMaskRules.ForField(property, type ?? "TEXT") == "PERSON";
    }

    /// <summary>Mask the complete string value and retain the encoding depth of its source interval.</summary>
    private static void AddNamedPerson(Frame value, List<EntitySpan> spans)
    {
        if (value.Text.Length == 0) return;
        int start = value.SourceOffset(0);
        int length = value.SourceOffset(value.Text.Length) - start;
        spans.Add(new(start, length, "PERSON", NamedPersonPriority)
        {
            JsonEscapeLayers = length == value.Text.Length ? 0 : value.Depth
        });
    }

    /// <summary>Inspect only nested message values and strings with a possible JSON container prefix.</summary>
    private static bool ReadString(Utf8JsonReader reader, string? property, int wrappers,
        out string decoded, out bool message, out bool container, bool includeDirectMessages)
    {
        decoded = string.Empty;
        message = (wrappers > 0 || includeDirectMessages) && property is ("message" or "event.original");
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
    [GeneratedRegex("""\{(?=\s*["}])|\[(?=\s*[\[{"\]\dntf-])|(?<!\\)"(?=\s*(?:[\[{]|\\+(?:"|[nrt]|u00(?:09|0[aAdD]|20|22|5[bB]|7[bB]))))""",
        RegexOptions.CultureInvariant, 100)]
    private static partial Regex JsonStarts();

    /// <summary>True when a raw JSON string can hold a query after JSON decoding.</summary>
    private static bool QueryHint(ReadOnlySpan<byte> raw)
    {
        if (raw.IndexOf((byte)'?') >= 0 || raw.IndexOf((byte)'&') >= 0) return true;
        ReadOnlySpan<byte> escapedAmp = "\\u0026"u8;
        for (int i = 0; i + escapedAmp.Length <= raw.Length; i++)
            if (raw.Slice(i, escapedAmp.Length).SequenceEqual(escapedAmp)) return true;
        return false;
    }

    /// <summary>Project a decoded frame back to absolute source offsets.</summary>
    private static MappedText ToMapped(Frame child) => new(child.Text, child.SourceOffsets, child.Depth);

    /// <summary>Decoded text with source offsets, or an identity map for the original string.</summary>
    internal readonly record struct MappedText(string Text, int[]? Offsets, int Layers)
    {
        internal int SourceOffset(int index) => Offsets is null ? index : Offsets[index];

        /// <summary>Lift offsets from a decoded child through this region to the original log.</summary>
        internal MappedText Compose(MappedText child)
        {
            if (Offsets is null || child.Offsets is null) return child;
            var offsets = new int[child.Text.Length + 1];
            for (int i = 0; i < offsets.Length; i++)
                offsets[i] = SourceOffset(child.Offsets[i]);
            return new(child.Text, offsets, Layers + child.Layers);
        }
    }

    /// <summary>Ranges and decoded strings collected for explicit log-analysis routing.</summary>
    internal sealed class Sink
    {
        internal readonly List<(int Start, int Length)> Ranges = new();
        internal readonly List<MappedText> Leaves = new();
        internal readonly List<MappedText> Queries = new();
    }

    /// <summary>Map UTF-16 boundaries in one decoded value to the original log.</summary>
    private readonly record struct Frame(string Text, int Start, int[]? SourceOffsets)
    {
        internal int Depth { get; init; }
        internal int SourceOffset(int index) => SourceOffsets is null ? index : SourceOffsets[index];

        /// <summary>Compose this value's JSON escape boundaries with its parent's source offsets.</summary>
        internal Frame Decode(int start, int length, string decoded)
        {
            int[] offsets = JsonMessagePersonNames.BuildOffsetMap(Text.AsSpan(start, length), decoded.Length);
            for (int i = 0; i < offsets.Length; i++) offsets[i] = SourceOffset(start + offsets[i]);
            return new(decoded, 0, offsets) { Depth = Depth + 1 };
        }
    }
}
