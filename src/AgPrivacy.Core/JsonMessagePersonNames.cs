using System.Text.Encodings.Web;
using System.Text.Json;

namespace AgPrivacy;

/// <summary>Detect and replace sensitive values in JSON message strings while preserving offsets in the original log.</summary>
internal static class JsonMessagePersonNames
{
    /// <summary>Decode ordinary JSON escapes for matching, then map each sensitive span back to the raw message.</summary>
    internal static void Add(string text, int start, int length, bool directJson, List<EntitySpan> spans, DisplayFieldExceptions exceptions, IPersonDetector? model = null, IPersonDetector? proseModel = null)
    {
        ReadOnlySpan<char> raw = text.AsSpan(start, length);
        if (!directJson || !raw.Contains('\\') || !TryDecode(raw, out string decoded))
        {
            // Login qualifiers must be read in decoded coordinates, especially for escaped Cyrillic.
            TransliteratedPersonNames.AddMessageNames(text, start, length, spans,
                recognizeLoginContext: directJson && !raw.Contains('\\'));
            ComplexLogPersonNames.Add(text, start, length, spans);
            if (directJson && !raw.Contains('\\')) LabelledCompoundPersonNames.Add(text, start, length, spans);
            if (directJson && !raw.Contains('\\')) ContextualLogPersonModel.Add(text, start, length, spans, model, proseModel);
            LogSensitiveFields.AddBirthDates(text, start, length, spans);
            LogSensitiveFields.AddInlineSecrets(text, start, length, spans);
            LogPersonContext.RemoveTechnicalSpans(text, start, length, spans);
            return;
        }

        var decodedSpans = FindDecodedSpans(decoded, exceptions, model, proseModel);
        if (decodedSpans.Count == 0) return;

        int[] offsets = BuildOffsetMap(raw, decoded.Length);
        foreach (var span in decodedSpans)
        {
            int first = offsets[span.Start];
            int last = offsets[span.Start + span.Length];
            spans.Add(span with { Start = start + first, Length = last - first, JsonEscapeLayers = last - first == span.Length ? 0 : 1 });
        }
    }

    /// <summary>Apply contextual detection rules and instrument exceptions to decoded message text.</summary>
    internal static List<EntitySpan> FindDecodedSpans(string text, DisplayFieldExceptions exceptions, IPersonDetector? model = null, IPersonDetector? proseModel = null)
    {
        var spans = new List<EntitySpan>();
        TransliteratedPersonNames.AddMessageNames(text, 0, text.Length, spans);
        ComplexLogPersonNames.Add(text, 0, text.Length, spans);
        LabelledCompoundPersonNames.Add(text, 0, text.Length, spans);
        LogSensitiveFields.AddBirthDates(text, 0, text.Length, spans);
        LogSensitiveFields.AddInlineSecrets(text, 0, text.Length, spans);
        LowercasePersonNames.Add(text, spans, persons: null);
        ContextualLogPersonModel.Add(text, 0, text.Length, spans, model, proseModel);
        TransliteratedPersonNames.PreserveTechnicalLogins(text, spans);
        LogMasking.RemoveInstrumentNameSpans(text, spans, exceptions);
        LogPersonContext.RemoveTechnicalSpans(text, 0, text.Length, spans);
        return spans;
    }

    /// <summary>Substitute decoded letters and digits, then restore all enclosing JSON string layers.</summary>
    internal static string ReplaceEscaped(string raw, int layers, string type, Pseudonymizer aliases)
    {
        string decoded = raw;
        for (int i = 0; i < layers; i++)
            if (!TryDecode(decoded, out decoded)) return SoftPartFormats.FullMask;

        string replacement = aliases.ReplaceWithShape(type, decoded);
        for (int i = 0; i < layers; i++)
            replacement = JsonEncodedText.Encode(replacement, JavaScriptEncoder.UnsafeRelaxedJsonEscaping).ToString();
        return replacement;
    }

    /// <summary>Parse the contents of one JSON string, with fallback for non-JSON text embedded in logs.</summary>
    internal static bool TryDecode(ReadOnlySpan<char> raw, out string decoded)
    {
        try
        {
            using var value = JsonDocument.Parse(string.Concat("\"", raw, "\""));
            decoded = value.RootElement.GetString()!;
            return true;
        }
        catch (JsonException)
        {
            decoded = string.Empty;
            return false;
        }
    }

    /// <summary>Map decoded UTF-16 boundaries to raw boundaries, one entry per JSON code unit.</summary>
    internal static int[] BuildOffsetMap(ReadOnlySpan<char> raw, int decodedLength)
    {
        var offsets = new int[decodedLength + 1];
        int source = 0;
        for (int i = 0; i < decodedLength; i++)
        {
            offsets[i] = source;
            source += raw[source] == '\\' ? (raw[source + 1] == 'u' ? 6 : 2) : 1;
        }
        offsets[decodedLength] = source;
        return offsets;
    }
}
