using System.Text.RegularExpressions;

namespace AgPrivacy;

internal enum LogField { None, Event, Trace, Message, TraceId }

/// <summary>Identify log fields and supply the additional spans used for selective log masking.</summary>
internal static partial class LogMasking
{
    private const string IsinShape = "[A-Za-z]{2}[A-Za-z0-9]{9}[0-9]";
    private const string TickerShape = "(?:[A-Za-z][A-Za-z0-9.-]{0,14}|[0-9]{1,6}(?:[.-][A-Za-z]{1,4})?)";

    /// <summary>Resolve nested and flattened ECS field names without guessing from arbitrary IDs.</summary>
    internal static LogField FieldFor(LogField parent, string name) => name switch
    {
        "message" or "event.original" => LogField.Message,
        "original" when parent == LogField.Event => LogField.Message,
        "trace.id" => LogField.TraceId,
        "id" when parent == LogField.Trace => LogField.TraceId,
        "event" => LogField.Event,
        "trace" => LogField.Trace,
        _ => LogField.None
    };

    /// <summary>Require the expected format for the two built-in instrument fields.</summary>
    internal static bool CanSkipPersonDetection(string? field, string value)
    {
        if (string.Equals(field, "isin", StringComparison.OrdinalIgnoreCase))
            return Isin().IsMatch(value);
        if (string.Equals(field, "ticker", StringComparison.OrdinalIgnoreCase))
            return Ticker().IsMatch(value);
        return true;
    }

    /// <summary>Use the same correlation pseudonym in both display modes within a key and scope.</summary>
    internal static string TraceId(Pseudonymizer aliases, string value) =>
        aliases.ReplaceForDisplay("IDENTIFIER", value, "TRACE_ID");

    /// <summary>Trim labels from formal matches and add log-specific detectors before merging spans.</summary>
    internal static void AddSpans(string text, List<EntitySpan> spans, IPersonDetector? persons, DisplayFieldExceptions exceptions)
    {
        for (int i = 0; i < spans.Count; i++)
        {
            var span = spans[i];
            if (span.Type is not ("INN" or "KPP" or "TRDACC") || span.Priority != 100) continue;

            ReadOnlySpan<char> matched = text.AsSpan(span.Start, span.Length);
            int offset = span.Type == "TRDACC"
                ? matched.IndexOfAny(':', '=') + 1
                : matched.IndexOfAnyInRange('0', '9');
            if (offset <= 0) continue;
            while (offset < matched.Length && char.IsWhiteSpace(matched[offset])) offset++;
            if (offset < matched.Length) spans[i] = span with { Start = span.Start + offset, Length = span.Length - offset };
        }

        foreach (Match match in JsonFieldNames.PhoneMatches(text))
            spans.Add(new(match.Index, match.Length, "PHONE", 150));
        foreach (Match match in SoftPartFormats.AgreementMatches(text))
            spans.Add(new(match.Index, match.Length, "IDENTIFIER", 150));
        foreach (Match match in CredentialsRedactor.AuthorizationMatches(text))
        {
            Group token = match.Groups["token"];
            spans.Add(new(token.Index, token.Length, "SECRET", 250));
        }
        foreach (Match match in CardCandidates().Matches(text))
        {
            if (PassesLuhn(text.AsSpan(match.Index, match.Length)))
                spans.Add(new(match.Index, match.Length, "ACCOUNT", 150));
        }
        if (persons is not null) LowercasePersonNames.Add(text, spans, persons);

        RemoveInstrumentNameSpans(text, spans, exceptions);
    }

    /// <summary>Apply ISIN and ticker exceptions to heuristic name spans in the same text coordinates.</summary>
    internal static void RemoveInstrumentNameSpans(string text, List<EntitySpan> spans, DisplayFieldExceptions exceptions)
    {
        foreach (Match match in InstrumentValues().Matches(text))
        {
            Group label = match.Groups["label"];
            if (!exceptions.Contains(label.Value)) continue;
            Group instrument = match.Groups["instrument"];
            int end = instrument.Index + instrument.Length;
            spans.RemoveAll(span => span.Type == "PERSON" && span.Priority < 100 && span.Start >= instrument.Index && span.Start + span.Length <= end);
        }
    }

    /// <summary>Validate the candidate checksum without retaining the digits.</summary>
    private static bool PassesLuhn(ReadOnlySpan<char> text)
    {
        int sum = 0;
        bool doubleDigit = false;
        for (int i = text.Length - 1; i >= 0; i--)
        {
            if (!char.IsAsciiDigit(text[i])) continue;
            int digit = text[i] - '0';
            if (doubleDigit)
            {
                digit *= 2;
                if (digit > 9) digit -= 9;
            }
            sum += digit;
            doubleDigit = !doubleDigit;
        }
        return sum % 10 == 0;
    }

    [GeneratedRegex(@"\A" + IsinShape + @"\z", RegexOptions.CultureInvariant, 100)]
    private static partial Regex Isin();

    [GeneratedRegex(@"\A" + TickerShape + @"\z", RegexOptions.CultureInvariant, 100)]
    private static partial Regex Ticker();

    [GeneratedRegex(@"(?i:\b(?<label>isin)\s*[:=]\s*""?)(?<instrument>" + IsinShape + @")(?![\p{L}\p{N}])|" +
        @"(?i:\b(?<label>ticker)\s*[:=]\s*""?)(?<instrument>" + TickerShape + @")(?![\p{L}\p{N}.-])",
        RegexOptions.CultureInvariant, 100)]
    private static partial Regex InstrumentValues();

    [GeneratedRegex(@"(?<![\p{L}\p{N}])(?<![0-9][ -])[0-9](?:[ -]?[0-9]){12,18}(?![\p{L}\p{N}]|[ -][0-9])",
        RegexOptions.CultureInvariant, 100)]
    private static partial Regex CardCandidates();
}
