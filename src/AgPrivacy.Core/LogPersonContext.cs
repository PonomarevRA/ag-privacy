using System.Text.RegularExpressions;

namespace AgPrivacy;

/// <summary>Identify explicitly technical assignments around heuristic person candidates.</summary>
internal static partial class LogPersonContext
{
    /// <summary>Check only the label immediately before a candidate in the same message.</summary>
    internal static bool IsTechnicalValue(string text, int messageStart, int valueStart)
    {
        int length = Math.Min(80, valueStart - messageStart);
        return TechnicalValuePrefix().IsMatch(text.AsSpan(valueStart - length, length));
    }

    /// <summary>Drop partial person predictions within an explicitly technical assignment's value.</summary>
    internal static void RemoveTechnicalSpans(string text, int messageStart, int messageLength, List<EntitySpan> spans)
    {
        if (!spans.Exists(span => span.Type == "PERSON")) return;
        int messageEnd = messageStart + messageLength;
        for (Match match = TechnicalAssignment().Match(text, messageStart, messageLength); match.Success; match = match.NextMatch())
        {
            int valueStart = match.Index + match.Length;
            var value = text.AsSpan(valueStart, Math.Min(168, messageEnd - valueStart));
            int valueEnd = valueStart + TechnicalValueLength(value);
            spans.RemoveAll(span => span.Type == "PERSON" && span.Priority < 100 &&
                span.Start >= valueStart && span.Start + span.Length <= valueEnd);
        }
    }

    /// <summary>Stop at the next clause, including dotted sentences after a technical token.</summary>
    private static int TechnicalValueLength(ReadOnlySpan<char> value)
    {
        for (int i = 0; i < value.Length; i++)
        {
            char ch = value[i];
            if (ch is ';' or '|' or ',' or '\r' or '\n' or '"' or '»') return i;
            if (ch == '.' && i > 1 && i + 1 < value.Length && char.IsWhiteSpace(value[i + 1]) &&
                char.IsLetterOrDigit(value[i - 1]) && char.IsLetterOrDigit(value[i - 2])) return i;
        }
        return value.Length;
    }

    private const string TechnicalLabel =
        """(?:\b(?:service|system|technical|automation|bot|сервисный|сервисная|системный|системная|технический|техническая)[ \t]+(?:(?:account|user|actor)[ \t]+)?(?:client|contact|login|username|клиент|контакт|логин)|\b(?:pipeline|job|service|component|module|report)[ \t]+(?:alias|label|name)|\b(?:request|response|event|rpc)\.(?:client|contact|employee|recipient))[ \t]*[:=][ \t]*["'«]?|\bsynthetic[ \t]+fixture[ \t]+label(?:[ \t]*[:=])?[ \t]+""";

    [GeneratedRegex("(?:" + TechnicalLabel + @")\z", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase, 100)]
    private static partial Regex TechnicalValuePrefix();

    [GeneratedRegex(TechnicalLabel, RegexOptions.CultureInvariant | RegexOptions.IgnoreCase, 100)]
    private static partial Regex TechnicalAssignment();
}
