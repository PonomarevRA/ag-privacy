using System.Text.RegularExpressions;

namespace AgPrivacy;

/// <summary>Recognize sensitive log fields that need an explicit schema or a nearby label.</summary>
internal static partial class LogSensitiveFields
{
    /// <summary>Mask numeric secrets without changing their JSON type.</summary>
    internal static void AddNumericSecrets(string text, List<EntitySpan> spans)
    {
        foreach (Match match in NumericSecrets().Matches(text))
        {
            Group value = match.Groups["value"];
            spans.Add(new(value.Index, value.Length, "SECRET", 200) { JsonNumber = true });
        }
    }

    /// <summary>Mask explicitly assigned secrets in free-form message text, preserving surrounding punctuation.</summary>
    internal static void AddInlineSecrets(string text, int start, int length, List<EntitySpan> spans)
    {
        for (Match match = InlineSecrets().Match(text, start, length); match.Success; match = match.NextMatch())
        {
            Group value = match.Groups["value"];
            spans.Add(new(value.Index, value.Length, "SECRET", 200));
        }
    }

    /// <summary>Mask only the date adjacent to a birth label, within the supplied message bounds.</summary>
    internal static void AddBirthDates(string text, int start, int length, List<EntitySpan> spans)
    {
        for (Match match = BirthDates().Match(text, start, length); match.Success; match = match.NextMatch())
        {
            Group value = match.Groups["value"];
            spans.Add(new(value.Index, value.Length, "DATE", 145));
        }
    }

    /// <summary>Preserve a complete trace identifier without exempting unrelated IDs or arbitrary trace text.</summary>
    internal static void PreserveTraceIds(string text, List<EntitySpan> spans)
    {
        if (spans.Count == 0) return;

        foreach (Match match in TraceIds().Matches(text))
        {
            Group id = match.Groups["id"];
            int end = id.Index + id.Length;
            spans.RemoveAll(span => span.Type != "SECRET" && span.Start >= id.Index && span.Start + span.Length <= end);
        }
    }

    [GeneratedRegex("""(?<!\\)(?<quote>\\*")(?:code[_-]?word|otp|cvv)\k<quote>\s*:\s*(?<value>-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)(?=[ \t\r\n,}\]])""",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, 100)]
    private static partial Regex NumericSecrets();

    [GeneratedRegex("""(?<![\p{L}\p{N}_.-])(?:code[_-]?word|otp|cvv|(?:x[_-])?api[_-]?key|(?:access|refresh|id|session|csrf|xsrf)[_-]?token|client[_-]?secret)[ \t]*[:=][ \t]*(?:"(?<value>[^"\r\n]+)"|'(?<value>[^'\r\n]+)'|«(?<value>[^»\r\n]+)»|(?<value>[^\s"',;&<>{}\[\]\\»]+?)(?=$|[\s"',;&<>{}\[\]\\»]|[.!?](?=$|[\s"'])))""",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, 100)]
    private static partial Regex InlineSecrets();

    [GeneratedRegex("""\b(?:дата[ \t]+рождения(?:[ \t]+клиента)?|date[ \t]+of[ \t]+birth|dateOfBirth|birthDate|dob)(?:[ \t]*[:=—–][ \t]*|[ \t]+)["'«]?(?<value>[0-9]{4}-[0-9]{2}-[0-9]{2}|[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{4}|[0-9]{1,2}/[0-9]{1,2}/[0-9]{4})(?![\p{L}\p{N}/-]|\.[0-9])""",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, 100)]
    private static partial Regex BirthDates();

    // Trace objects can carry scalar metadata before id. Never skip over another object or array.
    private const string Quote = """\k<quote>""";
    private const string TraceMember = Quote + """[^"\\\r\n]+""" + Quote + """\s*:\s*(?:""" +
        Quote + """[^"\\\r\n]*""" + Quote + """|[-.0-9eE+]+|true|false|null)\s*,\s*""";
    private const string TraceValue = """(?<id>[0-9a-f]{32}|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})""";

    [GeneratedRegex("""(?<!\\)(?<quote>\\*")(?:trace\.id|trace""" + Quote + """\s*:\s*\{\s*(?:""" +
        TraceMember + """)*?""" + Quote + """id)""" + Quote + """\s*:\s*""" + Quote + TraceValue + Quote,
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, 100)]
    private static partial Regex TraceIds();
}
