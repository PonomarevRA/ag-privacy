using System.Text.RegularExpressions;

namespace AgPrivacy;

/// <summary>Mask explicitly labelled person values whose spelling needs more than a word-pair detector.</summary>
internal static partial class LabelledCompoundPersonNames
{
    private const string Letter = "[A-Za-zА-Яа-яЁё]";
    private const string Word = Letter + "{2,40}";
    private const string Initial = "[A-ZА-ЯЁ]";
    private const string Gap = "[ \\t]+";
    internal const string Compound = Word + "[-‐‑]" + Word;
    private const string Surname = "(?:" + Compound + "|" + Word + ")";
    internal const string TwoInitials = Initial + @"\.[ \t]*" + Initial + @"\.";
    private const string Patronymic = @"(?:[а-яё]{2,32}(?:ович|евич|овна|евна|ична|ич)|[a-z]{2,32}(?:ovich|evich|ovna|evna|ich))";

    /// <summary>Add the complete value interval while leaving its label, quotes and log separators intact.</summary>
    internal static void Add(string text, int start, int length, List<EntitySpan> spans)
    {
        if (!text.AsSpan(start, length).ContainsAny('-', '.', '‐') &&
            !text.AsSpan(start, length).Contains('‑')) return;

        for (Match match = Candidates().Match(text, start, length); match.Success; match = match.NextMatch())
        {
            Group name = match.Groups["name"];
            if (LogPersonContext.IsTechnicalValue(text, start, name.Index)) continue;
            spans.Add(new(name.Index, name.Length, "PERSON", 46));
        }
    }

    // Anchor the complete value at a field boundary. Without this check a surname prefix could match a path or a job identifier.
    [GeneratedRegex(
        @"(?<![\p{L}\p{N}_.-])(?i:фио|ф[.]и[.]о[.]|получатель|заявитель|клиент|контакт|сотрудник|ответственный|full[ _-]?name|recipient|applicant|client|contact|employee)[ \t]*[:=][ \t]*(?:""|'|«)?" +
        @"(?<name>(?:" + Surname + Gap + TwoInitials + "|" + TwoInitials + Gap + Surname + "|" +
        @"(?:" + Compound + Gap + Word + "|" + Word + Gap + Compound + ")(?:" + Gap + "(?i:" + Patronymic + "))?))" +
        @"(?=[ \t]*(?:[;|,!?»'""\r\n]|\.(?:[ \t]|$)|$))",
        RegexOptions.CultureInvariant, 100)]
    private static partial Regex Candidates();

}
