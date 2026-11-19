using System.Collections.Frozen;
using System.Text.RegularExpressions;

namespace AgPrivacy;

/// <summary>Detect Russian names in a bounded, person-oriented log context.</summary>
internal static partial class LowercasePersonNames
{
    private const string Word = @"[\p{Ll}A-Z][\p{Ll}A-Z'’-]{1,39}";
    private const string EndWords = "for|about|was|has|для|по|получил[аи]?|подтвердил[аи]?|отправил[аи]?";
    private const string LegacyCues = "to|from|contact|client|customer|owner|assignee|fullname|фио|клиент|контакт";

    /// <summary>Add only the name's UTF-16 range, leaving the label and surrounding log text visible.</summary>
    internal static void Add(string text, List<EntitySpan> spans, IPersonDetector? persons)
    {
        foreach (Match match in Candidates().Matches(text))
        {
            Group first = match.Groups["first"], second = match.Groups["second"], third = match.Groups["third"];
            if (LogPersonContext.IsTechnicalValue(text, 0, first.Index)) continue;
            Group last = third.Success ? third : second;
            int length = last.Index + last.Length - first.Index;
            string? thirdWord = third.Success ? third.Value : null;
            bool matchesName = IsRussianName(first.Value, second.Value, thirdWord) ||
                TransliteratedPersonNames.IsMatch(first.Value, second.Value, thirdWord);

            // Keep the existing pair prediction available for unfamiliar name forms.
            bool fallback = !third.Success && LegacyCue().IsMatch(match.Groups["cue"].Value) &&
                !first.Value.Any(char.IsUpper) && !second.Value.Any(char.IsUpper);
            if (!matchesName && (persons is null || !fallback || !ModelConfirms(text, first, second, length, persons))) continue;
            spans.Add(new(first.Index, length, "PERSON", 50));
        }
    }

    /// <summary>Accept both Russian name orders and require a distinct patronymic in a three-word match.</summary>
    private static bool IsRussianName(string first, string second, string? third)
    {
        first = first.Replace('ё', 'е');
        second = second.Replace('ё', 'е');
        if (third is null)
            return IsNameAndSurname(first, second, hasPatronymic: false) ||
                IsNameAndSurname(second, first, hasPatronymic: false);

        third = third.Replace('ё', 'е');
        bool patronymicLast = Patronymic().IsMatch(third) &&
            (IsNameAndSurname(first, second, hasPatronymic: true) ||
             IsNameAndSurname(second, first, hasPatronymic: true));
        return patronymicLast ||
            (Patronymic().IsMatch(second) && IsNameAndSurname(first, third, hasPatronymic: true));
    }

    /// <summary>Use a lower surname margin when a separate patronymic supplies more evidence.</summary>
    private static bool IsNameAndSurname(string givenName, string surname, bool hasPatronymic) =>
        RussianWords.Names.Contains(givenName) &&
        SurnameShapeModel.Predict(surname, hasPatronymic ? 0.5f : 1.5f);

    /// <summary>Reuse the recased pair prediction without changing the source offsets.</summary>
    private static bool ModelConfirms(string text, Group first, Group second, int length, IPersonDetector persons)
    {
        char[] candidate = text.AsSpan(first.Index, length).ToArray();
        candidate[0] = char.ToUpperInvariant(candidate[0]);
        int next = second.Index - first.Index;
        candidate[next] = char.ToUpperInvariant(candidate[next]);
        return persons.Find(new string(candidate)).Any(span => span.Start == 0 && span.Length == length);
    }

    [GeneratedRegex(@"(?i:\b(?<cue>" + LegacyCues + @"|получатель|заявитель|исполнитель|ответственный|пользователь|участник|владелец|recipient|fio|full[ \t]+name))" +
        @"(?:[ \t]*[:=][ \t]*(?:\\*""|«)?|[ \t]+)(?<first>" + Word + @")[ \t]+(?<second>" + Word + @")" +
        @"(?:[ \t]+(?!(?:" + EndWords + @")\b)(?<third>" + Word + @"))?" +
        @"(?=$|[.,;:!?|»]|\\*""|[ \t]+(?i:" + EndWords + @")\b)",
        RegexOptions.CultureInvariant, 100)]
    private static partial Regex Candidates();

    [GeneratedRegex(@"\A(?:" + LegacyCues + @")\z", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking, 100)]
    private static partial Regex LegacyCue();

    [GeneratedRegex(@"\A[а-я]{2,}(?:ович|евич|овна|евна|ична|инична|ич)\z", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking, 100)]
    private static partial Regex Patronymic();

    internal static class RussianWords
    {
        internal static readonly FrozenSet<string> Names = Load("ru-names.txt");

        /// <summary>Read the embedded lexicon once with ordinal matching.</summary>
        private static FrozenSet<string> Load(string name)
        {
            using var source = typeof(LowercasePersonNames).Assembly.GetManifestResourceStream("AgPrivacy." + name)
                ?? throw new InvalidOperationException("missing-person-lexicon");
            using var reader = new StreamReader(source);
            var words = new List<string>();
            while (reader.ReadLine() is { } word) words.Add(word);
            return words.ToFrozenSet(StringComparer.Ordinal);
        }
    }
}
