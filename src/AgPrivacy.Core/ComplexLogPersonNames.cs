using System.Collections.Frozen;
using System.Text.RegularExpressions;

namespace AgPrivacy;

/// <summary>Find Russian names with mixed scripts, alternative spellings or separators.</summary>
internal static partial class ComplexLogPersonNames
{
    [Flags]
    private enum Role { None = 0, Given = 1, Surname = 2, Patronymic = 4 }
    private static readonly FrozenSet<string> SpeakerLabels = new[]
    {
        "докладчик", "выступающий", "модератор", "speaker", "presenter", "moderator"
    }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    /// <summary>Add full name spans inside the given source range, including separators between name parts.</summary>
    internal static void Add(string text, int start, int length, List<EntitySpan> spans)
    {
        int end = start;
        for (Match match = Candidates().Match(text, start, length); match.Success; match = match.NextMatch())
        {
            if (match.Index < end) continue;
            Group first = match.Groups["first"], second = match.Groups["second"], third = match.Groups["third"];
            Role a = GetRoles(first.Value), b = GetRoles(second.Value);
            if (a == Role.None || b == Role.None) continue;

            Group last;
            if (third.Success && IsTriple(a, b, GetRoles(third.Value)))
                last = third;
            else if (IsPair(a, b))
                last = second;
            else
                continue;

            if (LogPersonContext.IsTechnicalValue(text, start, first.Index)) continue;
            int nameEnd = last.Index + last.Length;
            bool explicitSeparator = match.Groups["separator"].Success ||
                (last == third && match.Groups["tailSeparator"].Success);
            // Ordinary Cyrillic names still use the existing contextual rule.
            if (!explicitSeparator && !HasLatin(text.AsSpan(first.Index, nameEnd - first.Index))) continue;
            end = nameEnd;
            int nameStart = StartsWithSpeakerLabel(first, match.Groups["separator"]) ? second.Index : first.Index;
            spans.Add(new(nameStart, end - nameStart, "PERSON", 50));
        }
    }

    /// <summary>Keep a speaker label outside the value when punctuation marks the boundary.</summary>
    private static bool StartsWithSpeakerLabel(Group word, Group separator)
    {
        ReadOnlySpan<char> gap = separator.ValueSpan;
        // An unspaced ASCII hyphen can belong to a compound surname.
        return gap.ContainsAny('-', '–', '—')
            && (gap.Length != 1 || gap[0] != '-')
            && SpeakerLabels.Contains(word.Value);
    }

    /// <summary>Accept given name and surname in either order.</summary>
    private static bool IsPair(Role first, Role second) =>
        (first.HasFlag(Role.Given) && second.HasFlag(Role.Surname)) ||
        (first.HasFlag(Role.Surname) && second.HasFlag(Role.Given));

    /// <summary>Require a separate patronymic when consuming a third word.</summary>
    private static bool IsTriple(Role first, Role second, Role third) =>
        (third.HasFlag(Role.Patronymic) && IsPair(first, second)) ||
        (second.HasFlag(Role.Patronymic) && IsPair(first, third));

    /// <summary>Score each word independently, repairing only visually identical letters inside mixed tokens.</summary>
    private static Role GetRoles(string value)
    {
        string word = value.ToLowerInvariant().Replace('ё', 'е')
            .Replace("'", "", StringComparison.Ordinal).Replace("’", "", StringComparison.Ordinal);
        bool latin = HasLatin(word);
        bool russian = HasRussian(word);
        if (!latin) return RussianRoles(word);
        if (!russian) return LatinRoles(word);

        string cyrillic = ReplaceLookalikes(word, "aceopxykbmht", "асеорхуквмнт");
        string roman = ReplaceLookalikes(word, "асеорхуквмнт", "aceopxykbmht");
        return (HasLatin(cyrillic) ? Role.None : RussianRoles(cyrillic)) |
            (HasRussian(roman) ? Role.None : LatinRoles(roman));
    }

    /// <summary>Check given names, surname model and patronymic shape.</summary>
    private static Role RussianRoles(string word)
    {
        Role role = Role.None;
        if (LowercasePersonNames.RussianWords.Names.Contains(word)) role |= Role.Given;
        if (SurnameShapeModel.Predict(word, 2.5f)) role |= Role.Surname;
        if (RussianPatronymic().IsMatch(word)) role |= Role.Patronymic;
        return role;
    }

    /// <summary>Fold Latin variants and score the original spelling or the folded version.</summary>
    private static Role LatinRoles(string word)
    {
        string key = Fold(word);
        Role role = Role.None;
        if (Folded.Names.Contains(key)) role |= Role.Given;
        if ((SurnameShapeModel.Predict(word, 2.5f) || (key != word && SurnameShapeModel.Predict(key, 2.5f)))) role |= Role.Surname;
        if (LatinPatronymic().IsMatch(key)) role |= Role.Patronymic;
        return role;
    }

    /// <summary>Fold observed transliteration variations without using general edit distance.</summary>
    private static string Fold(string value)
    {
        value = value.Replace('w', 'v').Replace('ï', 'i');
        if (value.EndsWith("off", StringComparison.Ordinal) || value.EndsWith("eff", StringComparison.Ordinal))
            value = string.Concat(value.AsSpan(0, value.Length - 2), "v");
        return value.Replace("oo", "o", StringComparison.Ordinal)
            .Replace("yo", "e", StringComparison.Ordinal).Replace("ye", "e", StringComparison.Ordinal)
            .Replace('y', 'i').Replace("iia", "ia", StringComparison.Ordinal);
    }

    /// <summary>Convert a small explicit set of homoglyphs for lookup only. Source offsets do not change.</summary>
    private static string ReplaceLookalikes(string word, string from, string to)
    {
        char[] result = word.ToCharArray();
        for (int i = 0; i < result.Length; i++)
        {
            int index = from.IndexOf(result[i]);
            if (index >= 0) result[i] = to[index];
        }
        return new string(result);
    }

    private static bool HasLatin(ReadOnlySpan<char> value) =>
        value.ContainsAnyInRange('A', 'Z') || value.ContainsAnyInRange('a', 'z') || value.ContainsAny('ï', 'Ï');

    private static bool HasRussian(ReadOnlySpan<char> value) => value.ContainsAnyInRange('а', 'я');

    private static class Folded
    {
        internal static readonly FrozenSet<string> Names = TransliteratedPersonNames.LatinNames
            .Append("oleh").Select(Fold).ToFrozenSet(StringComparer.Ordinal);
    }

    // A spaced slash can separate names, but unspaced slashes and dotted identifiers delimit paths.
    private const string Word = @"[A-Za-zА-Яа-яЁёÏï][A-Za-zА-Яа-яЁёÏï'’]{1,39}";
    private const string Separator = @"(?:[ \t]+/[ \t]+|[ \t]*[,–—-][ \t]*)";
    private const string Boundary = @"(?![\p{L}\p{M}\p{N}_@/'’-]|\.[\p{L}\p{M}\p{N}_]|\\(?!\\*""))";

    [GeneratedRegex(@"(?<![\p{L}\p{M}\p{N}_@/\\'’–—-])(?<![\p{L}\p{M}\p{N}_]\.)" +
        @"(?=(?<first>" + Word + @")(?:(?<separator>" + Separator + @")|[ \t]+)(?<second>" + Word + ")" + Boundary +
        @"(?:(?:(?<tailSeparator>" + Separator + @")|[ \t]+)(?<third>" + Word + ")" + Boundary + @")?)",
        RegexOptions.CultureInvariant, 100)]
    private static partial Regex Candidates();

    [GeneratedRegex(@"\A[а-я]{2,}(?:ович|евич|овна|евна|ична|ич)\z", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking, 100)]
    private static partial Regex RussianPatronymic();

    [GeneratedRegex(@"\A[a-z]{2,}(?:ovich|evich|ich|ovna|evna|ichna|ovitch|evitch)\z", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking, 100)]
    private static partial Regex LatinPatronymic();
}
