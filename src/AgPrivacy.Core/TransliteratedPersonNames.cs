using System.Collections.Frozen;
using System.Text;
using System.Text.RegularExpressions;

namespace AgPrivacy;

/// <summary>Recognize transliterated names and surname-initial forms using given names, spelling features and log context.</summary>
internal static partial class TransliteratedPersonNames
{
    private const string Cyrillic = "абвгдежзийклмнопрстуфхцчшщъыьэюя";
    private static readonly string[][] Schemes =
    [
        "a b v g d e zh z i y k l m n o p r s t u f kh ts ch sh shch _ y _ e yu ya".Split(' '),
        "a b v g d e zh z i i k l m n o p r s t u f kh ts ch sh shch _ y _ e iu ia".Split(' '),
        "a b v g d e zh z i j k l m n o p r s t u f h c ch sh sch _ y _ e ju ja".Split(' '),
        "a b v g d e zh z i y k l m n o p r s t u f kh ts ch sh shch _ y _ e yu ia".Split(' '),
        "a b v g d e zh z i i k l m n o p r s t u f kh tc ch sh shch _ y _ e iu ia".Split(' '),
    ];

    /// <summary>Require a given name and surname, plus patronymic evidence for a three-word value.</summary>
    internal static bool IsMatch(string first, string second, string? third)
    {
        if (!LatinWord().IsMatch(first) || !LatinWord().IsMatch(second) ||
            (third is not null && !LatinWord().IsMatch(third))) return false;

        first = Normalize(first);
        second = Normalize(second);
        if (third is null)
            return NameAndSurname(first, second, false) || NameAndSurname(second, first, false);

        third = Normalize(third);
        return (Patronymic().IsMatch(third) &&
                (NameAndSurname(first, second, true) || NameAndSurname(second, first, true))) ||
            (Patronymic().IsMatch(second) && NameAndSurname(first, third, true));
    }

    /// <summary>Scan only the supplied log message and keep all spans in source coordinates.</summary>
    internal static void AddMessageNames(string text, int start, int length, List<EntitySpan> spans,
        bool recognizeLoginContext = true)
    {
        AddUnlabelled(text, start, length, spans);
        AddShortNames(text, start, length, spans);
        if (recognizeLoginContext) AddContextualLogins(text, start, length, spans);
    }

    /// <summary>Find unlabelled Latin names in a message range, preferring complete three-word names.</summary>
    private static void AddUnlabelled(string text, int start, int length, List<EntitySpan> spans)
    {
        int maskedEnd = start;
        for (Match match = UnlabelledCandidates().Match(text, start, length); match.Success; match = match.NextMatch())
        {
            if (match.Index < maskedEnd) continue;
            Group first = match.Groups["first"], second = match.Groups["second"], third = match.Groups["third"];
            string firstWord = Normalize(first.Value);
            string secondWord = Normalize(second.Value);
            Group last;
            if (third.Success && IsUnlabelledTriple(firstWord, secondWord, Normalize(third.Value)))
                last = third;
            else if (UnlabelledPair(firstWord, secondWord) || UnlabelledPair(secondWord, firstWord))
                last = second;
            else if (IsAlternatePair(firstWord, secondWord) &&
                PersonContextShadow.HasPersonEvidence(text, new(start, start + length), first.Index, second.Index + second.Length))
                last = second;
            else
                continue;

            if (LogPersonContext.IsTechnicalValue(text, start, first.Index)) continue;
            maskedEnd = last.Index + last.Length;
            spans.Add(new(first.Index, maskedEnd - first.Index, "PERSON", 50));
        }
    }

    /// <summary>Require additional local evidence for less common transliteration endings.</summary>
    private static bool UnlabelledPair(string first, string last) =>
        !HasAlternateSurnameEnding(last) && NameAndSurname(first, last, false);

    /// <summary>Accept a separate patronymic only when the other words identify a given name and surname.</summary>
    private static bool IsUnlabelledTriple(string first, string second, string third) =>
        (Patronymic().IsMatch(third) && (NameAndSurname(first, second, false) || NameAndSurname(second, first, false))) ||
        (Patronymic().IsMatch(second) && NameAndSurname(first, third, false));

    // Match at each word boundary so surrounding prose does not consume the start of a name.
    // Dots, path separators and identifier characters cannot form a boundary inside a token.
    private const string CandidateWord = @"[A-Za-z][A-Za-z'’-]{1,39}";
    private const string TokenEnd = @"(?![\p{L}\p{M}\p{N}_@/'’-]|\.[\p{L}\p{M}\p{N}_]|\\(?!\\*""))";

    [GeneratedRegex(TokenStart +
        @"(?=(?<first>" + CandidateWord + @")[ \t]+(?<second>" + CandidateWord + ")" + TokenEnd +
        @"(?:[ \t]+(?<third>" + CandidateWord + ")" + TokenEnd + @")?)",
        RegexOptions.CultureInvariant, 100)]
    private static partial Regex UnlabelledCandidates();

    [GeneratedRegex(@"\A(?:[a-z]{3,}(?:ov|ev|ova|eva|ina|yna|skiy|skii|skij|sky|skaya|skaia|skaja|enko|chuk|iuk|yuk|dze|shvili)|[a-z]{4,}(?:in|yn))\z",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking, 100)]
    private static partial Regex DistinctiveSurname();

    /// <summary>Detect likely surnames followed by initials, including Latin account-style spellings.</summary>
    private static void AddShortNames(string text, int start, int length, List<EntitySpan> spans)
    {
        for (Match match = ShortCandidates().Match(text, start, length); match.Success; match = match.NextMatch())
        {
            Group separated = match.Groups["surname"];
            bool isName = separated.Success ? IsKnownSurname(separated.Value) : IsCompactName(match.Groups["compact"].Value);
            if (!isName && !separated.Success && IsContextualShortLogin(match.Groups["compact"].ValueSpan) &&
                PersonContextShadow.HasPersonEvidence(text, new(start, start + length), match.Index, match.Index + match.Length))
                isName = true;
            if (isName && !LogPersonContext.IsTechnicalValue(text, start, match.Index)) spans.Add(new(match.Index, match.Length, "PERSON", 50));
        }
    }

    /// <summary>Combine standard and alternate given-name spellings when the caller has verified local person context.</summary>
    private static bool IsAlternatePair(string first, string second) =>
        IsContextualNameAndSurname(first, second) || IsContextualNameAndSurname(second, first);

    /// <summary>Require a given name and a surname prediction in local person context.</summary>
    private static bool IsContextualNameAndSurname(string name, string surname) =>
        (Words.Names.Contains(name) || Words.AlternateNames.Contains(name)) &&
        SurnameShapeModel.Predict(surname, 1.5f);

    /// <summary>Recognize alternate and short known surnames with one or two nontechnical initials.</summary>
    private static bool IsContextualShortLogin(ReadOnlySpan<char> value)
    {
        int separator = value.IndexOf('_');
        if (separator < 4) return false;
        string initials = value[(separator + 1)..].ToString().ToLowerInvariant();
        if (MachineSuffixes.Contains(initials)) return false;
        string surname = value[..separator].ToString().ToLowerInvariant();
        return SurnameShapeModel.Predict(surname, 1.5f);
    }

    /// <summary>Score Cyrillic and Latin surname spellings followed by initials.</summary>
    private static bool IsKnownSurname(string value)
    {
        if (LatinWord().IsMatch(value))
        {
            return IsKnownLatinSurname(Normalize(value));
        }
        return SurnameShapeModel.Predict(value, 2.5f);
    }

    /// <summary>Require a distinctive spelling when initials provide less evidence than a full given name.</summary>
    private static bool IsKnownLatinSurname(string normalized) =>
        DistinctiveSurname().IsMatch(normalized) && !HasAlternateSurnameEnding(normalized) &&
        SurnameShapeModel.Predict(normalized, 2f);

    private static bool HasAlternateSurnameEnding(string value) =>
        value.EndsWith("iev", StringComparison.Ordinal) || value.EndsWith("ieva", StringComparison.Ordinal);

    /// <summary>Verify the surname portion of a compact name and reject common machine suffixes.</summary>
    private static bool IsCompactName(string value)
    {
        string word = value.ToLowerInvariant();
        int separator = word.IndexOf('_');
        if (separator >= 0)
            return IsKnownLatinSurname(word[..separator]) && !MachineSuffixes.Contains(word[(separator + 1)..]);

        if (word.EndsWith("ovo", StringComparison.Ordinal) ||
            word.EndsWith("evo", StringComparison.Ordinal) || word.EndsWith("ovka", StringComparison.Ordinal) ||
            word.EndsWith("evka", StringComparison.Ordinal)) return false;
        for (int initials = 1; initials <= 2; initials++)
        {
            string suffix = word[^initials..];
            // A trailing vowel without a separator is easily confused with a surname inflection.
            if (initials == 1 && "aeiouy".Contains(suffix[0])) continue;
            if (!MachineSuffixes.Contains(suffix) && IsKnownLatinSurname(word[..^initials])) return true;
        }
        return false;
    }

    /// <summary>Resolve an ambiguous surname-initial token only when the message identifies a login.</summary>
    internal static void AddContextualLogins(string text, int start, int length, List<EntitySpan> spans)
    {
        if (!text.AsSpan(start, length).Contains('_')) return;
        for (Match match = LoginCandidates().Match(text, start, length); match.Success; match = match.NextMatch())
        {
            Group value = match.Groups["login"];
            if (IsAmbiguousLogin(value.ValueSpan) && !IsTechnicalLogin(text, start, match.Index))
                spans.Add(new(value.Index, value.Length, "PERSON", 50));
        }
    }

    /// <summary>Remove only heuristic person masks fully inside an explicitly technical login value.</summary>
    internal static void PreserveTechnicalLogins(string text, List<EntitySpan> spans)
    {
        if (!text.Contains('_')) return;
        foreach (Match match in LoginCandidates().Matches(text))
        {
            if (!IsTechnicalLogin(text, 0, match.Index)) continue;
            Group login = match.Groups["login"];
            spans.RemoveAll(span => span.Type == "PERSON" && span.Priority < 100 &&
                span.Start >= login.Index && span.Start + span.Length <= login.Index + login.Length);
        }
    }

    /// <summary>Mask a complete value of an explicit login property in a structured log fragment.</summary>
    internal static void AddJsonLogin(string text, int cue, int start, int length, List<EntitySpan> spans)
    {
        // An escaped qualifier needs decoded coordinates. The message scanner handles that case.
        if (LoginPrefix(text, 0, cue).Contains('\\') ||
            !IsAmbiguousLogin(text.AsSpan(start, length)) || IsTechnicalLogin(text, 0, cue))
            return;
        spans.Add(new(start, length, "PERSON", 50));
    }

    /// <summary>Check a labelled login value against an adjacent, explicit service-account qualifier.</summary>
    internal static bool IsTechnicalLoginValue(string text, int cue, int start, int length)
    {
        Match match = LoginCandidates().Match(text, cue);
        Group login = match.Groups["login"];
        return match.Success && match.Index == cue && login.Index == start && login.Length == length &&
            IsTechnicalLogin(text, 0, cue);
    }

    /// <summary>Identify a technical login assignment that an account label captured as its value.</summary>
    internal static bool IsTechnicalLoginAssignment(string text, int start, int length)
    {
        Match match = LoginCandidates().Match(text, start, length);
        return match.Success && match.Index == start && match.Index + match.Length == start + length &&
            IsAmbiguousLogin(match.Groups["login"].ValueSpan) && IsTechnicalLogin(text, 0, start);
    }

    /// <summary>Require a surname prediction and one of the ambiguous suffixes.</summary>
    private static bool IsAmbiguousLogin(ReadOnlySpan<char> value)
    {
        int separator = value.IndexOf('_');
        return separator >= 4 && value.Length - separator == 3 &&
            MachineSuffixes.Contains(value[(separator + 1)..].ToString().ToLowerInvariant()) &&
            IsKnownLatinSurname(value[..separator].ToString().ToLowerInvariant());
    }

    /// <summary>Allow only a local service-account qualifier to override a login cue.</summary>
    private static bool IsTechnicalLogin(string text, int start, int cue) =>
        TechnicalLoginPrefix().IsMatch(LoginPrefix(text, start, cue));

    /// <summary>Bound the qualifier lookup and omit the optional opening quote of the login label.</summary>
    private static ReadOnlySpan<char> LoginPrefix(string text, int start, int cue)
    {
        int length = Math.Min(cue - start, 120);
        var prefix = text.AsSpan(cue - length, length);
        return !prefix.IsEmpty && prefix[^1] is ('"' or '\'') ? prefix[..^1] : prefix;
    }

    private const string LoginLabel = @"(?:login|user[ _-]?login|user[ _-]?name|klogin|логин)";
    private const string LoginPhrase = @"(?:logged[ \t]+in[ \t]+as|signed[ \t]+in[ \t]+as|(?:вход|вош[её]л[аи]?)[ \t]+под[ \t]+логином)";
    private const string TechnicalAccount = @"(?:service|system|machine|technical|automation|bot|robot|db|database|pipeline|ci|cd|сервисн(?:ый|ая)|системн(?:ый|ая)|техническ(?:ий|ая)|робот)";

    [GeneratedRegex(
        """(?<![\p{L}\p{M}\p{N}_./\\?&=%+@-])(?:(?i:""" + LoginLabel + """)["']?[ \t]*[:=][ \t]*|(?i:""" +
        LoginPhrase + """)(?:[ \t]*:[ \t]*|[ \t]+))["'«]?(?<login>[A-Za-z]{4,40}_[A-Za-z]{1,2})(?:(?='(?:[^\p{L}\p{N}_]|$))|""" +
        TokenEnd + ")",
        RegexOptions.CultureInvariant, 100)]
    private static partial Regex LoginCandidates();

    [GeneratedRegex(@"\A" + LoginLabel + @"\z", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, 100)]
    internal static partial Regex LoginField();

    [GeneratedRegex(
        """(?i:(?:\b|(?<=\\u0022))(?: (?:account|actor)[._-]?(?:type|kind)["']?[ \t]*[:=][ \t]*["']?""" + TechnicalAccount +
        """["']?[ \t]*[,;]|""" + TechnicalAccount +
        """(?:[ \t_-]+(?:account|user|уч[её]тная[ \t]+запись))?(?:[ \t]*:)?(?:[ \t]*\{)?)[ \t]*\z)""",
        RegexOptions.CultureInvariant | RegexOptions.IgnorePatternWhitespace, 100)]
    private static partial Regex TechnicalLoginPrefix();

    private static readonly FrozenSet<string> MachineSuffixes =
        new[] { "cd", "ci", "db", "id", "io", "ip", "os", "qa", "ui" }.ToFrozenSet(StringComparer.Ordinal);

    private const string TokenStart = @"(?<![\p{L}\p{M}\p{N}_@/\\'’-])(?<![\p{L}\p{M}\p{N}_]\.)";
    private const string Initial = "[A-ZА-ЯЁ]";
    private const string CompactName = @"[A-Za-z]{4,40}_[A-Za-z]{1,2}|[A-Za-z]{5,40}";

    [GeneratedRegex(TokenStart + @"(?:(?<surname>[A-Za-zА-Яа-яЁё][A-Za-zА-Яа-яЁё'’-]{3,39})[ \t]+(?:" +
        Initial + @"\.[ \t]*" + Initial + @"\.?|" + Initial + "{2}|" + Initial + @"\.)|" +
        @"(?<compact>" + CompactName + "))" + TokenEnd, RegexOptions.CultureInvariant, 100)]
    private static partial Regex ShortCandidates();

    /// <summary>Ignore case and soft-sign apostrophes when comparing a candidate to a spelling.</summary>
    private static string Normalize(string value) =>
        value.ToLowerInvariant().Replace("'", "", StringComparison.Ordinal).Replace("’", "", StringComparison.Ordinal);

    /// <summary>A separate patronymic supports surname predictions with a lower margin.</summary>
    private static bool NameAndSurname(string first, string last, bool hasPatronymic) =>
        Words.Names.Contains(first) && SurnameShapeModel.Predict(last, hasPatronymic ? 0.5f : 2.5f);

    /// <summary>Build common spellings once while keeping the Russian dictionary as the source of names.</summary>
    private static FrozenSet<string> Build(IEnumerable<string> source, params string[] aliases)
    {
        var words = new HashSet<string>(aliases, StringComparer.Ordinal);
        var result = new StringBuilder();
        foreach (string word in source)
        {
            foreach (string[] scheme in Schemes)
            {
                AddSpelling(words, result, word, scheme);
            }
        }
        return words.ToFrozenSet(StringComparer.Ordinal);
    }

    /// <summary>Transliterate given names and include the common ks → x variant.</summary>
    private static void AddSpelling(HashSet<string> words, StringBuilder result, string word, string[] scheme)
    {
        result.Clear();
        for (int i = 0; i < word.Length; i++)
        {
            char letter = word[i];
            if (letter == '-') result.Append(letter);
            else
            {
                int index = Cyrillic.IndexOf(letter);
                if (index >= 0 && scheme[index] != "_") result.Append(scheme[index]);
            }
        }
        string spelling = result.ToString();
        words.Add(spelling);
        if (spelling.Contains("ks", StringComparison.Ordinal))
            words.Add(spelling.Replace("ks", "x", StringComparison.Ordinal));
    }

    [GeneratedRegex(@"\A[A-Za-z][A-Za-z'’-]+\z", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking, 100)]
    private static partial Regex LatinWord();

    [GeneratedRegex(@"\A[a-z]{2,}(?:ovich|evich|ich|ovna|evna|ichna|ovitch|evitch)\z", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking, 100)]
    private static partial Regex Patronymic();

    /// <summary>Check a given name independently of the surname prediction.</summary>
    internal static bool IsLatinGivenName(string value) => Words.Names.Contains(value) || Words.AlternateNames.Contains(value);

    internal static IEnumerable<string> LatinNames => Words.Names;

    /// <summary>Collect alternate given-name spellings used only with a nearby person cue.</summary>
    private static FrozenSet<string> BuildAlternateNames()
    {
        var words = new HashSet<string>(StringComparer.Ordinal) { "victor" };
        var spelling = new StringBuilder();
        foreach (string name in LowercasePersonNames.RussianWords.Names)
        {
            if (!name.EndsWith("ий", StringComparison.Ordinal)) continue;
            foreach (string[] scheme in Schemes)
                AddSpelling(words, spelling, name[..^2] + "й", scheme);
        }
        return words.ToFrozenSet(StringComparer.Ordinal);
    }

    private static class Words
    {
        internal static readonly FrozenSet<string> Names = Build(LowercasePersonNames.RussianWords.Names,
            "alyona", "artyom", "fyodor", "pyotr", "semyon");
        internal static readonly FrozenSet<string> AlternateNames = BuildAlternateNames();
    }
}
