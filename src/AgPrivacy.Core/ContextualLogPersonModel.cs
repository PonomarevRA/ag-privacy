using System.Text.RegularExpressions;

namespace AgPrivacy;

/// <summary>Apply the micro model to bounded person candidates inside a log message.</summary>
internal static partial class ContextualLogPersonModel
{
    /// <summary>Require local person evidence and a complete prediction before adding a mask.</summary>
    internal static void Add(string text, int start, int length, List<EntitySpan> spans, IPersonDetector? model, IPersonDetector? proseModel)
    {
        AddUnlabelledCompoundNames(text, start, length, spans, model, proseModel);
        if (model is null && proseModel is null) return;
        int end = start + length;
        int covered = start;
        for (Match match = Names().Match(text, start, length); match.Success; match = match.NextMatch())
        {
            var first = match.Groups["first"];
            if (first.Index < covered) continue;
            var second = match.Groups["second"];
            var third = match.Groups["third"];
            // A patronymic identifies the third word without accepting arbitrary trailing prose.
            int last = second.Index + second.Length;
            if (third.Success && Patronymic().IsMatch(third.ValueSpan)) last = third.Index + third.Length;
            var left = text.AsSpan(Math.Max(start, first.Index - 100), Math.Min(first.Index - start, 100));
            var right = text.AsSpan(last, Math.Min(end - last, 100));
            if (LogPersonContext.IsTechnicalValue(text, start, first.Index)) continue;
            bool namedRole = RoleBefore().IsMatch(left);
            if (!namedRole && TechnicalSubject().IsMatch(text.AsSpan(first.Index, last - first.Index))) continue;
            if (!namedRole && !PersonAction().IsMatch(right)) continue;
            bool firstGiven = LooksLikeGivenName(first.ValueSpan);
            bool secondGiven = LooksLikeGivenName(second.ValueSpan);
            bool givenName = firstGiven || secondGiven;
            bool confirmed = model is not null && (namedRole || givenName) &&
                Confirms(model, first.ValueSpan, second.ValueSpan, namedRole && givenName);
            if (!confirmed && proseModel is not null &&
                (namedRole || givenName || HasSurnameEvidence(first.ValueSpan, second.ValueSpan, 0.5f)))
            {
                confirmed = ConfirmsInContext(proseModel, left, text.AsSpan(first.Index, last - first.Index), right) &&
                    Confirms(proseModel, first.ValueSpan, second.ValueSpan, namedRole && givenName);
            }
            if (!confirmed && proseModel is not null)
                confirmed = ConfirmsNewForm(proseModel, text.AsSpan(first.Index, last - first.Index),
                    first.ValueSpan, second.ValueSpan, last > second.Index + second.Length, namedRole, firstGiven, secondGiven);
            if (!confirmed) continue;
            // Keep novel predictions out of the exact-repeat cache, which requires priority 50.
            spans.Add(new(first.Index, last - first.Index, "PERSON", 45));
            covered = last;
        }

        AddPersonalLogins(text, start, length, spans, model, proseModel);
    }

    /// <summary>Use the configured prose model on complete accounts with an explicit person role.</summary>
    private static void AddPersonalLogins(string text, int start, int length, List<EntitySpan> spans,
        IPersonDetector? model, IPersonDetector? proseModel)
    {
        if (!text.AsSpan(start, length).Contains('_')) return;
        for (Match match = PersonLogin().Match(text, start, length); match.Success; match = match.NextMatch())
        {
            Group login = match.Groups["login"], surname = match.Groups["surname"];
            if (LogPersonContext.IsTechnicalValue(text, start, login.Index)) continue;
            bool confirmed = model is not null && ConfirmsSurname(model, surname.ValueSpan);
            if (!confirmed && proseModel is not null && SurnameShapeModel.Predict(surname.ValueSpan, 0f))
            {
                var left = text.AsSpan(match.Index, login.Index - match.Index);
                string candidate = string.Concat(left, login.ValueSpan);
                confirmed = Covers(proseModel, candidate, left.Length);
            }
            if (confirmed) spans.Add(new(login.Index, login.Length, "PERSON", 45));
        }
    }

    /// <summary>Check compound surnames and initials next to an action that can identify a person.</summary>
    private static void AddUnlabelledCompoundNames(string text, int start, int length, List<EntitySpan> spans,
        IPersonDetector? model, IPersonDetector? proseModel)
    {
        var message = text.AsSpan(start, length);
        if (!message.ContainsAny("-.‐‑")) return;
        int end = start + length;
        for (Match match = ComplexCandidates().Match(text, start, length); match.Success; match = match.NextMatch())
        {
            int nameStart = match.Index;
            int nameEnd = nameStart + match.Length;
            if (LogPersonContext.IsTechnicalValue(text, start, nameStart)) continue;
            if (!PersonAction().IsMatch(text.AsSpan(nameEnd, Math.Min(end - nameEnd, 100)))) continue;

            Group given = match.Groups["given"];
            Group surname = match.Groups["surname"];
            if (!given.Success)
            {
                // Initials have no given-name token. Require confirmation of the surname in the trained name view.
                if (!SurnameShapeModel.Predict(surname.ValueSpan, 0f) && (model is null || !ConfirmsSurname(model, surname.ValueSpan))) continue;
            }
            else
            {
                if (!LooksLikeGivenName(given.ValueSpan)) continue;
                var compound = surname.ValueSpan;
                int dash = compound.IndexOfAny('-', '‐', '‑');
                bool spelling = SurnameShapeModel.Predict(compound[..dash], -1f) &&
                    SurnameShapeModel.Predict(compound[(dash + 1)..], -1f);
                if (!spelling && (model is null || !ConfirmsCompound(model, given.ValueSpan, compound[..dash], compound[(dash + 1)..])) &&
                    (proseModel is null || !ConfirmsCompound(proseModel, given.ValueSpan, compound[..dash], compound[(dash + 1)..])))
                    continue;
            }

            spans.Add(new(nameStart, match.Length, "PERSON", 46));
        }
    }

    /// <summary>Score each half of a hyphenated surname next to the same given name.</summary>
    private static bool ConfirmsCompound(IPersonDetector model, ReadOnlySpan<char> given,
        ReadOnlySpan<char> first, ReadOnlySpan<char> second) =>
        Confirms(model, given, first, explicitRole: false) && Confirms(model, given, second, explicitRole: false);

    /// <summary>Use a known given name only for ambiguous prose without an explicit person label.</summary>
    private static bool LooksLikeGivenName(ReadOnlySpan<char> value)
    {
        string normalized = value.ToString().ToLowerInvariant().Replace('ё', 'е');
        return LowercasePersonNames.RussianWords.Names.Contains(normalized) ||
            TransliteratedPersonNames.IsLatinGivenName(normalized);
    }

    /// <summary>For an unfamiliar given name, require a complete prediction in the actual local context.</summary>
    private static bool ConfirmsInContext(IPersonDetector model, ReadOnlySpan<char> left, ReadOnlySpan<char> value,
        ReadOnlySpan<char> right)
    {
        // Normalize the name candidate as in the standalone model call, retaining the actual prose.
        string normalized = System.Globalization.CultureInfo.InvariantCulture.TextInfo.ToTitleCase(value.ToString().ToLowerInvariant());
        if (normalized.Length != value.Length) return false;
        string context = string.Concat(left, normalized, right);
        foreach (var span in model.Find(context))
            if (span.Start == left.Length && span.Length == value.Length) return true;
        return false;
    }

    /// <summary>Use spelling evidence to distinguish an unfamiliar person from a two-word technical subject.</summary>
    private static bool HasSurnameEvidence(ReadOnlySpan<char> first, ReadOnlySpan<char> second, float margin) =>
        SurnameShapeModel.Predict(first, margin) || SurnameShapeModel.Predict(second, margin);

    /// <summary>Check a supported surname shape and ask the model to confirm the complete name.</summary>
    private static bool ConfirmsNewForm(IPersonDetector model, ReadOnlySpan<char> value,
        ReadOnlySpan<char> first, ReadOnlySpan<char> second, bool patronymic, bool explicitRole, bool firstGiven, bool secondGiven)
    {
        float margin = explicitRole || patronymic ? -1f : 0.5f;
        if (firstGiven || secondGiven)
        {
            if (!SurnameShapeModel.Predict(firstGiven ? second : first, margin)) return false;
        }
        else if (!HasSurnameEvidence(first, second, margin)) return false;

        string normalized = System.Globalization.CultureInfo.InvariantCulture.TextInfo.ToTitleCase(value.ToString().ToLowerInvariant());
        if (Covers(model, normalized, 0)) return true;
        const string personLabel = "Employee: ";
        return (explicitRole || firstGiven || secondGiven) && Covers(model, personLabel + normalized, personLabel.Length);
    }

    /// <summary>Score a canonical two-word window with the original spelling retained for masking.</summary>
    private static bool Confirms(IPersonDetector model, ReadOnlySpan<char> first, ReadOnlySpan<char> second, bool explicitRole)
    {
        string candidate = string.Concat(Title(first), " ", Title(second));
        if (Covers(model, candidate, 0)) return true;

        // The trainer includes labelled examples. Reuse that view only for an explicit role
        // and a known given name, where another form of spelling has independent support.
        const string label = "Client: ";
        return explicitRole && Covers(model, label + candidate, label.Length);
    }

    /// <summary>Score a surname in the personnel context supplied by the login rule.</summary>
    private static bool ConfirmsSurname(IPersonDetector model, ReadOnlySpan<char> surname)
    {
        const string context = "Client: ";
        const string nameLabel = "Name: ";
        string normalized = Title(surname);
        return Covers(model, context + normalized, context.Length) ||
            Covers(model, nameLabel + normalized, nameLabel.Length);
    }

    /// <summary>Require coverage of all candidate characters in the model's span.</summary>
    private static bool Covers(IPersonDetector model, string text, int start)
    {
        foreach (var span in model.Find(text))
            if (span.Start <= start && span.Start + span.Length == text.Length) return true;
        return false;
    }

    /// <summary>Normalize case for the existing perceptron's learned features.</summary>
    private static string Title(ReadOnlySpan<char> word) =>
        char.ToUpperInvariant(word[0]) + word[1..].ToString().ToLowerInvariant();

    private const string Word = @"[A-Za-zА-Яа-яЁё][A-Za-zА-Яа-яЁё'-]{1,39}";
    private const string Boundary = @"[\p{L}\p{M}\p{N}_@/\\'-]";

    [GeneratedRegex("(?<!" + Boundary + @")(?<![\p{L}\p{N}_]\.)(?=(?<first>" + Word + @")[ \t]+(?<second>" + Word + @")(?!" +
        Boundary + @"|\.[\p{L}\p{N}_])(?:[ \t]+(?<third>" + Word + @")(?!" + Boundary + @"))?)", RegexOptions.CultureInvariant, 100)]
    private static partial Regex Names();

    [GeneratedRegex(@"(?:\b(?:recipient|client|customer|applicant|employee|contact|person|получатель|клиент|пользователь|заявитель|сотрудник|контакт|фио|ответственный|(?:согласующ|ответственн|уполномоченн)[а-я]+[ \t]+лицо)[ \t]*[:=][ \t]*|\b(?:heard from|spoke (?:with|to)|written by|sent(?:[ \t]+(?:the[ \t]+)?[a-z]+(?:[ \t]+[a-z]+)?)?[ \t]+to|delivered to|addressed to|received from|уведомление для|связались с|письмо от)[ \t]+)[""«']?\z",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, 100)]
    private static partial Regex RoleBefore();

    [GeneratedRegex(@"\A[ \t]+(?:подтвердил[аи]?|попросил[аи]?|сообщил[аи]?|выбрал[аи]?|ответил[аи]?|согласовал[аи]?|разрешил[аи]?|одобрил[аи]?|signed|confirmed|replied|requested|agreed|approved|authori[sz]ed)\b",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, 100)]
    private static partial Regex PersonAction();

    // Common adjective+noun and noun+genitive service subjects are frequent beside person-like actions.
    [GeneratedRegex(@"\A(?:(?:[а-яё]{3,}(?:ный|ная|ной|н[ое]е|вый|вая|вое|евой|щий|щая|щее))[ \t]+[а-яё]{1,}(?:тор|чик|щик|тель|ёр|уль|люз|тер|нер|кер|порт)|(?:очередь|реестр|служба|контур|модуль|система|конвейер)[ \t]+[а-яё]{3,})\z",
        RegexOptions.CultureInvariant | RegexOptions.IgnoreCase, 100)]
    private static partial Regex TechnicalSubject();

    [GeneratedRegex(@"\A(?:[а-яё]{2,}(?:ович|евич|овна|евна|ична|ич)|[a-z]{2,}(?:ovich|evich|ovna|evna|ich))\z",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, 100)]
    private static partial Regex Patronymic();

    private const string Compound = LabelledCompoundPersonNames.Compound;
    private const string Initials = LabelledCompoundPersonNames.TwoInitials;

    [GeneratedRegex(@"(?<![\p{L}\p{M}\p{N}_@./\\'-])(?:(?<given>" + Word + @")[ \t]+(?<surname>" + Compound +
        ")|(?<surname>" + Compound + @")[ \t]+(?<given>" + Word + @")|(?<surname>" + Word + @")[ \t]+" + Initials +
        "|" + Initials + @"[ \t]+(?<surname>" + Word + @"))(?![\p{L}\p{M}\p{N}_@./\\'-])",
        RegexOptions.CultureInvariant, 100)]
    private static partial Regex ComplexCandidates();

    [GeneratedRegex(@"\b(?:client|customer|employee|applicant|person|клиент[а-я]*|пользовател[а-я]+|сотрудник[а-я]*)['’]?(?:s)?[ \t]+(?:account[ \t]+)?(?:login|username|логин)[ \t]*[:=][ \t]*[""«']?(?<login>(?<surname>[a-z]{4,40})_[a-z]{1,2})(?![\w./@-])",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, 100)]
    private static partial Regex PersonLogin();
}
