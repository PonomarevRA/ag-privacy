using System.Text.RegularExpressions;

namespace AgPrivacy;

internal enum NumericContextKind { Unknown, Inn, Kpp, PersonalId, Technical }

/// <summary>Shared candidate and feature extraction for the numeric context models and offline evaluation.</summary>
internal static partial class NumericContextFeatures
{
    internal const int Count = 16;
    private const int ContextLength = 64;
    private static readonly string[][] Cues =
    [
        ["инн", "inn", "taxpayer", "tax id", "налоговый номер", "номер налогоплательщика"],
        ["кпп", "kpp", "tax branch", "registration reason", "код постановки", "код причины учета", "код причины учёта"],
        ["client id", "customer id", "person id", "clientid", "customerid", "personid", "profile id", "номер клиента", "код клиента", "клиентский идентификатор", "номер пользователя", "идентификатор пользователя", "user identifier", "номером клиента", "id клиента", "id профиля", "личный идентификатор", "идентификатор клиента"],
        ["operation id", "operationid", "request id", "requestid", "trace id", "trace.id", "job id", "jobid", "batch id", "transaction id", "номер операции", "номером операции", "номер задачи", "id запроса", "номер запроса", "серийный номер запроса", "идентификатор запроса", "номер пакета"]
    ];

    /// <summary>Match whole identifier-like tokens. Date segments and embedded digits are not separate candidates.</summary>
    [GeneratedRegex(@"(?<![\p{L}\p{N}_.@/-])(?:[A-Za-z]{1,12}[-_])?[0-9]{6,20}(?![\p{L}\p{N}_@/-]|\.[\p{L}\p{N}])",
        RegexOptions.CultureInvariant, 100)]
    internal static partial Regex Candidates();

    /// <summary>Encode format flags and the proximity of each cue on both sides of a candidate.</summary>
    internal static void Extract(ReadOnlySpan<char> text, int start, int length, Span<float> features, bool resolveRoles = true)
    {
        features.Clear();
        var value = text.Slice(start, length);
        bool digits = value.IndexOfAnyExceptInRange('0', '9') < 0;
        features[0] = 1;
        features[1] = digits && length is 10 or 12 ? 1 : 0;
        features[2] = digits && length == 9 ? 1 : 0;
        features[3] = features[1] == 1 && InnChecksum(value) ? 1 : 0;
        features[4] = digits ? 0 : 1;
        int leftSize = Math.Min(start, ContextLength);
        int end = start + length;
        var left = text.Slice(start - leftSize, leftSize);
        var right = text.Slice(end, Math.Min(text.Length - end, ContextLength));
        int leftBoundary = left.LastIndexOfAny(";\r\n!?");
        int rightBoundary = right.IndexOfAny(";\r\n!?");
        left = left[(leftBoundary + 1)..];
        if (rightBoundary >= 0) right = right[..rightBoundary];

        if (resolveRoles)
        {
            left = IsolateCandidate(left, before: true);
            right = IsolateCandidate(right, before: false);
        }

        for (int i = 0; i < Cues.Length; i++)
        {
            features[5 + i] = NearCue(left, Cues[i], before: true, resolveRoles);
            features[9 + i] = NearCue(right, Cues[i], before: false, resolveRoles);
        }

        if (resolveRoles)
        {
            // Compound action patterns provide a role even when the log omits “ID”.
            features[7] = Math.Max(features[7], CompactRole(left, right, ClientBefore(), ClientAfter()));
            features[8] = Math.Max(features[8], CompactRole(left, right, RequestBefore(), RequestAfter()));
            ResolveRoleCues(left, right, features);
        }
        features[13] = Math.Max(features[5], features[9]) * Math.Max(features[6], features[10]);
        features[14] = Math.Max(features[7], features[11]) * Math.Max(features[8], features[12]);
        features[15] = Math.Max(Math.Max(features[5], features[6]), Math.Max(features[9], features[10])) *
            Math.Max(features[8], features[12]);
    }

    /// <summary>Keep nearby clauses from borrowing the role of a different number in the same message.</summary>
    internal static ReadOnlySpan<char> IsolateCandidate(ReadOnlySpan<char> context, bool before)
    {
        int adjacent = -1;
        foreach (var match in Candidates().EnumerateMatches(context))
        {
            adjacent = before ? match.Index + match.Length : match.Index;
            if (!before) break;
        }
        if (adjacent < 0) return context;
        context = before ? context[adjacent..] : context[..adjacent];
        int separator = before ? context.LastIndexOfAny(",|") : context.IndexOfAny(",|");
        if (separator < 0) return context;
        return before ? context[(separator + 1)..] : context[..separator];
    }

    /// <summary>Prefer a closely attached role and abstain if the clause presents competing alternatives.</summary>
    private static void ResolveRoleCues(ReadOnlySpan<char> left, ReadOnlySpan<char> right, Span<float> features)
    {
        float strongest = 0;
        float second = 0;
        int best = 0;
        for (int i = 0; i < Cues.Length; i++)
        {
            float strength = Math.Max(features[5 + i], features[9 + i]);
            if (strength > strongest)
            {
                second = strongest;
                strongest = strength;
                best = i;
            }
            else second = Math.Max(second, strength);
        }
        if (second == 0) return;

        if (HasAlternative(left) || HasAlternative(right) || strongest - second < .3f)
        {
            features[5..13].Clear();
            return;
        }

        for (int i = 0; i < Cues.Length; i++)
        {
            if (i == best) continue;
            features[5 + i] = 0;
            features[9 + i] = 0;
        }
    }

    /// <summary>Recognize explicit alternatives inside the bounded clause.</summary>
    internal static bool HasAlternative(ReadOnlySpan<char> clause) =>
        clause.Contains('/') ||
        clause.Contains(" vs ", StringComparison.OrdinalIgnoreCase) ||
        clause.Contains("то ли ", StringComparison.OrdinalIgnoreCase) ||
        clause.Contains("alternatively", StringComparison.OrdinalIgnoreCase) ||
        clause.Contains(" or ", StringComparison.OrdinalIgnoreCase) ||
        clause.Contains(" или ", StringComparison.OrdinalIgnoreCase) ||
        clause.Contains(" либо ", StringComparison.OrdinalIgnoreCase) ||
        clause.TrimStart().StartsWith("vs ", StringComparison.OrdinalIgnoreCase) ||
        clause.TrimStart().StartsWith("or ", StringComparison.OrdinalIgnoreCase) ||
        clause.TrimStart().StartsWith("или ", StringComparison.OrdinalIgnoreCase) ||
        clause.TrimStart().StartsWith("либо ", StringComparison.OrdinalIgnoreCase);

    /// <summary>Find the closest whole-word phrase and weight direct attachment more heavily.</summary>
    private static float NearCue(ReadOnlySpan<char> text, string[] cues, bool before, bool rejectNegations)
    {
        int distance = int.MaxValue;
        foreach (string cue in cues)
        {
            int offset = 0;
            while (offset < text.Length)
            {
                int match = text[offset..].IndexOf(cue, StringComparison.OrdinalIgnoreCase);
                if (match < 0) break;
                int start = match + offset;
                int end = start + cue.Length;
                if ((start == 0 || !char.IsLetterOrDigit(text[start - 1])) &&
                    (end == text.Length || !char.IsLetterOrDigit(text[end])) &&
                    (!rejectNegations || (!NegatedCue().IsMatch(text[..start]) &&
                        (!before || !ValueDenied().IsMatch(text[end..])))))
                    distance = Math.Min(distance, before ? text.Length - end : start);
                offset = end;
            }
        }
        if (distance <= 8) return 1;
        if (distance <= 18) return 0.65f;
        return distance <= 35 ? 0.25f : 0;
    }

    /// <summary>Accept short actor and request labels only when an action confirms their role.</summary>
    private static float CompactRole(ReadOnlySpan<char> left, ReadOnlySpan<char> right, Regex before, Regex after) =>
        before.IsMatch(left) && after.IsMatch(right) ? 1 : 0;

    [GeneratedRegex(@"(?:^|[ ,])(?:for )?client\s+\z", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, 100)]
    private static partial Regex ClientBefore();

    [GeneratedRegex(@"\A(?:\s*\.|\s+(?:initiated|submitted|opened|started)\b)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, 100)]
    private static partial Regex ClientAfter();

    [GeneratedRegex(@"(?:^|[ ,])(?:request|operation|transaction|query)\s+\z", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, 100)]
    private static partial Regex RequestBefore();

    [GeneratedRegex(@"\A(?:\s*\.|\s+(?:processed|completed|from|initiated|executed|queued)\b)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, 100)]
    private static partial Regex RequestAfter();

    [GeneratedRegex(@"\A\s*(?:(?:is|was)\s+not|(?:это\s+)?не(?:\s+(?:равен|равно|соответствует))?)\s*[:=]?\s*\z",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, 100)]
    private static partial Regex ValueDenied();

    // Negation must directly govern the role phrase. A remote “не” in the same clause is insufficient.
    [GeneratedRegex(@"(?<![\p{L}\p{N}])(?:не(?:\s+(?:является|считается|указывает\s+на))?|not(?:\s+(?:a|an|the))?|isn't(?:\s+(?:a|an|the))?)\s*[:=\""«']?\s*\z",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, 100)]
    private static partial Regex NegatedCue();

    /// <summary>Validate the check-digit formulas for ten and twelve digit candidate shapes.</summary>
    private static bool InnChecksum(ReadOnlySpan<char> digits) => digits.Length == 10
        ? Check(digits, [2, 4, 10, 3, 5, 9, 4, 6, 8])
        : Check(digits, [7, 2, 4, 10, 3, 5, 9, 4, 6, 8]) &&
          Check(digits, [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8]);

    /// <summary>Check the digit immediately after the weighted prefix.</summary>
    private static bool Check(ReadOnlySpan<char> digits, ReadOnlySpan<int> weights)
    {
        int sum = 0;
        for (int i = 0; i < weights.Length; i++) sum += (digits[i] - '0') * weights[i];
        return sum % 11 % 10 == digits[weights.Length] - '0';
    }

    /// <summary>Keep stage predictions inside their shape and evidence constraints.</summary>
    internal static bool Supports(NumericContextKind kind, ReadOnlySpan<float> features) => kind switch
    {
        NumericContextKind.Inn => features[3] == 1 && Math.Max(features[5], features[9]) > 0,
        NumericContextKind.Kpp => features[2] == 1 && Math.Max(features[6], features[10]) > 0,
        NumericContextKind.PersonalId => Math.Max(features[7], features[11]) > 0,
        NumericContextKind.Technical => Math.Max(features[8], features[12]) > 0,
        _ => false
    };
}
