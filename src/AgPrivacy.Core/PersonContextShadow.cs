using System.Buffers.Binary;

namespace AgPrivacy;

/// <summary>Aggregate observations only. A proposed preserve decision never changes a stream replacement.</summary>
public sealed record PersonContextCounts(long Candidates, long WouldPreserve, long Abstained);

/// <summary>A fixed-size linear model for contextual review of heuristic person spans.</summary>
public sealed class PersonContextShadow
{
    internal const int FeatureCount = 11;
    public const int ModelBytes = 8 + sizeof(float) * (FeatureCount + 1);
    private const int ContextChars = 80;
    private static readonly string[] PersonCues =
        ["client", "customer", "recipient", "person", "employee", "patient", "human", "клиент", "получатель", "сотрудник", "человек", "заявитель", "владелец", "контакт", "фио"];
    private static readonly string[] MachineCues =
        ["worker", "runner", "pipeline", "service", "serviceaccount", "bot", "fixture", "stub", "module", "component", "job", "pod", "scheduler", "automation", "сервис", "робот", "процесс", "воркер", "заглушка"];
    private static readonly string[] AssignmentCues = ["login", "username", "account", "логин", "учётка", "учетка"];
    private readonly float[] weights;
    private readonly float threshold;

    private PersonContextShadow(float[] weights, float threshold)
    {
        this.weights = weights;
        this.threshold = threshold;
    }

    /// <summary>Read a versioned linear weight table. The format contains no executable graph or strings.</summary>
    public static PersonContextShadow Load(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != ModelBytes || !bytes[..8].SequenceEqual("APCTX001"u8))
            throw new ArgumentException("invalid-person-context-model");
        float threshold = BinaryPrimitives.ReadSingleLittleEndian(bytes[8..]);
        if (!float.IsFinite(threshold) || Math.Abs(threshold) > 64)
            throw new ArgumentException("invalid-person-context-model");

        var weights = new float[FeatureCount];
        for (int i = 0; i < weights.Length; i++)
        {
            weights[i] = BinaryPrimitives.ReadSingleLittleEndian(bytes[(12 + i * sizeof(float))..]);
            if (!float.IsFinite(weights[i]) || Math.Abs(weights[i]) > 64)
                throw new ArgumentException("invalid-person-context-model");
        }
        return new(weights, threshold);
    }

    /// <summary>Score a single span using a small local clause inside the message value.</summary>
    internal ContextVerdict Review(string text, LogMessageRange range, EntitySpan span)
    {
        Span<float> features = stackalloc float[FeatureCount];
        if (!Extract(text, range, span, features)) return ContextVerdict.Abstain;
        // Positive machine evidence is required even when the learned score is high.
        if (features[3] == 0 && features[4] == 0) return ContextVerdict.Mask;

        float score = 0;
        for (int i = 0; i < weights.Length; i++) score += weights[i] * features[i];
        return score >= threshold ? ContextVerdict.Preserve : ContextVerdict.Mask;
    }

    /// <summary>Require a nearby person cue before generating a candidate from an alternate spelling.</summary>
    internal static bool HasPersonEvidence(string text, LogMessageRange range, int start, int end)
    {
        int leftSize = Math.Min(ContextChars, start - range.Start);
        int rightSize = Math.Min(ContextChars, range.End - end);
        var left = LocalClause(text.AsSpan(start - leftSize, leftSize), before: true).TrimEnd();
        var right = LocalClause(text.AsSpan(end, rightSize), before: false);
        return HasCue(left, PersonCues) || HasCue(right, PersonCues) ||
            left.EndsWith(" sent to", StringComparison.OrdinalIgnoreCase) ||
            left.EndsWith(" sent to:", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Extract identical bounded features for training and inference without storing the message or name.</summary>
    internal static bool Extract(string text, LogMessageRange range, EntitySpan span, Span<float> features)
    {
        int end = span.Start + span.Length;
        int leftSize = Math.Min(ContextChars, span.Start - range.Start);
        int rightSize = Math.Min(ContextChars, range.End - end);
        var left = LocalClause(text.AsSpan(span.Start - leftSize, leftSize), before: true);
        var right = LocalClause(text.AsSpan(end, rightSize), before: false);
        var value = text.AsSpan(span.Start, span.Length);
        // Raw escapes can hide an opposing cue. The observer abstains on those clauses.
        if (left.Contains('\\') || right.Contains('\\') || value.Contains('\\')) return false;

        features[0] = 1;
        features[1] = HasCue(left, PersonCues) ? 1 : 0;
        features[2] = HasCue(right, PersonCues) ? 1 : 0;
        features[3] = HasCue(left, MachineCues) ? 1 : 0;
        features[4] = HasCue(right, MachineCues) ? 1 : 0;
        features[5] = HasCue(left, AssignmentCues) ? 1 : 0;
        features[6] = value.Contains('_') ? 1 : 0;
        features[7] = value.Contains(' ') ? 1 : 0;
        features[8] = left.Contains('=') || left.Contains(':') ? 1 : 0;
        features[9] = features[1] * features[4];
        features[10] = features[2] * features[3];
        return true;
    }

    /// <summary>Stop at the closest clause delimiter without treating dots inside technical keys as delimiters.</summary>
    private static ReadOnlySpan<char> LocalClause(ReadOnlySpan<char> text, bool before)
    {
        int split = before ? text.LastIndexOfAny(";\r\n!?") : text.IndexOfAny(";\r\n!?");
        int period = before ? text.LastIndexOf(". ", StringComparison.Ordinal) : text.IndexOf(". ", StringComparison.Ordinal);
        if (before) return text[(Math.Max(split, period) + 1)..];
        if (period >= 0 && (split < 0 || period < split)) split = period;
        return split < 0 ? text : text[..split];
    }

    /// <summary>Recognize a complete cue in the clause without allocating tokens.</summary>
    private static bool HasCue(ReadOnlySpan<char> clause, string[] cues)
    {
        foreach (string cue in cues)
        {
            var rest = clause;
            int offset = 0;
            while (true)
            {
                int index = rest.IndexOf(cue, StringComparison.OrdinalIgnoreCase);
                if (index < 0) break;
                int first = offset + index;
                int last = first + cue.Length;
                if ((first == 0 || !char.IsLetterOrDigit(clause[first - 1])) &&
                    (last == clause.Length || !char.IsLetterOrDigit(clause[last])))
                    return true;
                offset = last;
                rest = clause[offset..];
            }
        }
        return false;
    }
}

internal enum ContextVerdict { Mask, Preserve, Abstain }
internal readonly record struct LogMessageRange(int Start, int End);
