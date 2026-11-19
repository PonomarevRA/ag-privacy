using System.Buffers.Binary;
using System.Text.RegularExpressions;

namespace AgPrivacy;

/// <summary>Counts additional token proposals. Explicit secret rules always run separately.</summary>
public sealed record TokenContextCounts(long Reviewed, long Proposed);

/// <summary>Observes opaque values in bounded log contexts without feeding predictions back into masking.</summary>
public sealed partial class TokenContextShadow
{
    public const int ModelBytes = PersonalIdShadow.ModelBytes;
    internal static ReadOnlySpan<byte> Magic => "APTOK002"u8;
    private readonly bool specialized;
    private readonly float threshold;
    private readonly float[] weights;

    private TokenContextShadow(bool specialized, float threshold, float[] weights)
    {
        this.specialized = specialized;
        this.threshold = threshold;
        this.weights = weights;
    }

    /// <summary>Load a bounded model; the header selects generic or credential-specific features.</summary>
    public static TokenContextShadow Load(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != ModelBytes) throw new ArgumentException("invalid-token-context-model");
        bool specialized = bytes[..8].SequenceEqual(Magic);
        if (!specialized && !bytes[..8].SequenceEqual("APTOK001"u8))
            throw new ArgumentException("invalid-token-context-model");
        float threshold = ReadWeight(bytes[8..]);
        var weights = new float[PersonalIdShadow.Buckets];
        for (int i = 0; i < weights.Length; i++)
            weights[i] = ReadWeight(bytes[(12 + i * sizeof(float))..]);
        return new(specialized, threshold, weights);
    }

    /// <summary>Reject nonfinite values before inference.</summary>
    private static float ReadWeight(ReadOnlySpan<byte> bytes)
    {
        float value = BinaryPrimitives.ReadSingleLittleEndian(bytes);
        if (!float.IsFinite(value) || Math.Abs(value) > 64)
            throw new ArgumentException("invalid-token-weight");
        return value;
    }

    // Candidate generation is shape-only. A hash or trace identifier can have the same shape as a token.
    [GeneratedRegex(@"(?<![\w./~+\-])[A-Za-z0-9_~+\-]{16,256}(?![A-Za-z0-9_~+\-])",
        RegexOptions.CultureInvariant, 100)]
    internal static partial Regex Candidates();

    /// <summary>Skip ordinary letter runs and pure numbers before invoking the context model.</summary>
    internal static bool IsOpaque(ReadOnlySpan<char> value)
    {
        bool letter = false, digit = false;
        foreach (char c in value)
        {
            letter |= char.IsAsciiLetter(c);
            digit |= char.IsAsciiDigit(c);
            if (letter && digit) return true;
        }
        return false;
    }

    /// <summary>Score candidate context, excluding the candidate value from the model features.</summary>
    internal bool Predict(ReadOnlySpan<char> text, int start, int length)
    {
        Span<int> features = stackalloc int[PersonalIdShadow.FeatureLimit];
        int count = TokenContextFeatures.Extract(text, start, length, features, specialized);
        if (count == 0) return false;
        float score = 0;
        foreach (int index in features[..count]) score += weights[index];
        return score >= threshold;
    }

    /// <summary>Count novel suggestions when their final character enters the committed region.</summary>
    internal (int Reviewed, int Proposed) Observe(string text, LogMessageRange range, int from, int end, List<EntitySpan> masks)
    {
        if (range.End <= from || range.Start >= end) return default;
        var raw = text.AsSpan(range.Start, range.End - range.Start);
        if (raw.Length < 16) return default;

        ReadOnlySpan<char> decoded = raw;
        int[]? offsets = null;
        if (raw.Contains('\\'))
        {
            if (!JsonMessagePersonNames.TryDecode(raw, out string value)) return default;
            decoded = value;
            offsets = JsonMessagePersonNames.BuildOffsetMap(raw, value.Length);
        }

        int reviewed = 0, proposed = 0, maskIndex = 0;
        foreach (var match in Candidates().EnumerateMatches(decoded))
        {
            int last = match.Index + match.Length;
            int sourceStart = range.Start + (offsets is null ? match.Index : offsets[match.Index]);
            int sourceEnd = range.Start + (offsets is null ? last : offsets[last]);
            if (sourceEnd <= from || sourceEnd > end) continue;
            while (maskIndex < masks.Count && masks[maskIndex].Start + masks[maskIndex].Length <= sourceStart) maskIndex++;
            if (maskIndex < masks.Count && masks[maskIndex].Start < sourceEnd) continue;
            if (!IsOpaque(decoded.Slice(match.Index, match.Length))) continue;
            reviewed++;
            if (Predict(decoded, match.Index, match.Length)) proposed++;
        }
        return (reviewed, proposed);
    }
}
