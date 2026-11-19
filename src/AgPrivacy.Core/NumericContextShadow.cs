using System.Buffers.Binary;
using System.Text.RegularExpressions;

namespace AgPrivacy;

/// <summary>Aggregate predictions for committed candidates. None of these counters is permission to expose a value.</summary>
public sealed record NumericContextCounts(long Candidates, long Inn, long Kpp, long PersonalId, long Technical, long Abstained);

/// <summary>Separate tax and identifier classifiers in a fixed-size package for observation mode.</summary>
public sealed class NumericContextShadow
{
    internal static ReadOnlySpan<byte> Magic => "APNUM001"u8;
    internal const int Heads = 4;
    internal const int Outcomes = Heads + 1;
    public const int ModelBytes = 8 + Heads * (NumericContextFeatures.Count + 1) * sizeof(float);
    private static readonly NumericContextKind[] Classes =
        [NumericContextKind.Inn, NumericContextKind.Kpp, NumericContextKind.PersonalId, NumericContextKind.Technical];
    private const int Width = NumericContextFeatures.Count + 1;
    public const int SpecialistBytes = 12 + Width * sizeof(float);
    private static ReadOnlySpan<byte> SpecialistMagic => "APROLE01"u8;
    private readonly float[]?[] parameters;
    private readonly PersonalIdShadow? personalId;

    private NumericContextShadow(float[]?[] parameters, PersonalIdShadow? personalId = null)
    {
        this.parameters = parameters;
        this.personalId = personalId;
    }

    /// <summary>Create an observer without the bundled numeric weights. Attach only the desired models.</summary>
    public static NumericContextShadow Empty() => new(new float[]?[Heads]);

    /// <summary>Attach one tax specialist, checking that its file declares the expected role.</summary>
    public NumericContextShadow WithTaxSpecialist(ReadOnlySpan<byte> bytes, bool isInn)
    {
        var kind = isInn ? NumericContextKind.Inn : NumericContextKind.Kpp;
        if (bytes.Length != SpecialistBytes || !bytes[..8].SequenceEqual(SpecialistMagic) ||
            BinaryPrimitives.ReadInt32LittleEndian(bytes[8..]) != (int)kind)
            throw new ArgumentException("invalid-tax-specialist-model");
        var selected = (float[]?[])parameters.Clone();
        selected[(int)kind - 1] = ReadHead(bytes[12..]);
        return new(selected, personalId);
    }

    /// <summary>Encode one independently trained head for deployment without the other numeric weights.</summary>
    internal static byte[] EncodeSpecialist(NumericContextKind kind, ReadOnlySpan<float> head)
    {
        if (kind is not (NumericContextKind.Inn or NumericContextKind.Kpp) || head.Length != Width)
            throw new ArgumentException("invalid-tax-specialist-head");
        byte[] bytes = new byte[SpecialistBytes];
        SpecialistMagic.CopyTo(bytes);
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(8), (int)kind);
        for (int i = 0; i < head.Length; i++)
            BinaryPrimitives.WriteSingleLittleEndian(bytes.AsSpan(12 + i * sizeof(float)), head[i]);
        return bytes;
    }

    /// <summary>Attach an independent observer while retaining the original numeric decisions.</summary>
    public NumericContextShadow WithPersonalIdShadow(PersonalIdShadow observer)
    {
        ArgumentNullException.ThrowIfNull(observer);
        return new(parameters, observer);
    }

    internal bool HasPersonalIdShadow => personalId is not null;
    internal const int PersonalIdReviewed = Outcomes;
    internal const int PersonalIdProposed = Outcomes + 1;

    /// <summary>Load the bounded local weight table. Each head stores a threshold followed by its weights.</summary>
    public static NumericContextShadow Load(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != ModelBytes || !bytes[..8].SequenceEqual(Magic))
            throw new ArgumentException("invalid-numeric-context-model");

        var heads = new float[]?[Heads];
        for (int i = 0; i < Heads; i++)
            heads[i] = ReadHead(bytes[(8 + i * Width * sizeof(float))..]);
        return new(heads);
    }

    /// <summary>Decode one threshold followed by coefficients and reject invalid numbers.</summary>
    private static float[] ReadHead(ReadOnlySpan<byte> bytes)
    {
        var values = new float[Width];
        for (int i = 0; i < values.Length; i++)
        {
            values[i] = BinaryPrimitives.ReadSingleLittleEndian(bytes[(i * sizeof(float))..]);
            if (!float.IsFinite(values[i]) || Math.Abs(values[i]) > 64)
                throw new ArgumentException("invalid-numeric-context-model");
        }
        return values;
    }

    /// <summary>Resolve one candidate. Multiple competing predictions result in an abstention.</summary>
    internal NumericContextKind Classify(ReadOnlySpan<float> features)
    {
        NumericContextKind selected = NumericContextKind.Unknown;
        for (int head = 0; head < Heads; head++)
        {
            var kind = Classes[head];
            var weights = parameters[head];
            if (weights is null || !NumericContextFeatures.Supports(kind, features)) continue;
            float score = 0;
            for (int feature = 0; feature < features.Length; feature++)
                score += weights[1 + feature] * features[feature];
            if (score < weights[0]) continue;
            if (selected != NumericContextKind.Unknown) return NumericContextKind.Unknown;
            selected = kind;
        }
        return selected;
    }

    /// <summary>When a competing specialist is absent, preserve its explicit role evidence as a routing guard.</summary>
    private bool CanReviewPersonal(ReadOnlySpan<float> features)
    {
        foreach (var kind in Classes)
        {
            if (kind == NumericContextKind.PersonalId) continue;
            if (parameters[(int)kind - 1] is null && NumericContextFeatures.Supports(kind, features)) return false;
        }
        return true;
    }

    /// <summary>Count complete tokens when their final character is committed, mapping escaped JSON back to source offsets.</summary>
    internal void Observe(string window, LogMessageRange message, int from, int end, Span<long> counts)
    {
        var raw = window.AsSpan(message.Start, message.End - message.Start);
        if (raw.IndexOfAnyInRange('0', '9') < 0 && !raw.Contains('\\')) return;

        int[]? offsets = null;
        ReadOnlySpan<char> decoded = raw;
        if (raw.Contains('\\'))
        {
            if (!JsonMessagePersonNames.TryDecode(raw, out string value)) return;
            decoded = value.AsSpan();
            offsets = JsonMessagePersonNames.BuildOffsetMap(raw, value.Length);
        }

        Span<float> features = stackalloc float[NumericContextFeatures.Count];
        foreach (var match in NumericContextFeatures.Candidates().EnumerateMatches(decoded))
        {
            int last = match.Index + match.Length;
            int sourceEnd = message.Start + (offsets is null ? last : offsets[last]);
            if (sourceEnd <= from || sourceEnd > end) continue;
            NumericContextFeatures.Extract(decoded, match.Index, match.Length, features);
            var kind = Classify(features);
            counts[(int)kind]++;
            if (personalId is not null && kind == NumericContextKind.Unknown && CanReviewPersonal(features))
            {
                counts[PersonalIdReviewed]++;
                if (personalId.Predict(decoded, match.Index, match.Length))
                    counts[PersonalIdProposed]++;
            }
        }
    }
}
