using System.Buffers.Binary;

namespace AgPrivacy;

/// <summary>Load and apply an explicitly selected experimental acceptance policy.</summary>
public sealed class PilotSpanSelection
{
    private static ReadOnlySpan<byte> Magic => "AGPILOT1"u8;
    private const int HeaderBytes = 32;
    private readonly SpanPersonDetector detector;
    private readonly float[] cutoffs;
    private readonly SpanDecisionModel? decision;
    private readonly int mode;

    private PilotSpanSelection(SpanPersonDetector detector, float[] cutoffs, SpanDecisionModel? decision, int mode)
    {
        this.detector = detector;
        this.cutoffs = cutoffs;
        this.decision = decision;
        this.mode = mode;
    }

    public const int MaximumFileBytes = HeaderBytes + SpanPersonDetector.MaximumFileBytes + SpanDecisionModel.MaximumFileBytes;

    /// <summary>Read the optional wrapper while leaving the two published formats available.</summary>
    public static IPersonDetector Load(ReadOnlySpan<byte> bytes)
    {
        if (!bytes.StartsWith(Magic))
            return SpanPersonDetector.LoadModel(bytes);
        if (bytes.Length <= HeaderBytes || bytes.Length > MaximumFileBytes)
            throw new ArgumentException("pilot-model-size");
        int mode = BinaryPrimitives.ReadInt32LittleEndian(bytes[8..]);
        int detectorLength = BinaryPrimitives.ReadInt32LittleEndian(bytes[12..]);
        if (mode is < 1 or > 3 || detectorLength <= 0 || detectorLength > bytes.Length - HeaderBytes)
            throw new ArgumentException("pilot-model-header");
        if (SpanPersonDetector.LoadModel(bytes.Slice(HeaderBytes, detectorLength)) is not SpanPersonDetector detector)
            throw new ArgumentException("pilot-requires-span-model");
        var cutoffs = new float[4];
        for (int i = 0; i < cutoffs.Length; i++)
        {
            cutoffs[i] = BinaryPrimitives.ReadSingleLittleEndian(bytes[(16 + sizeof(float) * i)..]);
            if (!float.IsFinite(cutoffs[i]))
                throw new ArgumentException("pilot-cutoff");
        }
        ReadOnlySpan<byte> suffix = bytes[(HeaderBytes + detectorLength)..];
        if (mode == 1 && !suffix.IsEmpty)
            throw new ArgumentException("pilot-unexpected-decision-model");
        SpanDecisionModel? decision = mode == 1 ? null : SpanDecisionModel.Load(suffix);
        return new Runner(new PilotSpanSelection(detector, cutoffs, decision, mode));
    }

    /// <summary>Evaluate the same candidate with either a script-specific cutoff or learned score.</summary>
    public bool Accept(string text, IReadOnlyList<PersonToken> tokens, int first, int last, int end,
        int wholeBalance, float original, out float rankingScore)
    {
        int start = tokens[first].Start;
        int candidateBalance = AlphabetBalance(text.AsSpan(start, end - start));
        int contextBalance = wholeBalance - candidateBalance;
        bool cyrillic = candidateBalance > 0;
        bool russianContext = contextBalance > 0 || (contextBalance == 0 && cyrillic);
        int group = (russianContext ? 0 : 2) + (cyrillic ? 0 : 1);
        float score = decision?.Score(text, tokens, first, last, end, original) ?? original;
        rankingScore = mode == 3 ? score : original;
        return score >= cutoffs[group];
    }

    /// <summary>Compute the Cyrillic minus Latin letter count for a UTF-16 slice.</summary>
    public static int AlphabetBalance(ReadOnlySpan<char> value)
    {
        int count = 0;
        foreach (char letter in value)
        {
            if (letter is >= 'А' and <= 'я' or 'Ё' or 'ё')
                count++;
            else if (letter is >= 'A' and <= 'Z' or >= 'a' and <= 'z')
                count--;
        }
        return count;
    }

    private sealed class Runner(PilotSpanSelection selection) : IPersonDetector
    {
        public string Version => "AGPILOT1";

        /// <summary>Run the selected acceptance policy inside the shared generator and overlap resolver.</summary>
        public IReadOnlyList<EntitySpan> Find(string text) => selection.detector.Find(text, selection);
    }
}
