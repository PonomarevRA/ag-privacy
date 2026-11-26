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
    private readonly SpanDecisionModel? veto;
    private readonly int vetoScope;
    private readonly SpanDecisionModel? rescue;
    private const int VetoHeaderBytes = sizeof(int);

    private PilotSpanSelection(SpanPersonDetector detector, float[] cutoffs, SpanDecisionModel? decision, int mode,
        SpanDecisionModel? veto, int vetoScope, SpanDecisionModel? rescue)
    {
        this.detector = detector;
        this.cutoffs = cutoffs;
        this.decision = decision;
        this.mode = mode;
        this.veto = veto;
        this.vetoScope = vetoScope;
        this.rescue = rescue;
    }

    public const int MaximumFileBytes = HeaderBytes + SpanPersonDetector.MaximumFileBytes +
        3 * SpanDecisionModel.MaximumFileBytes + VetoHeaderBytes;

    /// <summary>Read the optional wrapper while leaving the two published formats available.</summary>
    public static IPersonDetector Load(ReadOnlySpan<byte> bytes)
    {
        if (!bytes.StartsWith(Magic))
            return SpanPersonDetector.LoadModel(bytes);
        if (bytes.Length <= HeaderBytes || bytes.Length > MaximumFileBytes)
            throw new ArgumentException("pilot-model-size");
        int mode = BinaryPrimitives.ReadInt32LittleEndian(bytes[8..]);
        int detectorLength = BinaryPrimitives.ReadInt32LittleEndian(bytes[12..]);
        if (mode is < 1 or > 5 || detectorLength <= 0 || detectorLength > bytes.Length - HeaderBytes)
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
        SpanDecisionModel? veto = null;
        SpanDecisionModel? rescue = null;
        int vetoScope = 0;
        if (mode >= 4)
        {
            int decisionLength = SpanDecisionModel.MaximumFileBytes;
            int headOffset = decisionLength + VetoHeaderBytes;
            int expectedSize = headOffset + (mode == 5 ? 2 : 1) * decisionLength;
            if (suffix.Length != expectedSize)
                throw new ArgumentException("pilot-veto-size");
            vetoScope = BinaryPrimitives.ReadInt32LittleEndian(suffix[decisionLength..]);
            if (vetoScope is < 1 or > 3 || (mode == 5 && vetoScope != 1))
                throw new ArgumentException("pilot-veto-scope");
            veto = SpanDecisionModel.Load(suffix.Slice(headOffset, decisionLength));
            if (mode == 5)
                rescue = SpanDecisionModel.Load(suffix[(headOffset + decisionLength)..]);
            suffix = suffix[..decisionLength];
        }
        SpanDecisionModel? decision = mode == 1 ? null : SpanDecisionModel.Load(suffix);
        return new Runner(new PilotSpanSelection(detector, cutoffs, decision, mode, veto, vetoScope, rescue));
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
        rankingScore = mode >= 3 ? score : original;
        return score >= cutoffs[group];
    }

    /// <summary>Allow the second head to reject eligible winners without reranking them.</summary>
    internal bool Suppress(string text, IReadOnlyList<PersonToken> tokens,
        int first, int last, int end, float baseScore)
    {
        if (veto is null)
            return false;
        ReadOnlySpan<char> value = text.AsSpan(tokens[first].Start, end - tokens[first].Start);
        if (AlphabetBalance(value) <= 0)
            return false;
        bool shortCandidate = last == first + 1 && tokens[first].Length > 1 && tokens[last].Length > 1;
        bool hasUppercase = false;
        foreach (char letter in value)
        {
            if (!char.IsUpper(letter))
                continue;
            hasUppercase = true;
            break;
        }
        bool eligible = !hasUppercase || (vetoScope >= 2 && shortCandidate) || vetoScope == 3;
        if (!eligible || veto.Score(text, tokens, first, last, end, baseScore) >= veto.Threshold)
            return false;
        // Reconsider only lowercase three-word winners of the original ranking.
        if (rescue is null || hasUppercase || last != first + 2)
            return true;
        return rescue.Score(text, tokens, first, last, end, baseScore) < rescue.Threshold;
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
