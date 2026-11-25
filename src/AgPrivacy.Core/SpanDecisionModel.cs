using System.Buffers.Binary;

namespace AgPrivacy;

/// <summary>Scores existing UTF-16 name intervals with nearby shape and morphology features.</summary>
public sealed class SpanDecisionModel
{
    private const int DenseFeatures = 32;
    private const int HashBuckets = 1 << 14;
    private const int HeaderBytes = 12;
    public const int FeatureCount = DenseFeatures + HashBuckets;
    public const int MaximumFileBytes = HeaderBytes + sizeof(float) * FeatureCount;
    public const int MaximumFeatures = 256;

    private static ReadOnlySpan<byte> Magic => "AGDECI01"u8;
    private readonly float[] weights;

    private SpanDecisionModel(float[] weights, float threshold)
    {
        this.weights = weights;
        Threshold = threshold;
    }

    public float Threshold { get; }

    /// <summary>Read a versioned linear checkpoint and reject non-finite parameters.</summary>
    public static SpanDecisionModel Load(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != MaximumFileBytes || !bytes.StartsWith(Magic))
            throw new ArgumentException("span-decision-format", nameof(bytes));
        float threshold = BinaryPrimitives.ReadSingleLittleEndian(bytes[8..]);
        if (!float.IsFinite(threshold))
            throw new ArgumentException("span-decision-threshold", nameof(bytes));
        var weights = new float[FeatureCount];
        for (int index = 0; index < weights.Length; index++)
        {
            float weight = BinaryPrimitives.ReadSingleLittleEndian(bytes[(HeaderBytes + index * sizeof(float))..]);
            if (!float.IsFinite(weight))
                throw new ArgumentException("span-decision-weight", nameof(bytes));
            weights[index] = weight;
        }
        return new SpanDecisionModel(weights, threshold);
    }

    /// <summary>Write little-endian weights and the caller-selected acceptance threshold.</summary>
    public static byte[] Encode(ReadOnlySpan<float> weights, float threshold)
    {
        if (weights.Length != FeatureCount || !float.IsFinite(threshold))
            throw new ArgumentException("span-decision-shape", nameof(weights));
        var bytes = new byte[MaximumFileBytes];
        Magic.CopyTo(bytes);
        BinaryPrimitives.WriteSingleLittleEndian(bytes.AsSpan(8), threshold);
        for (int index = 0; index < weights.Length; index++)
        {
            if (!float.IsFinite(weights[index]))
                throw new ArgumentException("span-decision-weight", nameof(weights));
            BinaryPrimitives.WriteSingleLittleEndian(bytes.AsSpan(HeaderBytes + index * sizeof(float)), weights[index]);
        }
        return bytes;
    }

    /// <summary>Return one candidate's score before cutoff and overlap resolution.</summary>
    public float Score(string text, IReadOnlyList<PersonToken> tokens, int first, int last, int end, float baseScore)
    {
        Span<Feature> features = stackalloc Feature[MaximumFeatures];
        int count = Collect(text, tokens, first, last, end, baseScore, features);
        return Evaluate(weights, features[..count]);
    }

    /// <summary>Apply the sparse features in the same order used by the trainer.</summary>
    public static float Evaluate(ReadOnlySpan<float> weights, ReadOnlySpan<Feature> features)
    {
        float score = 0;
        foreach (Feature feature in features)
            score += weights[feature.Index] * feature.Value;
        return score;
    }

    /// <summary>Write sparse features for a generated two-to-four-token window into caller storage.</summary>
    public static int Collect(string text, IReadOnlyList<PersonToken> tokens, int first, int last,
        int end, float baseScore, Span<Feature> destination)
    {
        var features = new FeatureWriter(destination);
        int start = tokens[first].Start;
        float score = Math.Clamp(baseScore, -8f, 8f) * .25f;
        features.Add(0, 1);
        features.Add(1, score);
        features.Add(2, MathF.Max(0f, score - .3f));
        features.Add(3, MathF.Min(0f, score - .3f));
        features.Add(4 + last - first, 1);
        features.Add(8, Math.Min(end - start, 40) * .025f);
        int spanAlphabet = 0;
        int capitals = 0;
        int initials = 0;
        for (int index = first; index <= last; index++)
        {
            PersonToken token = tokens[index];
            int alphabet = ReadAlphabet(token.Lower);
            spanAlphabet |= alphabet;
            int role = index == first ? 0 : index == last ? 2 : 1;
            int shape = ReadShape(token.Word);
            capitals += shape == 1 ? 1 : 0;
            initials += token.Length == 1 ? 1 : 0;
            AddWord(ref features, token, role, alphabet, shape);
            if (index < last)
            {
                int wordEnd = token.Start + token.Length;
                ReadOnlySpan<char> gap = text.AsSpan(wordEnd, tokens[index + 1].Start - wordEnd);
                features.Hash(20 + role, ClassifyGap(gap));
            }
        }
        features.Hash(23, spanAlphabet);
        features.Hash(24, capitals);
        features.Hash(25, initials);
        int outsideAlphabet = AddNeighbors(ref features, tokens, first, last);
        features.Hash(26, spanAlphabet | (outsideAlphabet << 3));
        features.Add(10 + spanAlphabet, score);
        features.Add(18 + outsideAlphabet, score);
        features.Hash(27, start == 0 ? 0 : BoundaryKind(text[start - 1]));
        features.Hash(28, end == text.Length ? 0 : BoundaryKind(text[end]));
        features.Hash(29, text[end - 1] == '.' ? 1 : 0);
        return features.Count;
    }

    /// <summary>Encode short forms shared across positions together with position-specific endings.</summary>
    private static void AddWord(ref FeatureWriter features, PersonToken token, int role, int alphabet, int shape)
    {
        ReadOnlySpan<char> word = token.Lower;
        int scope = 100 + role * 32;
        features.Hash(scope, alphabet | (shape << 3));
        features.Hash(scope + 1, Math.Min(word.Length, 15));
        features.Hash(scope + 2, word[..Math.Min(word.Length, 14)]);
        int maxAffix = Math.Min(word.Length, 5);
        for (int length = 1; length <= maxAffix; length++)
        {
            features.Hash(scope + 3 + length, word[^length..]);
            features.Hash(310 + length, word[^length..]);
            if (length <= 3)
                features.Hash(scope + 9 + length, word[..length]);
        }
        // Bound window scoring on long tokens. Prefix and suffix features still cover their edges.
        int trigramLimit = Math.Min(word.Length - 2, 12);
        for (int index = 0; index < trigramLimit; index++)
        {
            ReadOnlySpan<char> trigram = word.Slice(index, 3);
            features.Hash(scope + 14, trigram);
            features.Hash(316, trigram);
        }
    }

    /// <summary>Read nearest outer tokens and the script mixture visible outside the candidate.</summary>
    private static int AddNeighbors(ref FeatureWriter features, IReadOnlyList<PersonToken> tokens, int first, int last)
    {
        int alphabet = 0;
        for (int distance = 1; distance <= 2; distance++)
        {
            alphabet |= AddNeighbor(ref features, tokens, first - distance, 400 + distance * 8);
            alphabet |= AddNeighbor(ref features, tokens, last + distance, 424 + distance * 8);
        }
        return alphabet;
    }

    /// <summary>Encode neighbor shape and narrow word cues at one fixed distance.</summary>
    private static int AddNeighbor(ref FeatureWriter features, IReadOnlyList<PersonToken> tokens, int index, int scope)
    {
        if (index < 0 || index >= tokens.Count)
        {
            features.Hash(scope, 0);
            return 0;
        }
        PersonToken token = tokens[index];
        int alphabet = ReadAlphabet(token.Lower);
        ReadOnlySpan<char> word = token.Lower;
        features.Hash(scope, 1 + alphabet | (ReadShape(token.Word) << 3));
        features.Hash(scope + 1, Math.Min(token.Length, 12));
        features.Hash(scope + 2, word[..Math.Min(word.Length, 16)]);
        features.Hash(scope + 3, word[^Math.Min(word.Length, 3)..]);
        return alphabet;
    }

    /// <summary>Distinguish Latin, Cyrillic, other letters, and mixed token forms.</summary>
    private static int ReadAlphabet(ReadOnlySpan<char> word)
    {
        int mask = 0;
        foreach (char letter in word)
        {
            if (letter is >= 'a' and <= 'z')
                mask |= 1;
            else if (letter is >= 'а' and <= 'я' or 'ё')
                mask |= 2;
            else if (char.IsLetter(letter))
                mask |= 4;
        }
        return mask;
    }

    /// <summary>Distinguish title case, lowercase, all caps, mixed case, and digit-bearing words.</summary>
    private static int ReadShape(ReadOnlySpan<char> word)
    {
        bool lower = false;
        int capitals = 0;
        foreach (char letter in word)
        {
            if (char.IsDigit(letter))
                return 4;
            lower |= char.IsLower(letter);
            capitals += char.IsUpper(letter) ? 1 : 0;
        }
        if (capitals == 0)
            return 0;
        if (!lower)
            return 2;
        return capitals == 1 && char.IsUpper(word[0]) ? 1 : 3;
    }

    /// <summary>Identify punctuation inside a window without allocating a substring.</summary>
    private static int ClassifyGap(ReadOnlySpan<char> gap)
    {
        if (gap.Contains('-') || gap.Contains('‑'))
            return 1;
        return gap.Contains('.') ? 2 : 0;
    }

    /// <summary>Preserve punctuation classes used to distinguish boundaries from adjacent prose.</summary>
    private static int BoundaryKind(char value)
    {
        if (char.IsWhiteSpace(value))
            return 1;
        if (value is '-' or '‑')
            return 2;
        if (value is '.' or ',' or ':' or ';' or '!' or '?')
            return 3;
        return 4;
    }

    public readonly record struct Feature(int Index, float Value);

    /// <summary>Append feature occurrences without allocating or sorting a sparse set.</summary>
    private ref struct FeatureWriter
    {
        private readonly Span<Feature> features;
        public int Count { get; private set; }

        public FeatureWriter(Span<Feature> features)
        {
            this.features = features;
            Count = 0;
        }

        public void Add(int index, float value) => features[Count++] = new(index, value);

        public void Hash(int scope, int value)
        {
            uint hash = unchecked(((2166136261u ^ (uint)scope) * 16777619u ^ (uint)value) * 16777619u);
            Bucket(hash);
        }

        public void Hash(int scope, ReadOnlySpan<char> text)
        {
            uint hash = unchecked((2166136261u ^ (uint)scope) * 16777619u);
            foreach (char value in text)
                hash = unchecked((hash ^ value) * 16777619u);
            Bucket(hash);
        }

        private void Bucket(uint hash)
        {
            hash ^= hash >> 16;
            Add(DenseFeatures + (int)(hash & (HashBuckets - 1)), 1);
        }
    }
}
