using System.Buffers.Binary;
using System.Numerics;

namespace AgPrivacy;

/// <summary>Experimental name interval generator and sparse classifier for decoded message slices.</summary>
public sealed class SpanPersonDetector
    : IPersonDetector
{
    public const int FeatureCount = 1 << 17;
    public const int MaximumFileBytes = 12 + FeatureCount * sizeof(float) + MicroPersonModel.MaximumFileBytes;
    // Each window covers at most four 256-character tokens, with two n-grams per character.
    private const int MaximumWindowFeatures = 2200;
    private static ReadOnlySpan<byte> Magic => "AGSPAN01"u8;
    private readonly float[] weights;
    private readonly float threshold;
    private readonly MicroPersonModel parent;

    private SpanPersonDetector(float[] weights, float threshold, MicroPersonModel parent)
    {
        this.weights = weights;
        this.threshold = threshold;
        this.parent = parent;
    }

    public string Version => "AGSPAN01";

    /// <summary>Read a bounded local model while keeping the existing APNER format available.</summary>
    public static IPersonDetector LoadModel(ReadOnlySpan<byte> bytes)
    {
        if (!bytes.StartsWith(Magic))
            return MicroPersonModel.Load(bytes);
        int prefix = 12 + FeatureCount * sizeof(float);
        if (bytes.Length <= prefix || bytes.Length > MaximumFileBytes)
            throw new ArgumentException("span-model-size");
        float cutoff = BinaryPrimitives.ReadSingleLittleEndian(bytes[8..]);
        if (!float.IsFinite(cutoff))
            throw new ArgumentException("span-model-threshold");
        var weights = new float[FeatureCount];
        for (int index = 0; index < weights.Length; index++)
        {
            weights[index] = BinaryPrimitives.ReadSingleLittleEndian(bytes[(12 + sizeof(float) * index)..]);
            if (!float.IsFinite(weights[index]))
                throw new ArgumentException("span-model-coefficient");
        }
        return new SpanPersonDetector(weights, cutoff, MicroPersonModel.Load(bytes[prefix..]));
    }

    /// <summary>Encode the trained weights with the same parent model used during fitting.</summary>
    public static byte[] Encode(float[] weights, float threshold, byte[] parent)
    {
        if (weights.Length != FeatureCount || !float.IsFinite(threshold))
            throw new ArgumentException("span-model-dimensions");
        int prefix = 12 + FeatureCount * sizeof(float);
        var result = new byte[prefix + parent.Length];
        Magic.CopyTo(result);
        BinaryPrimitives.WriteSingleLittleEndian(result.AsSpan(8), threshold);
        for (int index = 0; index < weights.Length; index++)
            BinaryPrimitives.WriteSingleLittleEndian(result.AsSpan(12 + sizeof(float) * index), weights[index]);
        parent.CopyTo(result, prefix);
        return result;
    }

    /// <summary>Keep scored intervals in priority order while resolving overlaps deterministically.</summary>
    public IReadOnlyList<EntitySpan> Find(string text) => Find(text, null);

    /// <summary>Score candidate intervals using the optional validation model.</summary>
    internal IReadOnlyList<EntitySpan> Find(string text, PilotSpanSelection? selection)
    {
        int wholeBalance = selection is null ? 0 : PilotSpanSelection.AlphabetBalance(text);
        var accepted = new List<((int Start, int End) Span, float Value)>();
        var tokens = MicroPersonModel.Tokenize(text);
        var previous = parent.Find(text);
        var scripts = ReadAlphabets(tokens);
        Span<ulong> blocks = stackalloc ulong[FeatureCount / 64];
        Span<ulong> occupiedBlocks = stackalloc ulong[FeatureCount / (64 * 64)];
        Span<int> wordHashes = stackalloc int[MaximumWindowFeatures];
        var features = new FeatureSet(blocks, occupiedBlocks);
        int currentStart = -1;
        int cachedThrough = -1;
        int written = 0;
        int priorStart = 0;
        foreach (var (first, last, end) in Ranges(text, tokens))
        {
            if (first != currentStart)
            {
                written = 0;
                currentStart = first;
                cachedThrough = first - 1;
                priorStart = FirstPossibleOverlap(previous, priorStart, tokens[first].Start);
            }
            // Extending the endpoint preserves the hashed words and gaps already in this prefix.
            while (cachedThrough < last)
            {
                int next = ++cachedThrough;
                written += WriteWordAndGap(wordHashes[written..], text, tokens, scripts, first, next);
            }
            foreach (int feature in wordHashes[..written])
                features.Add(feature);
            CollectContext(ref features, text, tokens, scripts, previous, priorStart, first, last, end);
            float value = features.ScoreAndReset(weights);
            bool keep = selection is null ? value >= threshold :
                selection.Accept(text, tokens, first, last, end, wholeBalance, value, out value);
            if (keep)
                accepted.Add(((tokens[first].Start, end), value));
        }
        accepted.Sort((left, right) =>
        {
            int byScore = right.Value.CompareTo(left.Value);
            return byScore == 0 ? left.Span.Start.CompareTo(right.Span.Start) : byScore;
        });
        var result = new List<EntitySpan>();
        foreach (var (window, _) in accepted)
        {
            if (!Overlaps(result, window.Start, window.End))
                result.Add(new EntitySpan(window.Start, window.End - window.Start, "PERSON"));
        }
        result.Sort((left, right) => left.Start.CompareTo(right.Start));
        return result;
    }

    /// <summary>Check whether a higher-scoring interval already occupies any of this window.</summary>
    private static bool Overlaps(List<EntitySpan> spans, int start, int end)
    {
        foreach (EntitySpan span in spans)
        {
            if (span.Start < end && span.Start + span.Length > start)
                return true;
        }
        return false;
    }

    /// <summary>Advance through the ordered, non-overlapping BIO spans as window starts advance.</summary>
    private static int FirstPossibleOverlap(IReadOnlyList<EntitySpan> prior, int index, int start)
    {
        while (index < prior.Count && prior[index].Start + prior[index].Length <= start)
            index++;
        return index;
    }

    /// <summary>Enumerate contiguous two-to-four-token windows, including hyphens and dotted initials.</summary>
    public static IEnumerable<Candidate> Generate(string text, MicroPersonModel parent)
    {
        IReadOnlyList<PersonToken> tokens = MicroPersonModel.Tokenize(text);
        IReadOnlyList<EntitySpan> prior = parent.Find(text);
        var scripts = ReadAlphabets(tokens);
        foreach (var (start, last, end) in Ranges(text, tokens))
            yield return new(tokens[start].Start, end, Features(text, tokens, scripts, prior, start, last, end));
    }

    /// <summary>Classify a token once per logical message slice.</summary>
    private static int[] ReadAlphabets(IReadOnlyList<PersonToken> tokens)
    {
        var scripts = new int[tokens.Count];
        for (int i = 0; i < scripts.Length; i++)
            scripts[i] = Alphabet(tokens[i].Word);
        return scripts;
    }

    /// <summary>Produce the same UTF-16 candidate ranges in training and runtime.</summary>
    private static IEnumerable<(int StartIndex, int LastIndex, int End)> Ranges(string text, IReadOnlyList<PersonToken> tokens)
    {
        int available = tokens.Count;
        for (int start = 0; start < available; start++)
        {
            for (int last = start + 1; last < available && last <= start + 3; last++)
            {
                if (!Joinable(text, tokens[last - 1], tokens[last]))
                    break;
                int end = tokens[last].Start + tokens[last].Length;
                yield return (start, last, end);
                if (tokens[last].Length == 1 && end < text.Length && text[end] == '.')
                    yield return (start, last, end + 1);
            }
        }
    }

    /// <summary>Return the dot product for one candidate using the same hashes in both runtimes.</summary>
    public static float Score(float[] weights, ReadOnlySpan<int> features)
    {
        float sum = 0;
        foreach (int bucket in features)
            sum += weights[bucket];
        return sum;
    }

    /// <summary>Keep whitespace, surname hyphens and dotted initials inside a candidate.</summary>
    private static bool Joinable(string text, PersonToken left, PersonToken right)
    {
        int start = left.Start + left.Length;
        for (int i = start; i < right.Start; i++)
        {
            char ch = text[i];
            if (ch is ' ' or '\t' or '-' or '‑')
                continue;
            if (ch == '.' && i == start && left.Length == 1)
                continue;
            return false;
        }
        return right.Start > start;
    }

    /// <summary>Build role-position forms, two-sided context, and agreement with the original detector.</summary>
    private static int[] Features(string text, IReadOnlyList<PersonToken> words, int[] scripts,
        IReadOnlyList<EntitySpan> prior, int start, int last, int end)
    {
        Span<ulong> blocks = stackalloc ulong[FeatureCount / 64];
        Span<ulong> occupiedBlocks = stackalloc ulong[FeatureCount / (64 * 64)];
        Span<int> wordHashes = stackalloc int[MaximumWindowFeatures];
        var values = new FeatureSet(blocks, occupiedBlocks);
        for (int index = start; index <= last; index++)
        {
            int written = WriteWordAndGap(wordHashes, text, words, scripts, start, index);
            foreach (int feature in wordHashes[..written])
                values.Add(feature);
        }
        CollectContext(ref values, text, words, scripts, prior, 0, start, last, end);
        return values.ToSortedArray();
    }

    /// <summary>Collect the endpoint-specific features on top of the cached words and gaps.</summary>
    private static void CollectContext(ref FeatureSet values, string text, IReadOnlyList<PersonToken> words,
        int[] scripts, IReadOnlyList<EntitySpan> prior, int priorStart, int start, int last, int end)
    {
        Add(ref values, 1, "");
        Add(ref values, 2 + last - start, "");
        int begin = words[start].Start;
        bool exact = false, touches = false;
        for (int index = priorStart; index < prior.Count; index++)
        {
            EntitySpan span = prior[index];
            if (span.Start >= end)
                break;
            exact |= span.Start == begin && span.Start + span.Length == end;
            touches |= span.Start < end && span.Start + span.Length > begin;
        }
        Add(ref values, exact ? 10 : touches ? 11 : 12, "");
        if (text[end - 1] == '.')
            Add(ref values, 13, "");
        AddNeighbor(ref values, words, scripts, start - 1, scripts[start], 500);
        AddNeighbor(ref values, words, scripts, start - 2, scripts[start], 510);
        AddNeighbor(ref values, words, scripts, last + 1, scripts[last], 520);
        AddNeighbor(ref values, words, scripts, last + 2, scripts[last], 530);
    }

    /// <summary>Hash the word and preceding gap once for all endpoints containing them.</summary>
    private static int WriteWordAndGap(Span<int> output, string text, IReadOnlyList<PersonToken> words, int[] scripts,
        int start, int index)
    {
        int position = index - start;
        PersonToken word = words[index];
        int written = WriteWord(output, word, position, scripts[index]);
        if (position == 0)
            return written;
        PersonToken previous = words[index - 1];
        int gapStart = previous.Start + previous.Length;
        ReadOnlySpan<char> gap = text.AsSpan(gapStart, word.Start - gapStart);
        if (gap.Contains('-') || gap.Contains('‑'))
            output[written++] = Hash(18 + position - 1, "");
        return written;
    }

    /// <summary>Write role-specific spelling, affix, character group and shape hashes.</summary>
    private static int WriteWord(Span<int> output, PersonToken token, int position, int script)
    {
        ReadOnlySpan<char> word = token.Lower.AsSpan();
        int feature = 40 + position * 100;
        int written = 0;
        output[written++] = Hash(feature, word);
        output[written++] = Hash(feature + 1 + Math.Min(17, word.Length), "");
        output[written++] = Hash(feature + 22 + script, "");
        output[written++] = Hash(feature + (char.IsUpper(token.Word[0]) ? 29 : 28), "");
        for (int length = 2; length <= Math.Min(word.Length, 5); length++)
        {
            output[written++] = Hash(feature + 35 + length, word[..length]);
            output[written++] = Hash(feature + 45 + length, word[^length..]);
        }
        for (int index = 0; index + 3 <= word.Length; index++)
            output[written++] = Hash(feature + 56, word.Slice(index, 3));
        for (int index = 0; index + 2 <= word.Length; index++)
            output[written++] = Hash(61, word.Slice(index, 2));
        foreach (char character in token.Word)
        {
            if (!char.IsDigit(character))
                continue;
            output[written++] = Hash(feature + 65, "");
            break;
        }
        return written;
    }

    /// <summary>Encode adjacent words and observed script transitions in the decoded text.</summary>
    private static void AddNeighbor(ref FeatureSet output, IReadOnlyList<PersonToken> words, int[] scripts,
        int position, int candidateScript, int feature)
    {
        if (position < 0 || position >= words.Count)
        {
            Add(ref output, feature, "");
            return;
        }
        Add(ref output, feature + 1, words[position].Lower);
        Add(ref output, scripts[position] == candidateScript ? feature + 2 : feature + 3, "");
        Add(ref output, char.IsUpper(words[position].Word[0]) ? feature + 4 : feature + 5, "");
    }

    /// <summary>Recognize single-alphabet words and keep mixed forms as a separate feature.</summary>
    private static int Alphabet(string word)
    {
        int flags = 0;
        foreach (char value in word)
        {
            if (value is >= 'A' and <= 'Z' or >= 'a' and <= 'z')
                flags |= 1;
            else if (value is >= 'А' and <= 'я' or 'Ё' or 'ё')
                flags |= 2;
        }
        return flags;
    }

    /// <summary>Add a context feature using the same feature hashing as the cached words.</summary>
    private static void Add(ref FeatureSet values, int feature, ReadOnlySpan<char> text) =>
        values.Add(Hash(feature, text));

    /// <summary>Encode numeric feature identities and their text parts with stable hashing.</summary>
    private static int Hash(int feature, ReadOnlySpan<char> text)
    {
        uint hash = unchecked((2166136261u ^ (uint)feature) * 16777619u);
        foreach (char part in text)
            hash = unchecked((hash ^ part) * 16777619u);
        hash ^= hash >> 16;
        return (int)(hash & (FeatureCount - 1));
    }

    /// <summary>Store sparse feature identities in bitmaps indexed by nonempty groups and blocks.</summary>
    private ref struct FeatureSet
    {
        private readonly Span<ulong> blocks;
        private readonly Span<ulong> occupiedBlocks;
        private ulong occupiedGroups;

        public FeatureSet(Span<ulong> blocks, Span<ulong> occupiedBlocks)
        {
            this.blocks = blocks;
            this.occupiedBlocks = occupiedBlocks;
            occupiedGroups = 0;
            blocks.Clear();
            occupiedBlocks.Clear();
        }

        public void Add(int value)
        {
            int block = value >> 6;
            int group = block >> 6;
            blocks[block] |= 1UL << (value & 63);
            occupiedBlocks[group] |= 1UL << (block & 63);
            occupiedGroups |= 1UL << group;
        }

        /// <summary>Add weights in the original ascending order and clear only occupied storage.</summary>
        public float ScoreAndReset(ReadOnlySpan<float> weights)
        {
            float result = 0;
            while (occupiedGroups != 0)
            {
                int group = RemoveFirst(ref occupiedGroups);
                ulong remainingBlocks = occupiedBlocks[group];
                occupiedBlocks[group] = 0;
                while (remainingBlocks != 0)
                {
                    int block = (group << 6) + RemoveFirst(ref remainingBlocks);
                    int start = block << 6;
                    ulong remainingFeatures = blocks[block];
                    blocks[block] = 0;
                    while (remainingFeatures != 0)
                        result += weights[start + RemoveFirst(ref remainingFeatures)];
                }
            }
            return result;
        }

        /// <summary>Materialize the same ordered feature identities for offline training.</summary>
        public int[] ToSortedArray()
        {
            Span<int> result = stackalloc int[MaximumWindowFeatures];
            int count = 0;
            ulong remainingGroups = occupiedGroups;
            while (remainingGroups != 0)
            {
                int group = RemoveFirst(ref remainingGroups);
                ulong remainingBlocks = occupiedBlocks[group];
                while (remainingBlocks != 0)
                {
                    int block = (group << 6) + RemoveFirst(ref remainingBlocks);
                    int start = block << 6;
                    ulong remainingFeatures = blocks[block];
                    while (remainingFeatures != 0)
                        result[count++] = start + RemoveFirst(ref remainingFeatures);
                }
            }
            return result[..count].ToArray();
        }

        /// <summary>Remove the least significant active bit and return its zero-based index.</summary>
        private static int RemoveFirst(ref ulong bits)
        {
            int index = BitOperations.TrailingZeroCount(bits);
            bits &= bits - 1;
            return index;
        }
    }

    public readonly record struct Candidate(int Start, int End, int[] Features);
}
