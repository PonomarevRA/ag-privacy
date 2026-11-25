using System.Buffers.Binary;

namespace AgPrivacy;

/// <summary>Experimental name interval generator and sparse classifier for decoded message slices.</summary>
public sealed class SpanPersonDetector
    : IPersonDetector
{
    public const int FeatureCount = 1 << 17;
    public const int MaximumFileBytes = 12 + FeatureCount * sizeof(float) + MicroPersonModel.MaximumFileBytes;
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
    public IReadOnlyList<EntitySpan> Find(string text)
    {
        var accepted = new List<((int Start, int End) Span, float Value)>();
        var tokens = MicroPersonModel.Tokenize(text);
        var previous = parent.Find(text);
        var scripts = ReadAlphabets(tokens);
        // At most four 256-character words. Each produces at most two n-grams per character.
        Span<int> indices = stackalloc int[2200];
        Span<ulong> seen = stackalloc ulong[FeatureCount / 64];
        seen.Clear();
        var features = new FeatureSet(seen, indices);
        foreach (var (first, last, end) in Ranges(text, tokens))
        {
            Collect(ref features, text, tokens, scripts, previous, first, last, end);
            float value = Score(weights, features.Sorted());
            if (value >= threshold)
                accepted.Add(((tokens[first].Start, end), value));
            features.Reset();
        }
        accepted.Sort((left, right) =>
        {
            int byScore = right.Value.CompareTo(left.Value);
            return byScore == 0 ? left.Span.Start.CompareTo(right.Span.Start) : byScore;
        });
        var result = new List<EntitySpan>();
        foreach (var (window, _) in accepted)
        {
            if (!result.Exists(span => span.Start < window.End && span.Start + span.Length > window.Start))
                result.Add(new EntitySpan(window.Start, window.End - window.Start, "PERSON"));
        }
        result.Sort((left, right) => left.Start.CompareTo(right.Start));
        return result;
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
        Span<int> ids = stackalloc int[2200];
        Span<ulong> seen = stackalloc ulong[FeatureCount / 64];
        seen.Clear();
        var values = new FeatureSet(seen, ids);
        Collect(ref values, text, words, scripts, prior, start, last, end);
        return values.Sorted().ToArray();
    }

    /// <summary>Collect each active feature once with a reusable bitset.</summary>
    private static void Collect(ref FeatureSet values, string text, IReadOnlyList<PersonToken> words,
        int[] scripts, IReadOnlyList<EntitySpan> prior, int start, int last, int end)
    {
        Add(ref values, 1, "");
        Add(ref values, 2 + last - start, "");
        int begin = words[start].Start;
        bool exact = false, touches = false;
        foreach (EntitySpan span in prior)
        {
            exact |= span.Start == begin && span.Start + span.Length == end;
            touches |= span.Start < end && span.Start + span.Length > begin;
        }
        Add(ref values, exact ? 10 : touches ? 11 : 12, "");
        if (text[end - 1] == '.')
            Add(ref values, 13, "");
        for (int index = start; index <= last; index++)
        {
            int position = index - start;
            var word = words[index];
            AddWord(ref values, word, position, scripts[index]);
            if (index < last)
            {
                ReadOnlySpan<char> gap = text.AsSpan(word.Start + word.Length,
                    words[index + 1].Start - word.Start - word.Length);
                if (gap.Contains('-') || gap.Contains('‑'))
                    Add(ref values, 18 + position, "");
            }
        }
        AddNeighbor(ref values, words, scripts, start - 1, scripts[start], 500);
        AddNeighbor(ref values, words, scripts, start - 2, scripts[start], 510);
        AddNeighbor(ref values, words, scripts, last + 1, scripts[last], 520);
        AddNeighbor(ref values, words, scripts, last + 2, scripts[last], 530);
    }

    /// <summary>Score spelling beyond suffixes, including prefixes and inner character groups.</summary>
    private static void AddWord(ref FeatureSet output, PersonToken token, int position, int script)
    {
        ReadOnlySpan<char> word = token.Lower.AsSpan();
        int feature = 40 + position * 100;
        Add(ref output, feature, word);
        Add(ref output, feature + 1 + Math.Min(17, word.Length), "");
        Add(ref output, feature + 22 + script, "");
        Add(ref output, feature + (char.IsUpper(token.Word[0]) ? 29 : 28), "");
        for (int length = 2; length <= Math.Min(word.Length, 5); length++)
        {
            Add(ref output, feature + 35 + length, word[..length]);
            Add(ref output, feature + 45 + length, word[^length..]);
        }
        for (int index = 0; index + 3 <= word.Length; index++)
            Add(ref output, feature + 56, word.Slice(index, 3));
        for (int index = 0; index + 2 <= word.Length; index++)
            Add(ref output, 61, word.Slice(index, 2));
        if (token.Word.Any(char.IsDigit))
            Add(ref output, feature + 65, "");
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

    /// <summary>Encode numeric feature identities and their text parts with stable hashing.</summary>
    private static void Add(ref FeatureSet values, int feature, ReadOnlySpan<char> text)
    {
        uint hash = unchecked((2166136261u ^ (uint)feature) * 16777619u);
        foreach (char part in text)
            hash = unchecked((hash ^ part) * 16777619u);
        hash ^= hash >> 16;
        values.Add((int)(hash & (FeatureCount - 1)));
    }

    /// <summary>Keep sparse feature identities in caller-owned scratch memory.</summary>
    private ref struct FeatureSet
    {
        private readonly Span<ulong> seen;
        private readonly Span<int> indices;
        private int count;

        public FeatureSet(Span<ulong> seen, Span<int> indices)
        {
            this.seen = seen;
            this.indices = indices;
            count = 0;
        }

        public void Add(int value)
        {
            int slot = value >> 6;
            ulong bit = 1UL << (value & 63);
            if ((seen[slot] & bit) != 0)
                return;
            seen[slot] |= bit;
            indices[count++] = value;
        }

        public ReadOnlySpan<int> Sorted()
        {
            var used = indices[..count];
            used.Sort();
            return used;
        }

        public void Reset()
        {
            for (int i = 0; i < count; i++)
            {
                int value = indices[i];
                seen[value >> 6] &= ~(1UL << (value & 63));
            }
            count = 0;
        }
    }

    public readonly record struct Candidate(int Start, int End, int[] Features);
}
