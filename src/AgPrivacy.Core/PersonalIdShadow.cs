using System.Buffers.Binary;

namespace AgPrivacy;

/// <summary>Observations made only after the numeric classifier abstains.</summary>
public sealed record PersonalIdShadowCounts(long Reviewed, long Proposed);

/// <summary>Small local binary classifier using words and adjacent word pairs around a candidate.</summary>
public sealed class PersonalIdShadow
{
    internal const int Buckets = 1024;
    internal const int FeatureLimit = 128;
    internal const int ExplicitLabel = -1;
    internal static ReadOnlySpan<byte> Magic => "APPID002"u8;
    private static ReadOnlySpan<byte> LegacyMagic => "APPID001"u8;
    public const int ModelBytes = 12 + Buckets * sizeof(float);
    private static readonly string[] People =
        ["user", "customer", "client", "employee", "staff", "person", "human", "member", "subscriber", "holder",
         "пользовател", "клиент", "сотрудник", "физлиц", "владел", "человек", "личност", "работник", "подписчик", "посетител"];
    private static readonly string[] Infrastructure =
        ["request", "operation", "session", "task", "batch", "job", "cache", "device", "service", "system", "api",
         "config", "process", "audit", "routing", "transaction", "log", "запрос", "операци", "сесси", "задач", "пакет",
         "процесс", "модул", "служб", "сервис", "журнал", "транзакц", "конфигурац", "подразделен", "задани"];
    private static readonly string[] PersonalMarkers =
        ["personal", "individual", "identity", "payroll", "badge", "табель", "персональн", "личн", "физлиц"];
    private readonly bool legacy;
    private readonly float threshold;
    private readonly float[] weights;

    private PersonalIdShadow(float threshold, float[] weights, bool legacy)
    {
        this.threshold = threshold;
        this.weights = weights;
        this.legacy = legacy;
    }

    /// <summary>Load a bounded, versioned weight table and decision threshold.</summary>
    public static PersonalIdShadow Load(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != ModelBytes)
            throw new ArgumentException("invalid-personal-id-shadow");
        bool legacy = bytes[..8].SequenceEqual(LegacyMagic);
        if (!legacy && !bytes[..8].SequenceEqual(Magic))
            throw new ArgumentException("invalid-personal-id-shadow");
        float threshold = ReadWeight(bytes[8..]);
        var weights = new float[Buckets];
        for (int i = 0; i < weights.Length; i++)
            weights[i] = ReadWeight(bytes[(12 + i * sizeof(float))..]);
        return new(threshold, weights, legacy);
    }

    /// <summary>Reject nonfinite or out-of-range coefficients.</summary>
    private static float ReadWeight(ReadOnlySpan<byte> bytes)
    {
        float value = BinaryPrimitives.ReadSingleLittleEndian(bytes);
        if (!float.IsFinite(value) || Math.Abs(value) > 64)
            throw new ArgumentException("invalid-personal-id-shadow");
        return value;
    }

    /// <summary>Evaluate the same hashed features used to train the model, without retaining input.</summary>
    internal bool Predict(ReadOnlySpan<char> text, int start, int length)
    {
        Span<int> features = stackalloc int[FeatureLimit];
        int count = Extract(text, start, length, features, legacy);
        if (count == 0) return false;
        if (!legacy && features[count - 1] == ExplicitLabel) return true;
        float score = 0;
        foreach (int feature in features[..count]) score += weights[feature];
        return score >= threshold;
    }

    /// <summary>Collect capped features on each side, bounded by clause and neighbouring numeric candidates.</summary>
    internal static int Extract(ReadOnlySpan<char> text, int start, int length, Span<int> features, bool legacy = false)
    {
        const int window = 64;
        int end = start + length;
        var left = text[Math.Max(0, start - window)..start];
        var right = text[end..Math.Min(text.Length, end + window)];
        left = left[(left.LastIndexOfAny(";\r\n!?") + 1)..];
        int bound = right.IndexOfAny(";\r\n!?");
        if (bound >= 0) right = right[..bound];
        left = NumericContextFeatures.IsolateCandidate(left, before: true);
        right = NumericContextFeatures.IsolateCandidate(right, before: false);
        if (NumericContextFeatures.HasAlternative(left) || NumericContextFeatures.HasAlternative(right) ||
            Uncertain(left) || Uncertain(right)) return 0;
        if (!legacy && PersonalIdRoleFeatures.IsExplicitPersonalLabel(left))
        {
            features[0] = ExplicitLabel;
            return 1;
        }
        features[0] = 0;
        int count = 1;
        AddRoleFeatures(left, right, features, ref count);
        if (!legacy) PersonalIdRoleFeatures.Add(left, right, features, ref count);
        AddWords(left, features, ref count, legacy);
        AddWords(right, features, ref count, legacy);
        return count > 1 ? count : 0;
    }

    /// <summary>Generalize across variants of the same role and learn from explicit competing infrastructure cues.</summary>
    private static void AddRoleFeatures(ReadOnlySpan<char> left, ReadOnlySpan<char> right, Span<int> features, ref int count)
    {
        bool person = ContainsRole(left, People) || ContainsRole(right, People);
        bool technical = ContainsRole(left, Infrastructure) || ContainsRole(right, Infrastructure);
        bool personal = ContainsRole(left, PersonalMarkers) || ContainsRole(right, PersonalMarkers);
        if (person) features[count++] = 1;
        if (technical) features[count++] = 2;
        if (personal) features[count++] = 3;
        if (person && technical) features[count++] = 4;
        if (person && !technical) features[count++] = 5;
    }

    /// <summary>Find whole English words or known Russian stems in the local context.</summary>
    private static bool ContainsRole(ReadOnlySpan<char> text, string[] cues)
    {
        int offset = 0;
        while (TryWord(text, ref offset, out var word))
        {
            foreach (string cue in cues)
            {
                if (cue[0] < 'а' && word.Equals(cue, StringComparison.OrdinalIgnoreCase)) return true;
                if (cue[0] >= 'а' && word.StartsWith(cue, StringComparison.OrdinalIgnoreCase)) return true;
            }
        }
        return false;
    }

    /// <summary>Abstain on explicit denial or uncertainty before consulting the learned weights.</summary>
    private static bool Uncertain(ReadOnlySpan<char> text)
    {
        int i = 0;
        while (TryWord(text, ref i, out var word))
        {
            if (word.Equals("not", StringComparison.OrdinalIgnoreCase) ||
                word.Equals("no", StringComparison.OrdinalIgnoreCase) ||
                word.Equals("не", StringComparison.OrdinalIgnoreCase) ||
                word.Equals("unknown", StringComparison.OrdinalIgnoreCase) ||
                word.Equals("ambiguous", StringComparison.OrdinalIgnoreCase) ||
                word.Equals("неизвестно", StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    /// <summary>Encode whole words, prefixes and adjacent word pairs using a stable local hash.</summary>
    private static void AddWords(ReadOnlySpan<char> text, Span<int> features, ref int count, bool legacy)
    {
        int i = 0;
        uint previous = 0;
        while (TryWord(text, ref i, out var word) && count <= features.Length - 3)
        {
            uint wordHash = Hash(word);
            features[count++] = Bucket(wordHash, legacy);
            if (word.Length > 4) features[count++] = Bucket(Hash(word[..4]) ^ 0x69dbe621, legacy);
            if (previous != 0) features[count++] = Bucket(unchecked(previous * 16777619 ^ wordHash), legacy);
            previous = wordHash;
        }
    }

    /// <summary>Read the next alphabetic word, skipping the numeric value and punctuation.</summary>
    internal static bool TryWord(ReadOnlySpan<char> text, ref int offset, out ReadOnlySpan<char> word)
    {
        while (offset < text.Length && !char.IsLetter(text[offset])) offset++;
        int first = offset;
        while (offset < text.Length && char.IsLetter(text[offset])) offset++;
        word = text[first..offset];
        return !word.IsEmpty;
    }

    /// <summary>FNV-1a over invariant lowercase characters for portable model weights.</summary>
    private static uint Hash(ReadOnlySpan<char> word)
    {
        uint hash = 2166136261;
        foreach (char letter in word) hash = unchecked((hash ^ char.ToLowerInvariant(letter)) * 16777619);
        return hash;
    }

    /// <summary>Reserve initial buckets for the intercept and role features in the selected model format.</summary>
    private static int Bucket(uint hash, bool legacy)
    {
        int first = legacy ? 6 : PersonalIdRoleFeatures.FirstHashedBucket;
        return first + (int)(hash % (Buckets - first));
    }
}
