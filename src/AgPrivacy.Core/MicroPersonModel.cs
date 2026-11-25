using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
namespace AgPrivacy;

/// <summary>Fixed hashed-feature three-label linear sequence tagger. No vocabulary/raw text is retained between calls.</summary>
public sealed class MicroPersonModel : IPersonDetector
{
    private static ReadOnlySpan<byte> Magic => "APNER001"u8;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private const int MaximumTokenLength = 256;
    private const int FeatureCount = 12;
    private readonly short[] weights;
    public int Buckets { get; }
    public int WeightBytes => weights.Length * sizeof(short);
    public string Version { get; }
    public const int MaxTokens = 8192;
    public const int MaximumFileBytes = 16 + 8192 * 3 * 2;
    private MicroPersonModel(int buckets, short[] weights, string version) { Buckets=buckets;this.weights=weights;Version=version; }

    /// <summary>Validate the complete fixed-format local model before allocating weights. No executable model graph or downloads.</summary>
    public static MicroPersonModel Load(ReadOnlySpan<byte> bytes)
    {
        if(bytes.Length<16 || bytes.Length>MaximumFileBytes || !bytes[..8].SequenceEqual(Magic))throw new ArgumentException("invalid-model");
        int buckets=BinaryPrimitives.ReadInt32LittleEndian(bytes[8..]);
        if(buckets<256 || buckets>8192 || (buckets&(buckets-1))!=0 || BinaryPrimitives.ReadInt32LittleEndian(bytes[12..])!=1 || bytes.Length!=16+buckets*6)throw new ArgumentException("invalid-model");
        var weights=new short[buckets*3];
        for(int i=0;i<weights.Length;i++)weights[i]=BinaryPrimitives.ReadInt16LittleEndian(bytes[(16+i*2)..]);
        return new(buckets,weights,Convert.ToHexStringLower(SHA256.HashData(bytes)));
    }

    /// <summary>Serialize quantized weights from the offline trainer with the exact inference feature version.</summary>
    public static byte[] Encode(int buckets, ReadOnlySpan<short> weights)
    {
        if(buckets<256 || buckets>8192 || (buckets&(buckets-1))!=0 || weights.Length!=buckets*3)throw new ArgumentException("invalid-model");
        var bytes=new byte[16+weights.Length*2];Magic.CopyTo(bytes);
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(8),buckets);BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(12),1);
        for(int i=0;i<weights.Length;i++)BinaryPrimitives.WriteInt16LittleEndian(bytes.AsSpan(16+i*2),weights[i]);
        return bytes;
    }

    /// <summary>Greedy BIO decode. Unknown names may be missed; these intervals never authorize strict-mode raw output.</summary>
    public IReadOnlyList<EntitySpan> Find(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var result = new List<EntitySpan>();
        Find(text.AsSpan(), result);
        return result;
    }

    /// <summary>Append detected intervals relative to the slice into caller-owned storage.</summary>
    internal void Find(ReadOnlySpan<char> text, List<EntitySpan> result)
    {
        var reader = new TokenReader(text);
        int capacity = Math.Min(MaxTokens, (text.Length + 1) / 2);
        const int StackTokenCapacity = 128;
        TokenRange[]? rented = null;
        Span<TokenRange> tokens = capacity <= StackTokenCapacity
            ? stackalloc TokenRange[capacity]
            : (rented = ArrayPool<TokenRange>.Shared.Rent(capacity));
        try
        {
            int count = 0;
            while (reader.TryRead(out TokenRange token))
                tokens[count++] = token;
            if (count > 0)
                FindTokens(text, tokens[..count], result);
        }
        finally
        {
            // Rented storage contains only offsets and lengths.
            if (rented is not null)
                ArrayPool<TokenRange>.Shared.Return(rented);
        }
    }

    /// <summary>Decode validated UTF-16 token ranges with the same BIO scores and tie order as the public feature API.</summary>
    private void FindTokens(ReadOnlySpan<char> text, ReadOnlySpan<TokenRange> tokens, List<EntitySpan> result)
    {
        Span<int> features = stackalloc int[FeatureCount];
        Span<char> scratch = stackalloc char[3 * MaximumTokenLength];
        Span<char> beforeBuffer = scratch[..MaximumTokenLength];
        Span<char> currentBuffer = scratch.Slice(MaximumTokenLength, MaximumTokenLength);
        Span<char> afterBuffer = scratch[(2 * MaximumTokenLength)..];
        scoped FeatureToken before = new("<start>", "start");
        scoped FeatureToken current = PrepareToken(text, tokens[0], currentBuffer);
        int previous = 0, start = -1, end = 0;
        for (int i = 0; i < tokens.Length; i++)
        {
            bool hasAfter = i + 1 < tokens.Length;
            var after = hasAfter
                ? PrepareToken(text, tokens[i + 1], afterBuffer)
                : new FeatureToken("<end>", "end");
            FillFeatures(before, current, after, "012".AsSpan(previous, 1), Buckets, features);
            int label = Predict(weights, features);
            if(label==1 || (label==2 && start<0))
            {
                if(start>=0)result.Add(new(start,end-start,"PERSON"));
                start=tokens[i].Start;
            }
            if(label==0 && start>=0){result.Add(new(start,end-start,"PERSON"));start=-1;}
            if(label!=0)end=tokens[i].Start+tokens[i].Length;
            previous=label;
            // Keep both neighboring forms alive and reuse the oldest buffer for the next token.
            before = current;
            current = after;
            Span<char> reusable = beforeBuffer;
            beforeBuffer = currentBuffer;
            currentBuffer = afterBuffer;
            afterBuffer = reusable;
        }
        if(start>=0)result.Add(new(start,end-start,"PERSON"));
    }

    /// <summary>UTF-16 positions shared with regex and training. Bounded word tokens include path/query segments.</summary>
    public static IReadOnlyList<PersonToken> Tokenize(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var reader = new TokenReader(text.AsSpan());
        var tokens = new List<PersonToken>();
        while (reader.TryRead(out TokenRange token))
        {
            string word = text.Substring(token.Start, token.Length);
            tokens.Add(new(token.Start, token.Length, word, word.ToLowerInvariant()));
        }
        return tokens;
    }

    /// <summary>Stable FNV1a feature hashing; fixed memory independent of input vocabulary. Collisions are intentional.</summary>
    public static int[] Features(IReadOnlyList<PersonToken> tokens,int index,int previous,int buckets)
    {
        PersonToken token = tokens[index];
        var before = index > 0
            ? new FeatureToken(tokens[index - 1].Lower, Shape(tokens[index - 1].Word))
            : new FeatureToken("<start>", "start");
        var after = index + 1 < tokens.Count
            ? new FeatureToken(tokens[index + 1].Lower, Shape(tokens[index + 1].Word))
            : new FeatureToken("<end>", "end");
        var current = new FeatureToken(token.Lower.AsSpan(0, token.Lower.Length), Shape(token.Word));
        var features = new int[FeatureCount];
        FillFeatures(before, current, after, previous.ToString(), buckets, features);
        return features;
    }

    /// <summary>Fill the twelve APNER001 feature slots by hashing the original keys in their existing order.</summary>
    private static void FillFeatures(FeatureToken before, FeatureToken current, FeatureToken after,
        ReadOnlySpan<char> label, int buckets, Span<int> features)
    {
        ReadOnlySpan<char> word = current.Lower;
        features[0] = Hash(buckets, "bias");
        features[1] = Hash(buckets, "w=", word);
        features[2] = Hash(buckets, "shape=", current.Shape);
        features[3] = Hash(buckets, "prev=", before.Lower);
        features[4] = Hash(buckets, "next=", after.Lower);
        features[5] = Hash(buckets, "label=", label);
        features[6] = Hash(buckets, "prefix=", word[..Math.Min(2, word.Length)]);
        features[7] = Hash(buckets, "suffix=", word[Math.Max(0, word.Length - 3)..]);
        features[8] = Hash(buckets, "before-shape=", before.Shape);
        features[9] = Hash(buckets, "after-shape=", after.Shape);
        features[10] = Hash(buckets, "shape-prev=", current.Shape, ":", before.Lower);
        features[11] = Hash(buckets, "shape-label=", current.Shape, ":", label);
    }
    /// <summary>Scores the three fixed BIO labels; stable tie-break favours O and does not allocate a label dictionary.</summary>
    public static int Predict(ReadOnlySpan<short> weights,ReadOnlySpan<int> features)
    {
        Span<int> scores=stackalloc int[3];
        foreach(int feature in features)for(int label=0;label<3;label++)scores[label]+=weights[feature*3+label];
        int best=0;for(int label=1;label<3;label++)if(scores[label]>scores[best])best=label;
        return best;
    }
    /// <summary>Hash the UTF-16 code units as if the pieces were concatenated into one feature key.</summary>
    private static int Hash(int buckets, ReadOnlySpan<char> prefix, ReadOnlySpan<char> value = default,
        ReadOnlySpan<char> separator = default, ReadOnlySpan<char> tail = default)
    {
        uint hash = AppendHash(2166136261, prefix);
        hash = AppendHash(hash, value);
        hash = AppendHash(hash, separator);
        hash = AppendHash(hash, tail);
        return (int)(hash & (uint)(buckets - 1));
    }

    /// <summary>Continue the FNV-1a hash across the next part of the key.</summary>
    private static uint AppendHash(uint hash, ReadOnlySpan<char> value)
    {
        foreach (char c in value)
            hash = unchecked((hash ^ c) * 16777619);
        return hash;
    }

    /// <summary>Place the invariant lowercase word in scratch while classifying the original casing.</summary>
    private static FeatureToken PrepareToken(scoped ReadOnlySpan<char> text, TokenRange range, Span<char> scratch)
    {
        ReadOnlySpan<char> word = text.Slice(range.Start, range.Length);
        int length = word.ToLowerInvariant(scratch);
        return new FeatureToken(scratch[..length], Shape(word));
    }

    /// <summary>Classify the casing and keep non-letter tokens in the existing mixed class.</summary>
    private static string Shape(ReadOnlySpan<char> word)
    {
        bool letters=true,allUpper=true,allLower=true;
        foreach(char c in word){letters&=char.IsLetter(c);allUpper&=char.IsUpper(c);allLower&=char.IsLower(c);}
        if(!letters)return "mixed";if(allUpper)return "upper";if(allLower)return "lower";
        return char.IsUpper(word[0])?"title":"mixed";
    }

    private readonly record struct TokenRange(int Start, int Length);

    private readonly ref struct FeatureToken(ReadOnlySpan<char> lower, string shape)
    {
        public readonly ReadOnlySpan<char> Lower = lower;
        public readonly string Shape = shape;
    }

    /// <summary>Read UTF-16 letter and digit ranges under the same limits for inference and public tokenization.</summary>
    private ref struct TokenReader
    {
        private readonly ReadOnlySpan<char> text;
        private int position;
        private int count;

        public TokenReader(ReadOnlySpan<char> text)
        {
            if (StrictUtf8.GetByteCount(text) > PrivacyLimits.InputBytes)
                throw new ArgumentException("input-limit");
            this.text = text;
        }

        /// <summary>Return the next non-empty word range or false at the end of the input.</summary>
        public bool TryRead(out TokenRange token)
        {
            while (position < text.Length && !char.IsLetterOrDigit(text[position]))
                position++;
            if (position == text.Length)
            {
                token = default;
                return false;
            }

            int start = position++;
            while (position < text.Length && char.IsLetterOrDigit(text[position]))
                position++;
            int length = position - start;
            if (count >= MaxTokens || length > MaximumTokenLength)
                throw new InvalidOperationException("token-limit");
            count++;
            token = new TokenRange(start, length);
            return true;
        }
    }
}
public sealed record PersonToken(int Start,int Length,string Word,string Lower);
