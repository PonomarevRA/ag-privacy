using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
namespace AgPrivacy;

/// <summary>Fixed hashed-feature three-label linear sequence tagger. No vocabulary/raw text is retained between calls.</summary>
public sealed class MicroPersonModel : IPersonDetector
{
    private static ReadOnlySpan<byte> Magic => "APNER001"u8;
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
        var tokens=Tokenize(text);var result=new List<EntitySpan>();int previous=0,start=-1,end=0;
        for(int i=0;i<tokens.Count;i++)
        {
            int label=Predict(weights,Features(tokens,i,previous,Buckets));
            if(label==1 || (label==2 && start<0))
            {
                if(start>=0)result.Add(new(start,end-start,"PERSON"));
                start=tokens[i].Start;
            }
            if(label==0 && start>=0){result.Add(new(start,end-start,"PERSON"));start=-1;}
            if(label!=0)end=tokens[i].Start+tokens[i].Length;
            previous=label;
        }
        if(start>=0)result.Add(new(start,end-start,"PERSON"));
        return result;
    }

    /// <summary>UTF-16 positions shared with regex and training. Bounded word tokens include path/query segments.</summary>
    public static IReadOnlyList<PersonToken> Tokenize(string text)
    {
        if(new UTF8Encoding(false,true).GetByteCount(text)>PrivacyLimits.InputBytes)throw new ArgumentException("input-limit");
        var tokens=new List<PersonToken>();
        for(int i=0;i<text.Length;)
        {
            if(!char.IsLetterOrDigit(text[i])){i++;continue;}
            int start=i;while(i<text.Length && char.IsLetterOrDigit(text[i]))i++;
            if(tokens.Count>=MaxTokens || i-start>256)throw new InvalidOperationException("token-limit");
            string word=text[start..i];tokens.Add(new(start,i-start,word,word.ToLowerInvariant()));
        }
        return tokens;
    }

    /// <summary>Stable FNV1a feature hashing; fixed memory independent of input vocabulary. Collisions are intentional.</summary>
    public static int[] Features(IReadOnlyList<PersonToken> tokens,int index,int previous,int buckets)
    {
        var token=tokens[index];string word=token.Lower;
        string before=index>0 ? tokens[index-1].Lower : "<start>";
        string after=index+1<tokens.Count ? tokens[index+1].Lower : "<end>";
        string shape=Shape(token.Word);
        return [Hash("bias",buckets),Hash("w="+word,buckets),Hash("shape="+shape,buckets),
            Hash("prev="+before,buckets),Hash("next="+after,buckets),Hash("label="+previous,buckets),
            Hash("prefix="+word[..Math.Min(2,word.Length)],buckets),Hash("suffix="+word[Math.Max(0,word.Length-3)..],buckets),
            Hash("before-shape="+(index>0?Shape(tokens[index-1].Word):"start"),buckets),
            Hash("after-shape="+(index+1<tokens.Count?Shape(tokens[index+1].Word):"end"),buckets),
            Hash("shape-prev="+shape+":"+before,buckets),Hash("shape-label="+shape+":"+previous,buckets)];
    }
    /// <summary>Scores the three fixed BIO labels; stable tie-break favours O and does not allocate a label dictionary.</summary>
    public static int Predict(ReadOnlySpan<short> weights,ReadOnlySpan<int> features)
    {
        Span<int> scores=stackalloc int[3];
        foreach(int feature in features)for(int label=0;label<3;label++)scores[label]+=weights[feature*3+label];
        int best=0;for(int label=1;label<3;label++)if(scores[label]>scores[best])best=label;
        return best;
    }
    private static int Hash(string value,int buckets)
    {
        uint hash=2166136261;foreach(char c in value){hash^=c;hash=unchecked(hash*16777619);}
        return (int)(hash&(uint)(buckets-1));
    }
    private static string Shape(string word)
    {
        bool letters=true,allUpper=true,allLower=true;
        foreach(char c in word){letters&=char.IsLetter(c);allUpper&=char.IsUpper(c);allLower&=char.IsLower(c);}
        if(!letters)return "mixed";if(allUpper)return "upper";if(allLower)return "lower";
        return char.IsUpper(word[0])?"title":"mixed";
    }
}
public sealed record PersonToken(int Start,int Length,string Word,string Lower);
