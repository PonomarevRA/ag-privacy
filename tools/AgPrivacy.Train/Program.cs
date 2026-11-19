using System.Buffers.Binary;
using System.Text.Json;
using AgPrivacy;

// Offline deterministic averaged perceptron. Training/holdout are synthetic JSONL with exact span labels.
if(args.Length is not (4 or 6)){Console.Error.WriteLine("usage: train TRAIN.jsonl HOLDOUT.jsonl OUTPUT.bin BUCKETS [INITIAL.bin EPOCHS]");return 2;}
int buckets=int.Parse(args[3],System.Globalization.CultureInfo.InvariantCulture);
if(buckets<256 || buckets>8192 || (buckets&(buckets-1))!=0)return 2;
var train=Read(args[0]);var test=Read(args[1]);
var weights=new short[buckets*3];var totals=new long[weights.Length];long steps=0;
int epochs = 24;
if (args.Length == 6)
{
    epochs = int.Parse(args[5], System.Globalization.CultureInfo.InvariantCulture);
    if (epochs is < 1 or > 24) return 2;
    Initialize(args[4], buckets, weights);
}
for(int epoch=0;epoch<epochs;epoch++)
{
    // Corpus order is fixed by the seed-pinned generator; no runtime random/model download dependency.
    foreach(var example in train)
    {
        var tokens=MicroPersonModel.Tokenize(example.Text);int previous=0;
        for(int i=0;i<tokens.Count;i++)
        {
            int gold=Gold(tokens[i],example.Spans);
            int[] features=MicroPersonModel.Features(tokens,i,previous,buckets);
            int guess=MicroPersonModel.Predict(weights,features);
            if(guess!=gold)foreach(int f in features){weights[f*3+gold]=(short)Math.Clamp(weights[f*3+gold]+1,-2047,2047);weights[f*3+guess]=(short)Math.Clamp(weights[f*3+guess]-1,-2047,2047);}
            previous=guess;steps++;
            for(int j=0;j<weights.Length;j++)totals[j]+=weights[j];
        }
    }
}
for(int i=0;i<weights.Length;i++)weights[i]=(short)Math.Clamp((int)Math.Round((double)totals[i]/steps*64),short.MinValue,short.MaxValue);
byte[] bytes=MicroPersonModel.Encode(buckets,weights);Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(args[2]))!);File.WriteAllBytes(args[2],bytes);
var model=MicroPersonModel.Load(bytes);int tp=0,fp=0,fn=0;
foreach(var example in test)
{
    var expected=example.Spans.ToHashSet();var actual=model.Find(example.Text).Select(s=>(s.Start,s.Length)).ToHashSet();
    foreach(var span in actual)if(expected.Contains(span))tp++;else fp++;
    foreach(var span in expected)if(!actual.Contains(span))fn++;
}
// Metrics only: never print text, original examples or predicted span content.
Console.WriteLine($"{{\"buckets\":{buckets},\"modelBytes\":{bytes.Length},\"trainDocuments\":{train.Count},\"holdoutDocuments\":{test.Count},\"truePositive\":{tp},\"falsePositive\":{fp},\"falseNegative\":{fn},\"precision\":{Ratio(tp,tp+fp)},\"recall\":{Ratio(tp,tp+fn)},\"version\":\"{model.Version}\",\"qualification\":\"synthetic-only-not-production-recall\"}}");
return 0;

/// <summary>Seed the trainer with the existing model at the unquantized perceptron scale.</summary>
static void Initialize(string path, int buckets, Span<short> weights)
{
    if (new FileInfo(path).Length > MicroPersonModel.MaximumFileBytes)
        throw new ArgumentException("model-limit");
    byte[] bytes = File.ReadAllBytes(path);
    if (MicroPersonModel.Load(bytes).Buckets != buckets) throw new ArgumentException("model-bucket-mismatch");

    for (int index = 0; index < weights.Length; index++)
    {
        int quantized = BinaryPrimitives.ReadInt16LittleEndian(bytes.AsSpan(16 + index * sizeof(short)));
        weights[index] = (short)Math.Round(quantized / 64.0);
    }
}

/// <summary>Bounded local corpus parser for source-controlled synthetic training data only.</summary>
static List<Example> Read(string path)
{
    if(new FileInfo(path).Length>4*1024*1024)throw new ArgumentException("corpus-limit");
    var result=new List<Example>();
    foreach(string line in File.ReadLines(path))
    {
        if(line.Length>16384 || result.Count>=10000)throw new ArgumentException("corpus-limit");
        using var doc=JsonDocument.Parse(line);string text=doc.RootElement.GetProperty("text").GetString()!;
        var spans=new List<(int,int)>();foreach(var e in doc.RootElement.GetProperty("entities").EnumerateArray())spans.Add((e[0].GetInt32(),e[1].GetInt32()));
        result.Add(new(text,spans));
    }
    return result;
}
/// <summary>Convert exact span annotations into BIO labels for the shared tokenizer.</summary>
static int Gold(PersonToken token,List<(int Start,int Length)> spans)
{
    foreach(var span in spans)if(token.Start>=span.Start && token.Start+token.Length<=span.Start+span.Length)return token.Start==span.Start?1:2;
    return 0;
}
static string Ratio(int numerator,int denominator)=>((double)numerator/Math.Max(1,denominator)).ToString("0.0000",System.Globalization.CultureInfo.InvariantCulture);
internal sealed record Example(string Text,List<(int Start,int Length)> Spans);
