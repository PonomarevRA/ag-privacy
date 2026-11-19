using System.Globalization;
using System.Security.Cryptography;
using Microsoft.ML.OnnxRuntime;

namespace AgPrivacy;

/// <summary>Run an exported micro person model using ONNX Runtime and the core tokenizer.</summary>
public sealed class OnnxPersonDetector : IPersonDetector, IDisposable
{
    public const int MaximumFileBytes = 1024 * 1024;
    private const int FeatureCount = 12;
    private readonly InferenceSession session;
    private readonly object gate = new();
    private bool disposed;

    public int Buckets { get; }
    public string Version { get; }
    public string SourceModelVersion { get; }

    /// <summary>Validate the exported graph contract and configure a reusable single-threaded CPU session.</summary>
    private OnnxPersonDetector(byte[] bytes)
    {
        Version = Convert.ToHexStringLower(SHA256.HashData(bytes));
        using var options = new SessionOptions
        {
            IntraOpNumThreads = 1,
            InterOpNumThreads = 1,
            LogSeverityLevel = OrtLoggingLevel.ORT_LOGGING_LEVEL_FATAL
        };
        session = new InferenceSession(bytes, options);
        try
        {
            var metadata = session.ModelMetadata.CustomMetadataMap;
            if (!metadata.TryGetValue("agprivacy.format", out var format) || format != "person-perceptron-v1" ||
                !metadata.TryGetValue("agprivacy.buckets", out var count) ||
                !int.TryParse(count, NumberStyles.None, CultureInfo.InvariantCulture, out int buckets) ||
                buckets is < 256 or > 8192 || (buckets & (buckets - 1)) != 0 ||
                !metadata.TryGetValue("agprivacy.source_sha256", out var source) ||
                source.Length != 64 || source.Any(character => !char.IsAsciiHexDigit(character)))
                throw new ArgumentException("invalid-onnx-person-contract");
            ValidateTensors();
            Buckets = buckets;
            SourceModelVersion = source;
        }
        catch
        {
            session.Dispose();
            throw;
        }
    }

    /// <summary>Load an exported local model, with the graph and embedded weights bounded to one MiB.</summary>
    public static OnnxPersonDetector Load(ReadOnlySpan<byte> bytes)
    {
        if (bytes.IsEmpty || bytes.Length > MaximumFileBytes)
            throw new ArgumentException("invalid-onnx-model-size");
        return new(bytes.ToArray());
    }

    /// <summary>Return UTF-16 person intervals. Calls on one detector are serialized with its disposal.</summary>
    public IReadOnlyList<EntitySpan> Find(string text)
    {
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            var tokens = MicroPersonModel.Tokenize(text);
            if (tokens.Count == 0) return [];
            long[] features = BuildFeatures(tokens);
            using var input = OrtValue.CreateTensorValueFromMemory(features, [tokens.Count, 3, FeatureCount]);
            using var run = new RunOptions();
            try
            {
                using var outputs = session.Run(run, new Dictionary<string, OrtValue> { ["features"] = input }, ["labels"]);
                var labels = outputs[0].GetTensorDataAsSpan<long>();
                return Decode(tokens, labels);
            }
            catch (OnnxRuntimeException)
            {
                // Normalize backend failures to the exception contract handled by the masking pipeline.
                throw new InvalidOperationException("onnx-person-inference-failed");
            }
        }
    }

    /// <summary>Require the dynamic feature tensor and one label per token before accepting the graph.</summary>
    private void ValidateTensors()
    {
        if (session.InputMetadata.Count != 1 || session.OutputMetadata.Count != 1 ||
            !session.InputMetadata.TryGetValue("features", out var input) ||
            !session.OutputMetadata.TryGetValue("labels", out var output) ||
            !input.IsTensor || input.ElementType != typeof(long) ||
            input.Dimensions.Length != 3 || input.Dimensions[0] >= 0 ||
            input.Dimensions[1] != 3 || input.Dimensions[2] != FeatureCount ||
            !output.IsTensor || output.ElementType != typeof(long) ||
            output.Dimensions.Length != 1 || output.Dimensions[0] >= 0)
            throw new ArgumentException("invalid-onnx-person-tensors");
    }

    /// <summary>Reuse the exact core hashing for each possible preceding BIO label.</summary>
    private long[] BuildFeatures(IReadOnlyList<PersonToken> tokens)
    {
        var data = new long[tokens.Count * 3 * FeatureCount];
        int offset = 0;
        for (int index = 0; index < tokens.Count; index++)
        {
            for (int previous = 0; previous < 3; previous++)
            {
                int[] features = MicroPersonModel.Features(tokens, index, previous, Buckets);
                for (int feature = 0; feature < FeatureCount; feature++)
                    data[offset++] = features[feature];
            }
        }
        return data;
    }

    /// <summary>Reconstruct intervals with the core model's BIO semantics, including an orphan continuation.</summary>
    private static List<EntitySpan> Decode(IReadOnlyList<PersonToken> tokens, ReadOnlySpan<long> labels)
    {
        if (labels.Length != tokens.Count) throw new InvalidOperationException("invalid-onnx-person-output");
        var spans = new List<EntitySpan>();
        int start = -1;
        int end = 0;
        for (int index = 0; index < tokens.Count; index++)
        {
            long label = labels[index];
            if (label is < 0 or > 2) throw new InvalidOperationException("invalid-onnx-person-label");
            if (label == 1 || (label == 2 && start < 0))
            {
                if (start >= 0) spans.Add(new(start, end - start, "PERSON"));
                start = tokens[index].Start;
            }
            if (label == 0 && start >= 0)
            {
                spans.Add(new(start, end - start, "PERSON"));
                start = -1;
            }
            if (label != 0) end = tokens[index].Start + tokens[index].Length;
        }
        if (start >= 0) spans.Add(new(start, end - start, "PERSON"));
        return spans;
    }

    /// <summary>Release the native session after any in-flight call completes.</summary>
    public void Dispose()
    {
        lock (gate)
        {
            if (disposed) return;
            disposed = true;
            session.Dispose();
        }
    }
}
