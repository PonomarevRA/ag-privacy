using System.Security.Cryptography;
using AgPrivacy;

if (args.Length is < 1 or > 2)
{
    Console.Error.WriteLine("usage: Onnx BASE_MODEL.onnx [PROSE_MODEL.onnx] < input.ndjson > masked.ndjson");
    return 2;
}

try
{
    using var model = ReadModel(args[0]);
    using var prose = args.Length == 2 ? ReadModel(args[1]) : null;
    var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);

    // This executable demonstrates a session-local key. Production hosts supply their own protected key.
    byte[] key = RandomNumberGenerator.GetBytes(32);
    using var aliases = new Pseudonymizer(key, "onnx-example-session");
    CryptographicOperations.ZeroMemory(key);
    var masker = new StreamingPrivacyMasker(policy, aliases, model, null, null, null, prose);
    await masker.MaskAsync(Console.OpenStandardInput(), Console.OpenStandardOutput());
    return 0;
}
catch
{
    // Keep input, model contents and filesystem paths out of error output.
    Console.Error.WriteLine("onnx-masking-failed");
    return 2;
}

/// <summary>Bound the local model read before creating its ONNX Runtime session.</summary>
static OnnxPersonDetector ReadModel(string path)
{
    using var file = File.OpenRead(path);
    if (file.Length is < 1 or > OnnxPersonDetector.MaximumFileBytes)
        throw new ArgumentException("invalid-onnx-model-size");
    byte[] bytes = new byte[(int)file.Length];
    file.ReadExactly(bytes);
    if (file.ReadByte() != -1) throw new ArgumentException("invalid-onnx-model-size");
    return OnnxPersonDetector.Load(bytes);
}
