using System.Text;
using System.Text.Json;
using Xunit;

namespace AgPrivacy.Tests;

public sealed class OnnxPersonTests
{
    /// <summary>Keep every UTF-16 interval identical across casing, scripts, account syntax and Unicode escapes.</summary>
    [Theory]
    [InlineData("person-default")]
    [InlineData("person-prose")]
    public void MatchesNativeModel(string name)
    {
        var native = MicroPersonModel.Load(Read(name + ".bin"));
        using var onnx = OnnxPersonDetector.Load(Read(name + ".onnx"));
        Assert.Equal(native.Version, onnx.SourceModelVersion);
        string[] starts = ["", "Контакт: ", "After the call ", "service account login=", "Запись: "];
        string[] values = ["алина зорничева", "Роман Левчанов", "Alina Levchanova", "levchanov_io",
            "Зорничева А.М.", "API gateway", "архивный модуль", "Maria Sоkolova", "🙂", "\\u0410"];
        string[] ends = ["", "; approved", " подтвердила изменение.", " requested a call."];
        foreach (string start in starts)
        foreach (string value in values)
        foreach (string end in ends)
        {
            string text = start + value + end;
            Assert.True(native.Find(text).SequenceEqual(onnx.Find(text)), "onnx-span-parity");
        }
        Assert.Empty(onnx.Find(""));
        Assert.Empty(onnx.Find("  \t\n—"));
    }

    /// <summary>Preserve predicted-label feedback between tokens and prefer O when every score ties.</summary>
    [Theory]
    [InlineData("tie")]
    [InlineData("transition")]
    public void PreservesGreedyStateAndTies(string fixture)
    {
        var native = MicroPersonModel.Load(Read("Fixtures/" + fixture + ".bin"));
        using var onnx = OnnxPersonDetector.Load(Read("Fixtures/" + fixture + ".onnx"));
        const string text = "aa bb cc dd ee ff";
        Assert.True(native.Find(text).SequenceEqual(onnx.Find(text)), "onnx-state-parity");
        if (fixture == "tie") Assert.Empty(onnx.Find(text));
        else Assert.True(onnx.Find(text).Count > 1);
    }

    /// <summary>Exercise the full pipeline with both models and escaped messages across stream windows.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task MatchesStreamingReplacements(bool escaped)
    {
        var native = MicroPersonModel.Load(Read("person-default.bin"));
        var nativeProse = MicroPersonModel.Load(Read("person-prose.bin"));
        using var onnx = OnnxPersonDetector.Load(Read("person-default.onnx"));
        using var onnxProse = OnnxPersonDetector.Load(Read("person-prose.onnx"));
        var options = new JsonSerializerOptions
        {
            Encoder = escaped ? System.Text.Encodings.Web.JavaScriptEncoder.Default :
                System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };
        string message = "Контакт: алина зорничева; employee login=levchanov_io; service account login=levchanov_io";
        string row = JsonSerializer.Serialize(new Dictionary<string, string>
        {
            ["message"] = message, ["trace.id"] = "synthetic-trace-01", ["status"] = "ok"
        }, options);
        string input = string.Join('\n', Enumerable.Repeat(row, 40)) + "\n";
        string nativeOutput = await MaskAsync(input, native, nativeProse);
        string onnxOutput = await MaskAsync(input, onnx, onnxProse);
        Assert.True(nativeOutput == onnxOutput, "onnx-stream-parity");
        Assert.DoesNotContain("алина зорничева", onnxOutput);
        foreach (string outputRow in onnxOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            using var document = JsonDocument.Parse(outputRow);
            Assert.Equal("synthetic-trace-01", document.RootElement.GetProperty("trace.id").GetString());
        }
    }

    /// <summary>Share the core token and input limits and release the native session exactly once.</summary>
    [Fact]
    public void EnforcesLimitsAndDisposal()
    {
        var detector = OnnxPersonDetector.Load(Read("person-default.onnx"));
        Assert.Throws<InvalidOperationException>(() => detector.Find(new string('a', 257)));
        Assert.Throws<InvalidOperationException>(() => detector.Find(string.Concat(Enumerable.Repeat("a ", 8193))));
        Assert.Throws<ArgumentException>(() => detector.Find(new string('x', PrivacyLimits.InputBytes + 1)));
        detector.Dispose();
        detector.Dispose();
        Assert.Throws<ObjectDisposedException>(() => detector.Find("Alina Zornicheva"));
        Assert.Throws<ArgumentException>(() => OnnxPersonDetector.Load(new byte[OnnxPersonDetector.MaximumFileBytes + 1]));
        Assert.Throws<ArgumentException>(() => OnnxPersonDetector.Load([]));
    }

    /// <summary>Accept the largest token sequence allowed by the core detector.</summary>
    [Fact]
    public void HandlesMaximumTokenCount()
    {
        var native = MicroPersonModel.Load(Read("person-default.bin"));
        using var onnx = OnnxPersonDetector.Load(Read("person-default.onnx"));
        string text = string.Concat(Enumerable.Repeat("fixture ", MicroPersonModel.MaxTokens));
        Assert.True(native.Find(text).SequenceEqual(onnx.Find(text)), "onnx-token-limit-parity");
    }

    /// <summary>Backend errors become a blocked result at the ordinary engine entry point.</summary>
    [Fact]
    public void BlocksWhenTheBackendFails()
    {
        using var onnx = OnnxPersonDetector.Load(Read("Fixtures/failure.onnx"));
        using var aliases = new Pseudonymizer(new byte[32], "onnx-failure-fixture");
        var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
        var engine = new PrivacyEngine(policy, aliases, onnx);
        var result = engine.SanitizeText("Контакт: Алина Зорничева", heuristic: true);
        Assert.False(result.Allowed);
        Assert.Null(result.Text);
        Assert.Equal("privacy-processing-blocked", result.Status);
    }

    /// <summary>Calls on one shared session remain deterministic under concurrent use.</summary>
    [Fact]
    public void SupportsConcurrentCalls()
    {
        var native = MicroPersonModel.Load(Read("person-default.bin"));
        using var onnx = OnnxPersonDetector.Load(Read("person-default.onnx"));
        const string text = "Client: Alina Zornicheva; approved";
        var expected = native.Find(text);
        Parallel.For(0, 32, _ => Assert.True(expected.SequenceEqual(onnx.Find(text)), "onnx-concurrent-parity"));
    }

    /// <summary>Reject metadata that belongs to another feature contract.</summary>
    [Fact]
    public void RejectsUnknownContract()
    {
        byte[] bytes = Read("person-default.onnx");
        byte[] format = Encoding.UTF8.GetBytes("person-perceptron-v1");
        int start = bytes.AsSpan().IndexOf(format);
        Assert.True(start > 0);
        bytes[start + format.Length - 1] = (byte)'9';
        Assert.Throws<ArgumentException>(() => OnnxPersonDetector.Load(bytes));
    }

    /// <summary>Load a shipped model or a tiny synthetic model from this test's output directory.</summary>
    private static byte[] Read(string file) => File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, file));

    /// <summary>Compare complete masked stream output while keeping the pseudonym key constant.</summary>
    private static async Task<string> MaskAsync(string text, IPersonDetector model, IPersonDetector prose)
    {
        using var aliases = new Pseudonymizer(new byte[32], "onnx-synthetic-comparison");
        var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
        using var input = new MemoryStream(Encoding.UTF8.GetBytes(text));
        using var output = new MemoryStream();
        var pipe = new StreamingPrivacyMasker(policy, aliases, model, null, null, null, prose);
        var counts = await pipe.MaskAsync(input, output);
        Assert.Equal(0, counts.ConservativeMasks);
        return Encoding.UTF8.GetString(output.ToArray());
    }
}
