using System.Text;
using System.Text.Json;
using Xunit;

namespace AgPrivacy.Tests;

public sealed class StreamingPrivacyMaskerTests
{
    /// <summary>Preserve both name parts at a window seam, reapply the mask to an unlabelled repeat, and dedupe the journal.</summary>
    [Fact]
    public async Task MasksAcrossWindowAndReusesNameOnLaterLine()
    {
        const string label = "контакт: ";
        const string name = "анна соколова";
        string inputText = new string(' ', 4096 - label.Length - "анна ".Length) + label + name + ";\n" +
            string.Concat(Enumerable.Repeat("ready status for batch\n", 700)) + "signature: " + name + ";\n";
        using var input = new ShortReads(Encoding.UTF8.GetBytes(inputText));
        using var output = new MemoryStream();
        using var journal = new StringWriter();
        using var aliases = new Pseudonymizer(new byte[32], "stream-test");
        var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
        var pipe = new StreamingPrivacyMasker(policy, aliases, new EmptyPersonDetector());

        var result = await pipe.MaskAsync(input, output, journal);
        string masked = Encoding.UTF8.GetString(output.ToArray());
        string row = Assert.Single(journal.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries));
        using var doc = JsonDocument.Parse(row);
        string replacement = doc.RootElement.GetProperty("Replacement").GetString()!;
        Assert.Equal("PERSON", doc.RootElement.GetProperty("Rule").GetString());
        Assert.DoesNotContain(name, masked);
        Assert.DoesNotContain(name, row);
        Assert.Contains(label + replacement + ";\n", masked);
        Assert.EndsWith("signature: " + replacement + ";\n", masked);
        Assert.Equal(2, result.Replacements);
        Assert.Equal(0, result.ConservativeMasks);
        Assert.False(result.SafeForAgent);
    }

    /// <summary>Keep ECS context and correlation while masking the sensitive parts of each record.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task MasksSensitiveLogFieldsAndPreservesTraceAndMessage(bool escapeUnicode)
    {
        const string trace = "00000000-0000-4000-8000-000000000001";
        const string name = "Anna Sergeevna Sokolova";
        const string date = "14.08.1987";
        const string prefix = "Заявка принята. Клиент ";
        const string suffix = ". Дата подписания: " + date + ". Статус: OK.";
        var fields = new Dictionary<string, object>
        {
            ["trace.id"] = trace,
            ["trace"] = new { sampled = true, id = trace },
            ["requestId"] = trace,
            ["codeWord"] = "synthetic-word",
            ["OTP"] = "000042",
            ["CVV"] = 731,
            ["fullNameEng"] = name,
            ["message"] = prefix + name + ". Дата рождения: " + date + "; OTP=000519" + suffix
        };
        var options = new JsonSerializerOptions();
        if (!escapeUnicode) options.Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping;
        string row = JsonSerializer.Serialize(fields, options);
        string padding = new string(' ', 4080) + "\n";
        string tail = new string(' ', 3000) + "\n";
        string secondRow = """{"otp":412,"cvv":2.9e2}""";
        using var input = new ShortReads(Encoding.UTF8.GetBytes(padding + row + "\n" + secondRow + "\n" + tail));
        using var output = new MemoryStream();
        using var aliases = new Pseudonymizer(new byte[32], "stream-test");
        var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
        var pipe = new StreamingPrivacyMasker(policy, aliases);

        var result = await pipe.MaskAsync(input, output);
        string[] rows = Encoding.UTF8.GetString(output.ToArray()).Split('\n');
        Assert.Equal(padding.TrimEnd('\n'), rows[0]);
        using var record = JsonDocument.Parse(rows[1]);
        var log = record.RootElement;
        Assert.Equal(trace, log.GetProperty("trace.id").GetString());
        Assert.Equal(trace, log.GetProperty("trace").GetProperty("id").GetString());
        Assert.NotEqual(trace, log.GetProperty("requestId").GetString());
        Assert.NotEqual("synthetic-word", log.GetProperty("codeWord").GetString());
        Assert.NotEqual("000042", log.GetProperty("OTP").GetString());
        Assert.Equal(0, log.GetProperty("CVV").GetInt32());
        Assert.NotEqual(name, log.GetProperty("fullNameEng").GetString());
        string message = log.GetProperty("message").GetString()!;
        Assert.Matches(@"^Заявка принята\. Клиент [A-Za-z ]+\. Дата рождения: [0-9]{2}\.[0-9]{2}\.[0-9]{4}; OTP=[0-9]{6}\. Дата подписания: 14\.08\.1987\. Статус: OK\.$", message);
        Assert.DoesNotContain(name, message);
        Assert.DoesNotContain("Дата рождения: " + date, message);
        Assert.DoesNotContain("000519", message);
        Assert.StartsWith(prefix, message);
        Assert.EndsWith(suffix, message);
        using var numeric = JsonDocument.Parse(rows[2]);
        Assert.Equal(0, numeric.RootElement.GetProperty("otp").GetInt32());
        Assert.Equal(0, numeric.RootElement.GetProperty("cvv").GetInt32());
        Assert.Equal(tail.TrimEnd('\n'), rows[3]);
        Assert.Equal(0, result.ConservativeMasks);
    }

    /// <summary>Even a preserve proposal leaves stdout and journal identical across stream windows.</summary>
    [Fact]
    public async Task ContextShadowObservesWithoutChangingReplacements()
    {
        byte[] weights = new byte[PersonContextShadow.ModelBytes];
        "APCTX001"u8.CopyTo(weights);
        var shadow = PersonContextShadow.Load(weights);
        const string row = """{"message":"worker label: ponomarev_ra; client: Anna Sokolova","fullName":"Fixture Person","otp":"000042"}""";
        const string escaped = """{"message":"\u0077orker label: ponomarev_ra"}""";
        string padding = new(' ', 3900);
        byte[] inputBytes = Encoding.UTF8.GetBytes(padding + "\n" + row + "\n" + escaped + "\n" + padding);
        using var aliases = new Pseudonymizer(new byte[32], "stream-context-test");
        var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);

        var baseline = await Run(new StreamingPrivacyMasker(policy, aliases));
        var observed = await Run(new StreamingPrivacyMasker(policy, aliases, null, shadow));

        Assert.Equal(baseline.Output, observed.Output);
        Assert.Equal(baseline.Journal, observed.Journal);
        Assert.Equal(baseline.Result.Replacements, observed.Result.Replacements);
        Assert.Null(baseline.Result.PersonContext);
        Assert.Equal(new PersonContextCounts(3, 1, 1), observed.Result.PersonContext);

        /// <summary>Exercise the same stream with fragmented input and a fresh journal.</summary>
        async Task<(byte[] Output, string Journal, StreamMaskResult Result)> Run(StreamingPrivacyMasker pipe)
        {
            using var input = new ShortReads(inputBytes);
            using var output = new MemoryStream();
            using var journal = new StringWriter();
            var result = await pipe.MaskAsync(input, output, journal);
            return (output.ToArray(), journal.ToString(), result);
        }
    }

    /// <summary>Read an oversized token incrementally, emit one fallback, and resume at the next boundary.</summary>
    [Fact]
    public async Task MasksOversizedTokenAndResumesBeyondSingleInputLimit()
    {
        string oversized = new('x', PrivacyLimits.InputBytes + 1200);
        using var input = new ShortReads(Encoding.UTF8.GetBytes(oversized + "\nstatus ready 😀\n"));
        using var output = new MemoryStream();
        using var aliases = new Pseudonymizer(new byte[32], "stream-test");
        var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
        var pipe = new StreamingPrivacyMasker(policy, aliases);

        var result = await pipe.MaskAsync(input, output);

        Assert.Equal("****\nstatus ready 😀\n", Encoding.UTF8.GetString(output.ToArray()));
        Assert.Equal(1, result.ConservativeMasks);
    }

    /// <summary>Fragment UTF-8 reads so neither entities nor Unicode scalars align with read calls.</summary>
    private sealed class ShortReads(byte[] bytes) : MemoryStream(bytes)
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            base.ReadAsync(buffer[..Math.Min(buffer.Length, 37)], cancellationToken);
    }

    private sealed class EmptyPersonDetector : IPersonDetector
    {
        public string Version => "fixture";
        public IReadOnlyList<EntitySpan> Find(string text) => [];
    }
}
