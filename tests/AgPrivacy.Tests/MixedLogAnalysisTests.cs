using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Xunit;

namespace AgPrivacy.Tests;

public sealed class MixedLogAnalysisTests
{
    private const string Outside = "qerolat";
    private const string Tail = "tuvenak";
    private const string Inside = "zoliwex";
    private const string Trace = "synthetic-trace-kept";
    private static readonly PrivacyPolicy Policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);

    /// <summary>Dispatch each detector only to its own logical slice and preserve the unrelated envelope.</summary>
    [Theory]
    [InlineData(LogAnalysisMode.Text, true, false)]
    [InlineData(LogAnalysisMode.Structured, false, true)]
    [InlineData(LogAnalysisMode.Mixed, true, true)]
    public void RoutesDetectorsIndependently(LogAnalysisMode mode, bool masksOutside, bool masksInside)
    {
        using var aliases = new Pseudonymizer(new byte[32], "mixed-model-routing");
        var textDetector = new FixtureDetector(Outside, Tail, Inside);
        var structuredDetector = new FixtureDetector(Outside, Tail, Inside);
        var engine = new PrivacyEngine(Policy, aliases);
        string envelope = BuildEnvelope("phase " + Inside + " complete");
        string input = "prefix " + Outside + " payload " + envelope + " suffix " + Tail + " done";

        var result = engine.SanitizeTypedLogForDisplay(input, includePreview: true, mode, textDetector, structuredDetector);

        Assert.True(result.Allowed);
        Assert.False(result.SafeForAgent);
        string output = Assert.IsType<string>(result.Text);
        Assert.Equal(!masksOutside, output.Contains(Outside, StringComparison.Ordinal));
        Assert.Equal(!masksOutside, output.Contains(Tail, StringComparison.Ordinal));
        Assert.Equal(!masksInside, output.Contains(Inside, StringComparison.Ordinal));
        Assert.Equal(masksOutside, textDetector.Inputs.Count > 0);
        Assert.Equal(masksInside, structuredDetector.Inputs.Count > 0);
        Assert.All(textDetector.Inputs, text => Assert.DoesNotContain(Inside, text));
        Assert.All(structuredDetector.Inputs, text =>
        {
            Assert.DoesNotContain(Outside, text);
            Assert.DoesNotContain(Tail, text);
            Assert.DoesNotContain("\"message\"", text);
        });
        Assert.Contains("\"trace.id\":\"" + Trace + "\"", output);
        Assert.Contains("\"ticker\":\"MOCK\"", output);
        Assert.StartsWith("prefix ", output);
        Assert.EndsWith(" done", output);
    }

    /// <summary>Nested JSON must parse after every string wrapper and decode to a masked value.</summary>
    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(4)]
    public void HandlesMultipleEscapingLayers(int layers)
    {
        using var aliases = new Pseudonymizer(new byte[32], "mixed-escaped-model");
        var engine = new PrivacyEngine(Policy, aliases);
        string original = BuildEnvelope("state " + Inside + " and Юлия");
        string escaped = original;
        for (int i = 0; i < layers; i++) escaped = JsonSerializer.Serialize(escaped);
        const string before = "fixture ";
        const string after = " completed";
        var result = engine.SanitizeTypedLogForDisplay(before + escaped + after,
            LogAnalysisMode.Mixed, new FixtureDetector(Outside), new FixtureDetector(Inside));

        Assert.True(result.Allowed);
        var output = Assert.IsType<string>(result.Text);
        Assert.StartsWith(before, output);
        Assert.EndsWith(after, output);
        string json = output[before.Length..^after.Length];
        for (int i = 0; i < layers; i++) json = JsonSerializer.Deserialize<string>(json)!;
        using var decoded = JsonDocument.Parse(json);
        Assert.Equal(Trace, decoded.RootElement.GetProperty("trace.id").GetString());
        Assert.Equal("MOCK", decoded.RootElement.GetProperty("ticker").GetString());
        string message = decoded.RootElement.GetProperty("message").GetString()!;
        Assert.DoesNotContain(Inside, message);
        Assert.EndsWith(" and Юлия", message);
    }

    /// <summary>Both branches can operate after decoding the text of an ECS message field.</summary>
    [Fact]
    public void RoutesJsonInsideMessageTogetherWithSurroundingProse()
    {
        using var aliases = new Pseudonymizer(new byte[32], "mixed-nested-message-routing");
        var engine = new PrivacyEngine(Policy, aliases);
        string inner = BuildEnvelope("phase " + Inside + " complete");
        string input = BuildEnvelope("prefix " + Outside + " payload " + inner + " suffix " + Tail + " done");
        var textDetector = new FixtureDetector(Outside, Tail, Inside);
        var structuredDetector = new FixtureDetector(Outside, Tail, Inside);

        var result = engine.SanitizeTypedLogForDisplay(input,
            LogAnalysisMode.Mixed, textDetector, structuredDetector);

        Assert.True(result.Allowed);
        using var outer = JsonDocument.Parse(Assert.IsType<string>(result.Text));
        string message = outer.RootElement.GetProperty("message").GetString()!;
        Assert.StartsWith("prefix ", message);
        Assert.EndsWith(" done", message);
        Assert.DoesNotContain(Outside, message);
        Assert.DoesNotContain(Tail, message);
        int start = message.IndexOf('{');
        int end = message.LastIndexOf('}') + 1;
        using var nested = JsonDocument.Parse(message[start..end]);
        Assert.DoesNotContain(Inside, nested.RootElement.GetProperty("message").GetString()!);
        Assert.Equal(Trace, nested.RootElement.GetProperty("trace.id").GetString());
        Assert.All(textDetector.Inputs, text => Assert.DoesNotContain(Inside, text));
        Assert.All(structuredDetector.Inputs, text => Assert.DoesNotContain(Outside, text));
    }

    /// <summary>Keep mixed routing when the decoded message begins with the nested JSON value.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void RoutesTextAfterJsonAtStartOfMessage(bool quoted)
    {
        using var aliases = new Pseudonymizer(new byte[32], "mixed-leading-json");
        var engine = new PrivacyEngine(Policy, aliases);
        const string inside = "золивекс";
        string inner = BuildEnvelope("phase " + inside + " complete");
        if (quoted) inner = JsonSerializer.Serialize(inner);
        string input = BuildEnvelope(inner + " suffix " + Tail + " done");
        var textDetector = new FixtureDetector(Tail);
        var structuredDetector = new FixtureDetector(inside);

        var result = engine.SanitizeTypedLogForDisplay(input,
            LogAnalysisMode.Mixed, textDetector, structuredDetector);

        Assert.True(result.Allowed);
        using var outer = JsonDocument.Parse(Assert.IsType<string>(result.Text));
        string message = outer.RootElement.GetProperty("message").GetString()!;
        int suffix = message.IndexOf(" suffix ", StringComparison.Ordinal);
        Assert.True(suffix > 0);
        string embedded = message[..suffix];
        if (quoted) embedded = JsonSerializer.Deserialize<string>(embedded)!;
        using var nested = JsonDocument.Parse(embedded);
        Assert.DoesNotContain(inside, nested.RootElement.GetProperty("message").GetString()!);
        Assert.DoesNotContain(Tail, message[suffix..]);
        Assert.Contains(" suffix " + Tail + " done", textDetector.Inputs);
        Assert.Contains("phase " + inside + " complete", structuredDetector.Inputs);
    }

    /// <summary>Preserve service aliases, trace and routing metadata while masking private IPs.</summary>
    [Fact]
    public void AppliesTechnicalGuardsBeforeProjection()
    {
        using var aliases = new Pseudonymizer(new byte[32], "mixed-technical-guard");
        var engine = new PrivacyEngine(Policy, aliases);
        const string service = "queue_trace";
        const string message = "service login=queue_trace; src=[2001:db8::7]:443";
        var model = new FixtureDetector(service, Trace);
        string input = BuildEnvelope(message);

        var result = engine.SanitizeTypedLogForDisplay(input, LogAnalysisMode.Mixed, model, model);

        using var json = JsonDocument.Parse(Assert.IsType<string>(result.Text));
        string masked = json.RootElement.GetProperty("message").GetString()!;
        Assert.Contains("service login=" + service + ";", masked);
        Assert.DoesNotContain("2001:db8::7", masked);
        Assert.EndsWith(":443", masked);
        Assert.Equal(Trace, json.RootElement.GetProperty("trace.id").GetString());
    }

    /// <summary>Mask two adjacent known query parameters, including one before the closing quote.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void KeepsQueryEncodingBoundaries(bool escaped)
    {
        using var aliases = new Pseudonymizer(new byte[32], "mixed-adjacent-query");
        var engine = new PrivacyEngine(Policy, aliases);
        const string original = "email=fixture%26stay%40example.invalid&fullName=Mira+Tracewell";
        string input = JsonSerializer.Serialize(new { request = "GET /lookup?" + original }, escaped
            ? null : new JsonSerializerOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
        string separator = escaped ? "\\u0026" : "&";

        var result = engine.SanitizeTypedLogForDisplay(input, LogAnalysisMode.Structured, null, null);

        string output = Assert.IsType<string>(result.Text);
        Assert.Contains(separator + "fullName=", output);
        using var parsed = JsonDocument.Parse(output);
        string request = parsed.RootElement.GetProperty("request").GetString()!;
        Assert.StartsWith("GET /lookup?email=", request);
        Assert.Contains("%26", request);
        Assert.DoesNotContain("Mira+Tracewell", request);
        Assert.DoesNotContain("fixture%26stay", request);
    }

    /// <summary>Retain the JSON string delimiter and benign parameters after masking a policy-matched query.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void MasksKnownQueryValueWithoutConsumingOtherFields(bool escapeEnvelope)
    {
        using var aliases = new Pseudonymizer(new byte[32], "mixed-query-routing");
        var engine = new PrivacyEngine(Policy, aliases);
        const string old = "mira.trace%40example.invalid";
        const string suffix = "mode=active&ticker=MOCK";
        string embedded = BuildEnvelope("GET /lookup?email=" + old + "&" + suffix);
        string input = escapeEnvelope ? JsonSerializer.Serialize(embedded) : embedded;

        var result = engine.SanitizeTypedLogForDisplay(input, LogAnalysisMode.Structured, null, null);

        Assert.True(result.Allowed);
        string output = Assert.IsType<string>(result.Text);
        string json = escapeEnvelope ? JsonSerializer.Deserialize<string>(output)! : output;
        using var decoded = JsonDocument.Parse(json);
        string message = decoded.RootElement.GetProperty("message").GetString()!;
        Assert.StartsWith("GET /lookup?email=", message);
        Assert.EndsWith("&" + suffix, message);
        Assert.DoesNotContain("mira.trace", message);
        Assert.Contains("=", message);
        Assert.Equal(Trace, decoded.RootElement.GetProperty("trace.id").GetString());
    }

    /// <summary>Stream and direct mode must agree when a bounded mixed record is read in small fragments.</summary>
    [Fact]
    public async Task StreamsMixedLogUsingBothModels()
    {
        using var aliases = new Pseudonymizer(new byte[32], "mixed-stream-routing");
        var engine = new PrivacyEngine(Policy, aliases);
        string json = BuildEnvelope("step " + Inside + " complete");
        string input = "prefix " + Outside + " " + json + " suffix " + Tail + " done";
        var expected = engine.SanitizeTypedLogForDisplay(input, LogAnalysisMode.Mixed,
            new FixtureDetector(Outside, Tail), new FixtureDetector(Inside));
        var stream = new StreamingPrivacyMasker(Policy, aliases, null, null, null, null,
            new FixtureDetector(Outside, Tail), LogAnalysisMode.Mixed, new FixtureDetector(Inside));
        using var source = new FragmentedStream(Encoding.UTF8.GetBytes(input));
        using var destination = new MemoryStream();
        var counts = await stream.MaskAsync(source, destination);

        Assert.Equal(expected.Text, Encoding.UTF8.GetString(destination.ToArray()));
        Assert.Equal(3, counts.Replacements);
        Assert.Equal(0, counts.ConservativeMasks);
    }

    /// <summary>Combine the encoding and envelope axes with two known kinds of query values.</summary>
    public static IEnumerable<object[]> QueryPatterns()
    {
        foreach (int wrappers in new[] { 0, 1, 2, 4 })
        foreach (bool relaxed in new[] { false, true })
        foreach (bool array in new[] { false, true })
        foreach (bool mixed in new[] { false, true })
        foreach (string field in new[] { "email", "fullName" })
            yield return [wrappers, relaxed, array, mixed, field];
    }

    /// <summary>Check raw and escaped JSON with both query encodings and untouched metadata.</summary>
    [Theory]
    [MemberData(nameof(QueryPatterns))]
    public void ParsesAndMasksQueryPatterns(int wrappers, bool relaxed, bool array, bool mixed, string field)
    {
        using var aliases = new Pseudonymizer(new byte[32], "mixed-format-matrix");
        var engine = new PrivacyEngine(Policy, aliases);
        const string safeQuery = "&service=queue%2Bmain&ticker=MOCK";
        const string prefix = "record received ";
        const string suffix = " record complete";
        string sensitive = field == "email" ? "sample.person%40example.invalid" : "Mira+Tracewell";
        string message = "GET /lookup?" + field + "=" + sensitive + safeQuery;
        var value = new Dictionary<string, string> { ["message"] = message, ["trace.id"] = Trace, ["ticker"] = "MOCK" };
        var options = relaxed ? new JsonSerializerOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping } : null;
        string payload = array ? JsonSerializer.Serialize(new[] { value }, options) : JsonSerializer.Serialize(value, options);
        for (int i = 0; i < wrappers; i++) payload = JsonSerializer.Serialize(payload, options);
        string input = mixed ? prefix + payload + suffix : payload;
        var mode = mixed ? LogAnalysisMode.Mixed : LogAnalysisMode.Structured;

        var result = engine.SanitizeTypedLogForDisplay(input, mode, null, null);

        Assert.True(result.Allowed);
        string output = Assert.IsType<string>(result.Text);
        if (mixed)
        {
            Assert.StartsWith(prefix, output);
            Assert.EndsWith(suffix, output);
            output = output[prefix.Length..^suffix.Length];
        }
        for (int i = 0; i < wrappers; i++) output = JsonSerializer.Deserialize<string>(output)!;
        using var parsed = JsonDocument.Parse(output);
        JsonElement root = array ? parsed.RootElement[0] : parsed.RootElement;
        Assert.Equal(Trace, root.GetProperty("trace.id").GetString());
        Assert.Equal("MOCK", root.GetProperty("ticker").GetString());
        string masked = root.GetProperty("message").GetString()!;
        Assert.StartsWith("GET /lookup?" + field + "=", masked);
        Assert.EndsWith(safeQuery, masked);
        Assert.DoesNotContain(sensitive, masked);
        Assert.DoesNotContain(field == "email" ? "sample.person" : "Mira", masked);
    }

    private static string BuildEnvelope(string message) => JsonSerializer.Serialize(new Dictionary<string, string>
    {
        ["trace.id"] = Trace,
        ["message"] = message,
        ["ticker"] = "MOCK",
    });

    /// <summary>Expose model call boundaries through synthetic deterministic exact matches.</summary>
    private sealed class FixtureDetector(params string[] targets) : IPersonDetector
    {
        public string Version => "test-role";
        internal List<string> Inputs { get; } = [];

        public IReadOnlyList<EntitySpan> Find(string text)
        {
            Inputs.Add(text);
            var found = new List<EntitySpan>();
            foreach (string target in targets)
            {
                int index = text.IndexOf(target, StringComparison.Ordinal);
                if (index >= 0) found.Add(new(index, target.Length, "PERSON", 90));
            }
            return found;
        }
    }

    /// <summary>Split UTF-8 and syntax at arbitrary boundaries without changing the source.</summary>
    private sealed class FragmentedStream(byte[] data) : MemoryStream(data)
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            => base.ReadAsync(buffer[..Math.Min(buffer.Length, 5)], cancellationToken);
    }
}
