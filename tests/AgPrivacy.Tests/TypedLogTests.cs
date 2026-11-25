using System.Text.Encodings.Web;
using System.Text.Json;
using Xunit;

namespace AgPrivacy.Tests;

public sealed class TypedLogTests
{
    /// <summary>Count only emitted masks and preserve JSON quoting across the log's encoding layers.</summary>
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public void ReportsTypesAndPreservesMasterId(int escapeDepth)
    {
        using var aliases = new Pseudonymizer(new byte[32], "typed-log-tests");
        var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
        var model = MicroPersonModel.Load(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "person-default.bin")));
        var engine = new PrivacyEngine(policy, aliases, model);
        var options = new JsonSerializerOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
        const string guid = "00000000-0000-4000-8000-000000000001";
        var input = new Dictionary<string, string>
        {
            [guid] = "topic",
            ["MasterId"] = guid,
            ["Id"] = guid,
            ["Email"] = "fixture@example.invalid",
            ["Phone"] = "+70012345678",
            ["AgreementNumber"] = "12-451123/26",
            ["FullName"] = "Mira Tracewell",
            ["Password"] = "synthetic\"quote\\",
            ["ApiKey"] = "line\nfixture",
            ["CardNumber"] = "4111111111111111",
            ["Status"] = "approved",
            ["Name"] = "Консультация клиента",
            ["Existing"] = "[REDACTED:v1:EMAIL:" + new string('a', 64) + "]"
        };
        const string prefix = """Unary-запрос "\"/ChatConversations.ChatConversationsService/GetTopicsByConversations\"" обработан за "1" мс. Ответ: """;
        string payload = JsonSerializer.Serialize(input, options);
        for (int i = 0; i < escapeDepth; i++) payload = JsonSerializer.Serialize(payload, options);

        var result = engine.SanitizeTypedLogForDisplay(prefix + payload);

        Assert.True(result.Allowed);
        Assert.False(result.SafeForAgent);
        Assert.Equal("log-types", result.ProtectionMode);
        Assert.Equal(9, result.Replacements);
        var counts = result.ReplacementsByType!;
        Assert.Equal(result.Replacements, counts.Values.Sum());
        Assert.Equal(2, counts["GUID"]);
        foreach (string type in new[] { "EMAIL", "PHONE", "AGREEMENT", "PERSON", "ACCOUNT" })
            Assert.Equal(1, counts[type]);
        Assert.Equal(2, counts["SECRET"]);

        Assert.StartsWith(prefix, result.Text);
        string output = result.Text![prefix.Length..];
        for (int i = 0; i < escapeDepth; i++) output = JsonSerializer.Deserialize<string>(output)!;
        var fields = JsonSerializer.Deserialize<Dictionary<string, string>>(output)!;
        Assert.Equal(input.Count, fields.Count);
        Assert.Equal(guid, fields["MasterId"]);
        Assert.True(Guid.TryParseExact(fields["Id"], "D", out _));
        AssertSubstituted(input["Id"], fields["Id"]);
        AssertSubstituted(input["Email"], fields["Email"]);
        AssertSubstituted(input["Phone"], fields["Phone"]);
        AssertSubstituted(input["AgreementNumber"], fields["AgreementNumber"]);
        Assert.Equal(result.Text, engine.SanitizeTypedLogForDisplay(prefix + payload).Text);
        Assert.Equal("topic", fields[fields["Id"]]);
        AssertSubstituted(input["Password"], fields["Password"]);
        Assert.Equal("****", fields["ApiKey"]);
        Assert.Equal("approved", fields["Status"]);
        Assert.Equal("Консультация клиента", fields["Name"]);
        Assert.Equal(input["Existing"], fields["Existing"]);
    }

    /// <summary>Substitute mixed and variant names while preserving separators and adjacent JSON.</summary>
    [Theory]
    [InlineData("Иван Petrovich Петров")]
    [InlineData("Maria Sоkolova")]
    [InlineData("Dmytryy Wolkoff")]
    [InlineData("Semenov, Ivan")]
    [InlineData("Nikitin / Oleg")]
    [InlineData("Zaitsev–Andrei")]
    [InlineData("Anna-Volkova")]
    public void SubstitutesComplexNamesInJsonMessage(string name)
    {
        using var aliases = new Pseudonymizer(new byte[32], "typed-complex-name-fixture");
        var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
        var engine = new PrivacyEngine(policy, aliases);
        const string before = "Подпись «";
        const string after = "» получена.";
        var fields = new Dictionary<string, string> { ["message"] = before + name + after, ["note"] = name };
        foreach (var options in new[] { new JsonSerializerOptions(),
            new JsonSerializerOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping } })
        {
            var result = engine.SanitizeTypedLogForDisplay(JsonSerializer.Serialize(fields, options), includePreview: true);
            Assert.True(result.Allowed);
            Assert.Equal(1, result.ReplacementsByType!["PERSON"]);
            Assert.Single(result.Preview!.Highlights);
            using var output = JsonDocument.Parse(result.Text!);
            string message = output.RootElement.GetProperty("message").GetString()!;
            Assert.StartsWith(before, message);
            Assert.EndsWith(after, message);
            AssertSubstituted(name, message[before.Length..^after.Length]);
            Assert.Equal(name, output.RootElement.GetProperty("note").GetString());
        }
    }

    /// <summary>Keep ticker exceptions active when punctuation in the JSON message is escaped.</summary>
    [Fact]
    public void PreservesTickerInEscapedJsonMessage()
    {
        using var aliases = new Pseudonymizer(new byte[32], "typed-complex-name-fixture");
        var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
        var engine = new PrivacyEngine(policy, aliases);
        string input = JsonSerializer.Serialize(new { message = "Выписка «ticker=voronovsn» готова." });
        var result = engine.SanitizeTypedLogForDisplay(input);
        Assert.Equal(input, result.Text);
        Assert.Equal(0, result.Replacements);
    }

    /// <summary>Parse every enclosing string after redaction and preserve other properties and log text.</summary>
    [Theory]
    [InlineData(1, false)]
    [InlineData(2, true)]
    [InlineData(3, false)]
    [InlineData(4, true)]
    [InlineData(8, false)]
    public void SubstitutesNamesThroughUnicodeEscapedJson(int wrappers, bool prefixLog)
    {
        using var aliases = new Pseudonymizer(new byte[32], "typed-nested-name-fixture");
        var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
        var engine = new PrivacyEngine(policy, aliases);
        const string before = "Готово 😀 «";
        const string name = "Иван Petrovich Петров";
        const string after = "» обработано";
        const string prefix = "fixture response: ";
        var options = new JsonSerializerOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
        string encoded = JsonSerializer.Serialize(new { message = before + name + after, note = name });
        for (int i = 0; i < wrappers - 1; i++)
            encoded = JsonSerializer.Serialize(encoded, i % 2 == 0 ? null : options);
        string original = JsonSerializer.Serialize(new { payload = encoded, status = "ok" }, options);
        if (prefixLog) original = prefix + original;

        var result = engine.SanitizeTypedLogForDisplay(original, includePreview: true);

        Assert.True(result.Allowed);
        Assert.Equal(1, result.ReplacementsByType!["PERSON"]);
        Assert.Single(result.Preview!.Highlights);
        if (prefixLog) Assert.StartsWith(prefix, result.Text);
        using var envelope = JsonDocument.Parse(prefixLog ? result.Text![prefix.Length..] : result.Text!);
        Assert.Equal("ok", envelope.RootElement.GetProperty("status").GetString());
        string inner = envelope.RootElement.GetProperty("payload").GetString()!;
        for (int i = 0; i < wrappers - 1; i++)
            inner = JsonSerializer.Deserialize<string>(inner)!;
        using var log = JsonDocument.Parse(inner);
        string message = log.RootElement.GetProperty("message").GetString()!;
        Assert.StartsWith(before, message);
        Assert.EndsWith(after, message);
        AssertSubstituted(name, message[before.Length..^after.Length]);
        Assert.Equal(name, log.RootElement.GetProperty("note").GetString());
    }

    /// <summary>Keep instrument identifiers in nested message strings even when punctuation is escaped.</summary>
    [Fact]
    public void PreservesTickerThroughNestedUnicodeEscapes()
    {
        using var aliases = new Pseudonymizer(new byte[32], "typed-nested-name-fixture");
        var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
        var engine = new PrivacyEngine(policy, aliases);
        string payload = JsonSerializer.Serialize(new { message = "Выписка «ticker=voronovsn» готова." });
        string encoded = JsonSerializer.Serialize(JsonSerializer.Serialize(payload));

        var result = engine.SanitizeTypedLogForDisplay(encoded);
        Assert.Equal(encoded, result.Text);
        Assert.Equal(0, result.Replacements);
    }

    /// <summary>Keep a structured payload valid when it has metadata and no message field.</summary>
    [Fact]
    public void PreservesNestedJsonWithoutMessage()
    {
        using var aliases = new Pseudonymizer(new byte[32], "typed-nested-name-fixture");
        var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
        var model = MicroPersonModel.Load(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "person-default.bin")));
        var engine = new PrivacyEngine(policy, aliases, model);
        string payload = JsonSerializer.Serialize(new { note = "Готово, Анна Соколова." });
        string encoded = JsonSerializer.Serialize(JsonSerializer.Serialize(payload));

        var result = engine.SanitizeTypedLogForDisplay("fixture response: " + encoded);
        Assert.Equal("fixture response: " + encoded, result.Text);
        Assert.Equal(0, result.Replacements);
    }

    /// <summary>Locate a prefixed JSON string whose decoded object starts on the next line.</summary>
    [Fact]
    public void SubstitutesPrefixedJsonAfterEscapedLeadingWhitespace()
    {
        using var aliases = new Pseudonymizer(new byte[32], "typed-nested-name-fixture");
        var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
        var engine = new PrivacyEngine(policy, aliases);
        const string prefix = "fixture response: ";
        const string name = "Олег Nikitin";
        string payload = JsonSerializer.Serialize(new { message = name });
        string input = prefix + JsonSerializer.Serialize("\n " + payload);

        var result = engine.SanitizeTypedLogForDisplay(input);

        Assert.StartsWith(prefix, result.Text);
        string decoded = JsonSerializer.Deserialize<string>(result.Text![prefix.Length..])!;
        Assert.StartsWith("\n ", decoded);
        using var output = JsonDocument.Parse(decoded);
        AssertSubstituted(name, output.RootElement.GetProperty("message").GetString()!);
    }

    /// <summary>Verify that each fixture letter or digit changes and each separator stays in place.</summary>
    private static void AssertSubstituted(string original, string masked)
    {
        Assert.Equal(original.Length, masked.Length);
        for (int i = 0; i < original.Length; i++)
        {
            char source = original[i], replacement = masked[i];
            if (!char.IsLetterOrDigit(source))
            {
                Assert.Equal(source, replacement);
                continue;
            }
            Assert.NotEqual(source, replacement);
            Assert.Equal(char.IsDigit(source), char.IsDigit(replacement));
            Assert.Equal(char.IsUpper(source), char.IsUpper(replacement));
        }
    }

    /// <summary>A free-form log can identify values even when there is no matching field name.</summary>
    [Fact]
    public void DetectsTypesFromValuesInPlainLog()
    {
        using var aliases = new Pseudonymizer(new byte[32], "typed-log-tests");
        var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
        var engine = new PrivacyEngine(policy, aliases);
        var result = engine.SanitizeTypedLogForDisplay("sent to fixture@example.invalid, phone +70012345678, contract 12-451123/26, card 4111 1111 1111 1111");
        Assert.Equal(4, result.Replacements);
        Assert.Equal(1, result.ReplacementsByType!["EMAIL"]);
        Assert.Equal(1, result.ReplacementsByType["PHONE"]);
        Assert.Equal(1, result.ReplacementsByType["AGREEMENT"]);
        Assert.Equal(1, result.ReplacementsByType["ACCOUNT"]);
    }
}
