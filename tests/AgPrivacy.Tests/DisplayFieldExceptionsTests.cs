using System.Text.Json;
using Xunit;

namespace AgPrivacy.Tests;

public sealed class DisplayFieldExceptionsTests
{
    /// <summary>Check case-insensitive exact matching and retain formal checks and explicit field rules.</summary>
    [Fact]
    public void ConfiguredExceptionsApplyToBothDisplayModes()
    {
        var policy = PrivacyPolicy.Compile("""
            {"schemaVersion":"ag-privacy-policy-v1","displayFieldExceptions":["ISIN","ticker","instrument.name","email"]}
            """u8);
        using var aliases = new Pseudonymizer(new byte[32], "display-exceptions");
        var model = new FixturePersonDetector();
        var engine = new PrivacyEngine(policy, aliases, model);
        var soft = new SoftPartMasker(aliases, policy, model);
        const string input = """
            [{"instrument.name":"Mira Tracewell","instrument-name":"Mira Tracewell","ticker":"BRK.B"},
             {"instrument.name":"fixture@example.invalid","email":"fixture@example.invalid","ticker":"Mira Tracewell",
              "message":"customer: Mira Tracewell"}]
            """;

        foreach (var masked in new[] { engine.SanitizeJsonForDisplay(input), soft.SanitizeJson(input) })
        {
            Assert.True(masked.Allowed);
            Assert.False(masked.SafeForAgent);
            var data = masked.Data!;
            Assert.Equal("Mira Tracewell", data[0]!["instrument.name"]!.GetValue<string>());
            Assert.NotEqual("Mira Tracewell", data[0]!["instrument-name"]!.GetValue<string>());
            Assert.Equal("BRK.B", data[0]!["ticker"]!.GetValue<string>());
            Assert.NotEqual("fixture@example.invalid", data[1]!["instrument.name"]!.GetValue<string>());
            Assert.NotEqual("fixture@example.invalid", data[1]!["email"]!.GetValue<string>());
            Assert.NotEqual("Mira Tracewell", data[1]!["ticker"]!.GetValue<string>());
            Assert.DoesNotContain("Mira Tracewell", data[1]!["message"]!.GetValue<string>());
        }

        var strict = engine.SanitizeJson(input);
        Assert.True(strict.SafeForAgent);
        Assert.DoesNotContain("Mira Tracewell", strict.Data!.ToJsonString());
    }

    /// <summary>Check that an empty UI override removes defaults for one request.</summary>
    [Fact]
    public void RequestOverrideDoesNotChangeConfiguredDefaults()
    {
        var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
        Assert.True(policy.DisplayFieldExceptions.Fields.SetEquals(["isin", "ticker"]));
        using var aliases = new Pseudonymizer(new byte[32], "display-exceptions");
        var model = new FixturePersonDetector();
        var engine = new PrivacyEngine(policy, aliases, model);
        var soft = new SoftPartMasker(aliases, policy, model);
        using var list = JsonDocument.Parse("[]");
        var empty = DisplayFieldExceptions.Compile(list.RootElement);
        const string input = """{"ticker":"BRK.B","message":"order accepted ticker=BRK.B"}""";

        foreach (var masked in new[] { engine.SanitizeJsonForDisplay(input, empty), soft.SanitizeJson(input, empty) })
        {
            Assert.NotEqual("BRK.B", masked.Data!["ticker"]!.GetValue<string>());
            Assert.DoesNotContain("BRK.B", masked.Data!["message"]!.GetValue<string>());
        }

        Assert.Equal("BRK.B", engine.SanitizeJsonForDisplay(input).Data!["ticker"]!.GetValue<string>());
        Assert.Contains("ticker=BRK.B", soft.SanitizeJson(input).Data!["message"]!.GetValue<string>());
    }

    /// <summary>Reject duplicate, wildcard and non-string entries in both configuration sources.</summary>
    [Theory]
    [InlineData("""["ticker","TICKER"]""")]
    [InlineData("""["field.*"]""")]
    [InlineData("""[1]""")]
    [InlineData("""{}""")]
    public void RejectsInvalidLists(string input)
    {
        using var list = JsonDocument.Parse(input);
        Assert.Throws<ArgumentException>(() => DisplayFieldExceptions.Compile(list.RootElement));
    }

    private sealed class FixturePersonDetector : IPersonDetector
    {
        public string Version => "fixture";

        /// <summary>Model a deterministic false positive for the synthetic instrument label.</summary>
        public IReadOnlyList<EntitySpan> Find(string text)
        {
            foreach (string value in new[] { "Mira Tracewell", "BRK.B" })
            {
                int start = text.IndexOf(value, StringComparison.Ordinal);
                if (start >= 0) return [new(start, value.Length, "PERSON")];
            }
            return [];
        }
    }
}
