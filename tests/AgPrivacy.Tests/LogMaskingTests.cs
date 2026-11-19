using System.Text.Json.Nodes;
using AgPrivacy;
using Xunit;

namespace AgPrivacy.Tests;

public class LogMaskingTests
{
    /// <summary>Exercise the real model and retain the context surrounding a lowercase name.</summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void MasksLowercaseNameInMessageAndRawCopy(bool soft)
    {
        using var aliases = new Pseudonymizer(new byte[32], "log-mask-test");
        var mask = DisplayMasker(aliases, soft);
        const string message = "routing the draft to mira tracewell for review";
        var data = mask(new JsonObject { ["message"] = message, ["event"] = new JsonObject { ["original"] = message } }.ToJsonString()).Data!;
        string output = data["message"]!.GetValue<string>();

        Assert.StartsWith("routing the draft to [REDACTED:v1:PERSON:", output);
        Assert.EndsWith("] for review", output);
        Assert.DoesNotContain("mira tracewell", output);
        Assert.Equal(output, data["event"]!["original"]!.GetValue<string>());
    }

    /// <summary>Recognize a standalone card candidate in prose while retaining a failed checksum.</summary>
    [Theory]
    [InlineData(true, "4111 1111 1111 1111")]
    [InlineData(false, "4111111111111111")]
    [InlineData(true, "0000 0000 0000 0000")]
    public void MasksUnlabeledCardOnlyInsideMessage(bool soft, string card)
    {
        using var aliases = new Pseudonymizer(new byte[32], "log-mask-test");
        var mask = DisplayMasker(aliases, soft);
        const string nonCard = "4111-1111-1111-1112";
        var result = mask(new JsonObject { ["message"] = $"instrument {card} accepted; reference {nonCard} queued" }.ToJsonString());
        Assert.True(result.Allowed);
        string output = result.Data!["message"]!.GetValue<string>();

        Assert.StartsWith("instrument [REDACTED:v1:ACCOUNT:", output);
        Assert.EndsWith($"] accepted; reference {nonCard} queued", output);
        Assert.DoesNotContain(card, output);
        Assert.Equal(1, result.Replacements);
    }

    /// <summary>Keep log labels, instrument values, and the correlation link across modes and ECS representations.</summary>
    [Fact]
    public void PreservesInstrumentValuesAndPseudonymizesTracesConsistently()
    {
        using var aliases = new Pseudonymizer(new byte[32], "log-mask-test");
        const string input = """
            [
              {"trace":{"id":"3a0e1ab96f8c400caf6a5e8000000000"},
               "message":"completed isin=US0378331005 ticker=BRK.B email=synthetic@example.invalid; status=ready",
               "isin":"US0378331005","ticker":"BRK.B"},
              {"trace.id":"3a0e1ab96f8c400caf6a5e8000000000","ticker":"other@example.invalid"},
              {"trace.id":"3a0e1ab96f8c400caf6a5e8000000001","isin":"+70000000000"}
            ]
            """;
        var strict = DisplayMasker(aliases, soft: false)(input);
        var soft = DisplayMasker(aliases, soft: true)(input);
        Assert.True(strict.Allowed && soft.Allowed);
        string trace = strict.Data![0]!["trace"]!["id"]!.GetValue<string>();
        Assert.StartsWith("[REDACTED:v1:TRACE_ID:", trace);
        foreach (var result in new[] { strict, soft })
        {
            Assert.Equal(trace, result.Data![0]!["trace"]!["id"]!.GetValue<string>());
            Assert.Equal(trace, result.Data![1]!["trace.id"]!.GetValue<string>());
            Assert.NotEqual(trace, result.Data![2]!["trace.id"]!.GetValue<string>());
            Assert.Equal("US0378331005", result.Data![0]!["isin"]!.GetValue<string>());
            Assert.Equal("BRK.B", result.Data![0]!["ticker"]!.GetValue<string>());
            Assert.DoesNotContain("other@example.invalid", result.Data![1]!["ticker"]!.GetValue<string>());
            Assert.DoesNotContain("+70000000000", result.Data![2]!["isin"]!.GetValue<string>());
            string message = result.Data![0]!["message"]!.GetValue<string>();
            Assert.StartsWith("completed isin=US0378331005 ticker=BRK.B email=[REDACTED:v1:EMAIL:", message);
            Assert.EndsWith("]; status=ready", message);
            Assert.DoesNotContain("synthetic@example.invalid", message);
        }
    }

    /// <summary>Use the same local name model and default policy as the playground.</summary>
    private static Func<string, PrivacyResult> DisplayMasker(Pseudonymizer aliases, bool soft)
    {
        var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
        var model = MicroPersonModel.Load(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "person-default.bin")));
        return soft
            ? new SoftPartMasker(aliases, policy, model).SanitizeJson
            : new PrivacyEngine(policy, aliases, model).SanitizeJsonForDisplay;
    }
}
