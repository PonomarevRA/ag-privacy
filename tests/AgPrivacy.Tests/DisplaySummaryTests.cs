using Xunit;

namespace AgPrivacy.Tests;

public sealed class DisplaySummaryTests
{
    /// <summary>Count only applied rules, including masked keys and fragments inside a message.</summary>
    [Fact]
    public void StrictAndSoftPartReportTheirOwnAppliedRules()
    {
        using var aliases = new Pseudonymizer(new byte[32], "display-summary-tests");
        var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
        var engine = new PrivacyEngine(policy, aliases);
        var soft = new SoftPartMasker(aliases, policy);
        const string input = """
            {"firstName":"Synthetic","email":"fixture@example.invalid","phone":"+70012345678",
             "agreementNumber":"12-451123/26","other":"00000000-0000-4000-8000-000000000001",
             "message":"sent to recipient@example.invalid","trace.id":"00000000-0000-4000-8000-000000000002",
             "key@example.invalid":null,"status":"approved"}
            """;

        var strictResult = engine.SanitizeJsonForDisplay(input);
        var softResult = soft.SanitizeJson(input);
        foreach (var result in new[] { strictResult, softResult })
        {
            Assert.True(result.Allowed);
            var counts = result.ReplacementsByType!;
            Assert.Equal(result.Replacements, counts.Values.Sum());
            Assert.Equal(2, counts["EMAIL"]);
            foreach (string type in new[] { "PHONE", "AGREEMENT", "GUID", "TRACE_ID", "KEY_EMAIL" })
                Assert.Equal(1, counts[type]);
        }
        Assert.Equal(1, strictResult.ReplacementsByType!["PERSON"]);
        Assert.False(softResult.ReplacementsByType!.ContainsKey("PERSON"));
        Assert.Null(engine.SanitizeJson(input).ReplacementsByType);
    }
}
