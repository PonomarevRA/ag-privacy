using System.Text;
using System.Text.Json;
using Xunit;

namespace AgPrivacy.Tests;

public sealed class ApiLogMaskingTests
{
    /// <summary>Mask network addresses and explicit API credentials without removing surrounding log text.</summary>
    [Fact]
    public async Task MasksAddressesAndCredentialFields()
    {
        const string input = """{"message":"peer:192.0.2.42:443; origin=[2001:db8::1]:8443; remote ::1; build=1.2.3.4; malformed=999.1.2.3","x-api-key":"fixture-AbE00000000000","sessionToken":"fixture-YzE00000000000","trace.id":"00000000000000000000000000000004"}""";
        var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
        using var aliases = new Pseudonymizer(new byte[32], "api-log-synthetic");
        using var source = new MemoryStream(Encoding.UTF8.GetBytes(input));
        using var destination = new MemoryStream();
        var observed = await new StreamingPrivacyMasker(policy, aliases).MaskAsync(source, destination);

        using var document = JsonDocument.Parse(destination.ToArray());
        var row = document.RootElement;
        Assert.Equal("peer:[IP]:443; origin=[[IP]]:8443; remote [IP]; build=1.2.3.4; malformed=999.1.2.3", row.GetProperty("message").GetString());
        Assert.NotEqual("fixture-AbE00000000000", row.GetProperty("x-api-key").GetString());
        Assert.NotEqual("fixture-YzE00000000000", row.GetProperty("sessionToken").GetString());
        Assert.Equal("00000000000000000000000000000004", row.GetProperty("trace.id").GetString());
        Assert.Equal(5, observed.Replacements);
    }

    /// <summary>Use the same explicit credential aliases in plain text and escaped JSON messages.</summary>
    [Theory]
    [InlineData("api_key=fixture-AbE00000000000; trace=ready")]
    [InlineData("""{"message":"client_secret=fixture-AbE00000000000; trace=ready"}""")]
    [InlineData("""{"message":"callback x-api-key=\"fixture-AbE00000000000\"; trace=ready"}""")]
    public async Task MasksInlineApiCredentials(string input)
    {
        var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
        using var aliases = new Pseudonymizer(new byte[32], "api-log-synthetic");
        using var source = new MemoryStream(Encoding.UTF8.GetBytes(input));
        using var destination = new MemoryStream();
        await new StreamingPrivacyMasker(policy, aliases).MaskAsync(source, destination);

        string output = Encoding.UTF8.GetString(destination.ToArray());
        Assert.DoesNotContain("fixture-AbE00000000000", output);
        Assert.Contains("trace=ready", output);
        if (input.StartsWith('{'))
        {
            using var document = JsonDocument.Parse(output);
            Assert.EndsWith("trace=ready", document.RootElement.GetProperty("message").GetString());
        }
    }

    /// <summary>Run token telemetry independently and only for candidates outside active masks.</summary>
    [Fact]
    public async Task TokenShadowOnlyReportsPreviouslyUnmaskedCandidates()
    {
        const string row = """{"message":"grant material ZrMxVcTnQp7456dsWfLo; token=ZrMxVcTnQp7456dsWfLo"}""";
        var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
        using var aliases = new Pseudonymizer(new byte[32], "token-shadow-synthetic");
        var weights = new byte[TokenContextShadow.ModelBytes];
        "APTOK001"u8.CopyTo(weights);
        var model = TokenContextShadow.Load(weights);
        var baseline = await Run(new StreamingPrivacyMasker(policy, aliases));
        var observed = await Run(new StreamingPrivacyMasker(policy, aliases, null, null, null, model));
        Assert.Equal(baseline.Data, observed.Data);
        Assert.Equal(baseline.Journal, observed.Journal);
        Assert.Equal(new TokenContextCounts(1, 1), observed.Result.TokenContext);

        /// <summary>Capture both output streams for an identical synthetic record.</summary>
        async Task<(byte[] Data, string Journal, StreamMaskResult Result)> Run(StreamingPrivacyMasker masker)
        {
            using var input = new MemoryStream(Encoding.UTF8.GetBytes(row));
            using var output = new MemoryStream();
            using var journal = new StringWriter();
            var result = await masker.MaskAsync(input, output, journal);
            return (output.ToArray(), journal.ToString(), result);
        }
    }
}
