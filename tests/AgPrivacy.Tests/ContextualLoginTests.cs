using System.Text.Json;
using Xunit;

namespace AgPrivacy.Tests;

public sealed class ContextualLoginTests
{
    /// <summary>Use the login cue to mask the ambiguous token across all log display modes.</summary>
    [Theory]
    [InlineData("activity login=", "voronov_io", "; completed")]
    [InlineData("username: '", "orlov_cd", "' accepted")]
    [InlineData("вход под логином ", "nikitin_io", " подтверждён")]
    [InlineData("signed in as ", "zaitsev_cd", " from fixture")]
    public void MasksAmbiguousSuffixWithLoginCue(string before, string token, string after)
    {
        using var aliases = new Pseudonymizer(new byte[32], "contextual-login-tests");
        var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
        var engine = new PrivacyEngine(policy, aliases);
        var soft = new SoftPartMasker(aliases, policy, null);
        string input = JsonSerializer.Serialize(new { message = before + token + after });

        var strict = engine.SanitizeJsonForDisplay(input);
        var partial = soft.SanitizeJson(input);
        var typed = engine.SanitizeTypedLogForDisplay(input);
        using var document = JsonDocument.Parse(typed.Text!);
        foreach (string output in new[] { strict.Data!["message"]!.GetValue<string>(),
            partial.Data!["message"]!.GetValue<string>(), document.RootElement.GetProperty("message").GetString()! })
        {
            Assert.StartsWith(before, output);
            Assert.EndsWith(after, output);
            Assert.DoesNotContain(token, output);
        }
        Assert.Equal(1, typed.ReplacementsByType!["PERSON"]);
    }

    /// <summary>Keep the same token intact in technical contexts, including after Unicode decoding.</summary>
    [Theory]
    [InlineData("component=voronov_io; completed")]
    [InlineData("service account: username=voronov_io; completed")]
    [InlineData("технический login=voronov_io; завершено")]
    [InlineData("actor.type=service; login=voronov_io")]
    [InlineData("module.login=voronov_io; completed")]
    [InlineData("login=voronov_io.dll; completed")]
    public void PreservesTechnicalIdentifier(string message)
    {
        using var aliases = new Pseudonymizer(new byte[32], "contextual-login-tests");
        var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
        var engine = new PrivacyEngine(policy, aliases);
        var soft = new SoftPartMasker(aliases, policy, null);
        string input = JsonSerializer.Serialize(new { message });

        Assert.Equal(message, engine.SanitizeJsonForDisplay(input).Data!["message"]!.GetValue<string>());
        Assert.Equal(message, soft.SanitizeJson(input).Data!["message"]!.GetValue<string>());
        Assert.Equal(input, engine.SanitizeTypedLogForDisplay(input).Text);
    }

    /// <summary>Apply the cue inside nested JSON message strings without treating service logins as names.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void UsesDecodedLoginContextInNestedJson(bool service)
    {
        using var aliases = new Pseudonymizer(new byte[32], "contextual-login-tests");
        var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
        var engine = new PrivacyEngine(policy, aliases);
        const string token = "orlov_cd";
        string message = service ? $$"""{"account_type":"service","login":"{{token}}"}"""
            : $$"""{"login":"{{token}}"}""";
        string payload = JsonSerializer.Serialize(new { message, component = token });
        string input = JsonSerializer.Serialize(JsonSerializer.Serialize(payload));

        var result = engine.SanitizeTypedLogForDisplay(input);
        string inner = JsonSerializer.Deserialize<string>(JsonSerializer.Deserialize<string>(result.Text!)!)!;
        using var log = JsonDocument.Parse(inner);
        Assert.Equal(token, log.RootElement.GetProperty("component").GetString());
        using var embedded = JsonDocument.Parse(log.RootElement.GetProperty("message").GetString()!);
        string output = embedded.RootElement.GetProperty("login").GetString()!;
        if (service) Assert.Equal(token, output);
        else
        {
            Assert.NotEqual(token, output);
            Assert.Equal(token.Length, output.Length);
            Assert.Equal('_', output[5]);
            Assert.Equal(1, result.ReplacementsByType!["PERSON"]);
        }
    }
}
