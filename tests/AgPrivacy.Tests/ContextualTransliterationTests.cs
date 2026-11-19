using System.Text.Encodings.Web;
using System.Text.Json;
using Xunit;

namespace AgPrivacy.Tests;

public sealed class ContextualTransliterationTests
{
    /// <summary>Accept lexicon alternatives in a personal context while retaining identical technical tokens.</summary>
    [Theory]
    [InlineData("Alina Solovieva")]
    [InlineData("Yury Kozlov")]
    [InlineData("Valery Egorov")]
    [InlineData("soloviev_rk")]
    [InlineData("ilin_rk")]
    public void MasksAlternateSpellingOnlyInPersonContext(string value)
    {
        using var aliases = new Pseudonymizer(new byte[32], "context-transliteration-test");
        var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
        var engine = new PrivacyEngine(policy, aliases);
        var relaxed = new JsonSerializerOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

        foreach (var options in new JsonSerializerOptions?[] { null, relaxed })
        {
            var personal = engine.SanitizeTypedLogForDisplay(JsonSerializer.Serialize(new
            {
                message = $"Заявка; recipient: {value}; status=ready"
            }, options));
            var technical = engine.SanitizeTypedLogForDisplay(JsonSerializer.Serialize(new
            {
                message = $"Заявка; pipeline alias: {value}; status=ready"
            }, options));

            Assert.True(personal.Allowed && technical.Allowed);
            using var personalJson = JsonDocument.Parse(personal.Text!);
            using var technicalJson = JsonDocument.Parse(technical.Text!);
            string message = personalJson.RootElement.GetProperty("message").GetString()!;
            Assert.StartsWith("Заявка; recipient: ", message);
            Assert.EndsWith("; status=ready", message);
            Assert.False(message.Contains(value, StringComparison.Ordinal));
            Assert.True(technicalJson.RootElement.GetProperty("message").GetString() == $"Заявка; pipeline alias: {value}; status=ready");
        }
    }
}
