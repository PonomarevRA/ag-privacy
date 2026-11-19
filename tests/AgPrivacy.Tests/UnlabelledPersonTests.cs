using System.Text.Json;
using Xunit;

namespace AgPrivacy.Tests;

public sealed class UnlabelledPersonTests
{
    /// <summary>Mask only the full name or initials inside a message, without relying on a model prediction.</summary>
    [Theory]
    [InlineData("fixture label: ", "yuliya ivanova", "; ready")]
    [InlineData("акт принял ", "ivan petrovich petrov", ", запись закрыта")]
    [InlineData("new event (", "voronovsn", ") received")]
    [InlineData("new event (", "voronov_sn", ") received")]
    [InlineData("new event (", "voronovs", ") received")]
    [InlineData("подпись «", "Соколов РА", "» принята")]
    [InlineData("подпись «", "Соколов Р.A", "» принята")]
    [InlineData("подпись «", "Соколов Р.", "» принята")]
    public void MasksNameWithoutLabel(string before, string name, string after)
    {
        using var aliases = new Pseudonymizer(new byte[32], "unlabelled-person-fixture");
        var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
        var detector = new EmptyPersonDetector();
        var engine = new PrivacyEngine(policy, aliases, detector);
        var soft = new SoftPartMasker(aliases, policy, detector);
        string source = $$"""{"message":"{{before}}{{name}}{{after}}","note":"voronov_sn"}""";

        var strict = engine.SanitizeJsonForDisplay(source);
        var partial = soft.SanitizeJson(source);
        var typed = engine.SanitizeTypedLogForDisplay(source);
        using var typedJson = JsonDocument.Parse(typed.Text!);

        Assert.Equal(1, strict.ReplacementsByType!["PERSON"]);
        Assert.Equal(1, partial.ReplacementsByType!["PERSON"]);
        Assert.Equal(1, typed.ReplacementsByType!["PERSON"]);
        Assert.Equal("voronov_sn", typedJson.RootElement.GetProperty("note").GetString());

        foreach (string output in new[]
        {
            strict.Data!["message"]!.GetValue<string>(),
            partial.Data!["message"]!.GetValue<string>(),
            typedJson.RootElement.GetProperty("message").GetString()!
        })
        {
            Assert.StartsWith(before, output);
            Assert.EndsWith(after, output);
            string replacement = output[before.Length..^after.Length];
            foreach (string word in name.Split(' ')) Assert.DoesNotContain(word, replacement);
        }
    }

    /// <summary>Preserve machine suffixes, path components and ordinary names of services.</summary>
    [Theory]
    [InlineData("job uses voronov_db and voronovci")]
    [InlineData("file opened at /work/voronov_sn/path")]
    [InlineData("method: root.voronov_sn.refresh")]
    [InlineData("health: payment routing service")]
    public void PreservesTechnicalTokens(string message)
    {
        using var aliases = new Pseudonymizer(new byte[32], "unlabelled-person-fixture");
        var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
        var detector = new EmptyPersonDetector();
        var engine = new PrivacyEngine(policy, aliases, detector);
        var soft = new SoftPartMasker(aliases, policy, detector);
        string source = $$"""{"message":"{{message}}"}""";

        Assert.Equal(message, engine.SanitizeJsonForDisplay(source).Data!["message"]!.GetValue<string>());
        Assert.Equal(message, soft.SanitizeJson(source).Data!["message"]!.GetValue<string>());
        Assert.Equal(source, engine.SanitizeTypedLogForDisplay(source).Text);
    }

    private sealed class EmptyPersonDetector : IPersonDetector
    {
        public string Version => "fixture";
        public IReadOnlyList<EntitySpan> Find(string text) => [];
    }
}
