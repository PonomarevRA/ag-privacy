using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Xunit;

namespace AgPrivacy.Tests;

public sealed class ContextualStreamModelTests
{
    /// <summary>Apply the configured model inside JSON messages and leave other JSON fields intact.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task UsesModelForNovelSurnameInMessage(bool escaped)
    {
        const string value = "Анна Сарвелин";
        var options = new JsonSerializerOptions
        {
            Encoder = escaped ? JavaScriptEncoder.Default : JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };
        string json = JsonSerializer.Serialize(new { message = "Заявитель: " + value + "; запись закрыта", status = "ready" }, options);

        using var rules = JsonDocument.Parse(await MaskAsync(json, null));
        Assert.Contains(value, rules.RootElement.GetProperty("message").GetString());

        using var result = JsonDocument.Parse(await MaskAsync(json, LoadModel()));
        string message = result.RootElement.GetProperty("message").GetString()!;
        Assert.StartsWith("Заявитель: ", message);
        Assert.EndsWith("; запись закрыта", message);
        Assert.DoesNotContain("Сарвелин", message);
        Assert.Equal("ready", result.RootElement.GetProperty("status").GetString());
    }

    /// <summary>Preserve a service username while still masking a secret in the same message.</summary>
    [Theory]
    [InlineData("service account login=")]
    [InlineData("техническая учётная запись логин=")]
    public async Task PreservesExplicitServiceLogin(string qualifier)
    {
        const string serviceLogin = "voronov_ra";
        const string secret = "fixtureOnlyKey2";
        string json = JsonSerializer.Serialize(new { message = qualifier + serviceLogin + "; api-key=" + secret });
        using var result = JsonDocument.Parse(await MaskAsync(json, LoadModel()));
        string message = result.RootElement.GetProperty("message").GetString()!;
        Assert.StartsWith(qualifier + serviceLogin, message);
        Assert.DoesNotContain(secret, message);
    }

    private static MicroPersonModel LoadModel() => MicroPersonModel.Load(
        File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "person-default.bin")));

    /// <summary>Exercise the real stream writer with synthetic input.</summary>
    private static async Task<string> MaskAsync(string json, MicroPersonModel? model)
    {
        using var aliases = new Pseudonymizer(new byte[32], "stream-person-model-test");
        var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
        using var source = new MemoryStream(Encoding.UTF8.GetBytes(json));
        using var target = new MemoryStream();
        await new StreamingPrivacyMasker(policy, aliases, model).MaskAsync(source, target);
        return Encoding.UTF8.GetString(target.ToArray());
    }
}
