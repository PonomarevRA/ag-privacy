using System.Text;
using System.Text.Json;
using Xunit;

namespace AgPrivacy.Tests;

public sealed class RetrainedLogPersonTests
{
    [Theory]
    [InlineData("универсальный адаптер подтвердила следующий визит.")]
    [InlineData("модуль сверки попросил копию уведомления.")]
    public async Task PreservesTechnicalSubjectsBesidePersonActions(string message)
    {
        string result = await MaskAsync(message, new SuggestsEverything());
        Assert.Equal(message, result);
    }

    [Fact]
    public async Task AppliesConfiguredProseModelToAnExplicitPersonalLogin()
    {
        const string transliteration = "soloviev_io";
        const string before = "Заметка; сотрудник логин=";
        const string after = "; проверка завершена";
        var detector = new SuggestsExactLogin(transliteration);
        string personal = await MaskAsync(before + transliteration + after, detector);
        Assert.StartsWith(before, personal);
        Assert.EndsWith(after, personal);
        Assert.DoesNotContain(transliteration, personal);
        Assert.True(detector.SawCandidate);
        string service = "Служебная проверка; system account login=" + transliteration + after;
        Assert.Equal(service, await MaskAsync(service, detector));
    }

    /// <summary>Exercise the typed streaming path with decoded Cyrillic and verify its correlation field.</summary>
    private static async Task<string> MaskAsync(string message, IPersonDetector prose)
    {
        using var aliases = new Pseudonymizer(new byte[32], "retrained-person-fixture");
        var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
        const string trace = "fixture-trace-17";
        string json = JsonSerializer.Serialize(new Dictionary<string, string> { ["message"] = message, ["trace.id"] = trace });
        using var input = new MemoryStream(Encoding.UTF8.GetBytes(json + "\n"));
        using var output = new MemoryStream();
        var stream = new StreamingPrivacyMasker(policy, aliases, null, null, null, null, prose);
        await stream.MaskAsync(input, output);
        using var result = JsonDocument.Parse(output.ToArray());
        Assert.Equal(trace, result.RootElement.GetProperty("trace.id").GetString());
        return result.RootElement.GetProperty("message").GetString()!;
    }

    private sealed class SuggestsEverything : IPersonDetector
    {
        public string Version => "test";
        public IReadOnlyList<EntitySpan> Find(string text) => [new(0, text.Length, "PERSON")];
    }

    private sealed class SuggestsExactLogin(string login) : IPersonDetector
    {
        public string Version => "test";
        public bool SawCandidate { get; private set; }
        public IReadOnlyList<EntitySpan> Find(string text)
        {
            int offset = text.IndexOf(login, StringComparison.Ordinal);
            if (offset < 0) return [];
            SawCandidate = true;
            return [new(offset, login.Length, "PERSON")];
        }
    }
}
