using System.Text.Encodings.Web;
using System.Text.Json;
using Xunit;

namespace AgPrivacy.Tests;

public sealed class NamedJsonPersonFieldTests
{
    private static readonly PrivacyPolicy Policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);

    /// <summary>Use the decoded field policy independently of the name model and source encoding.</summary>
    [Theory]
    [InlineData(false, false, 0)]
    [InlineData(true, false, 0)]
    [InlineData(false, true, 0)]
    [InlineData(true, true, 0)]
    [InlineData(false, true, 1)]
    [InlineData(true, true, 1)]
    [InlineData(false, true, 2)]
    [InlineData(true, true, 2)]
    [InlineData(false, true, 4)]
    [InlineData(true, true, 4)]
    public void MasksNamedFieldsAndPreservesTheJsonShape(bool mixed, bool escapeUnicode, int wrappers)
    {
        const string name = "Золивексов Артём Игоревич";
        const string first = "Артём";
        const string last = "Золивексов";
        const string patronymic = "Игоревич";
        const string trace = "fixture-trace-stays";
        var fields = new Dictionary<string, object?>
        {
            ["fio"] = name,
            ["ФИО"] = name,
            ["fullName"] = name,
            ["full_name_rus"] = name,
            ["Ф.И.О."] = null,
            ["person"] = new Dictionary<string, string> { ["firstName"] = first, ["surname"] = last, ["patronymic"] = patronymic },
            ["name"] = "Контрольная Очередь",
            ["status"] = "Служебный Контур",
            ["ticker"] = "MOCK",
            ["trace.id"] = trace,
        };
        var options = new JsonSerializerOptions
        {
            Encoder = escapeUnicode ? JavaScriptEncoder.Default : JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };
        string input = JsonSerializer.Serialize(fields, options);
        for (int i = 0; i < wrappers; i++)
            input = JsonSerializer.Serialize(input);
        using var aliases = new Pseudonymizer(new byte[32], "named-person-json");
        var engine = new PrivacyEngine(Policy, aliases);

        var result = mixed
            ? engine.SanitizeTypedLogForDisplay(input, LogAnalysisMode.Mixed, null, null)
            : engine.SanitizeTypedLogForDisplay(input);

        Assert.True(result.Allowed);
        Assert.Equal(7, result.ReplacementsByType!["PERSON"]);
        string output = Assert.IsType<string>(result.Text);
        for (int i = 0; i < wrappers; i++)
            output = JsonSerializer.Deserialize<string>(output)!;
        using var json = JsonDocument.Parse(output);
        var document = json.RootElement;
        foreach (string key in new[] { "fio", "ФИО", "fullName", "full_name_rus" })
        {
            string replacement = document.GetProperty(key).GetString()!;
            Assert.NotEqual(name, replacement);
            Assert.DoesNotContain(last, replacement);
            Assert.DoesNotContain(first, replacement);
            Assert.DoesNotContain(patronymic, replacement);
            Assert.Equal(name.Length, replacement.Length);
        }
        Assert.Equal(JsonValueKind.Null, document.GetProperty("Ф.И.О.").ValueKind);
        var person = document.GetProperty("person");
        Assert.NotEqual(first, person.GetProperty("firstName").GetString());
        Assert.NotEqual(last, person.GetProperty("surname").GetString());
        Assert.NotEqual(patronymic, person.GetProperty("patronymic").GetString());
        Assert.Equal("Контрольная Очередь", document.GetProperty("name").GetString());
        Assert.Equal("Служебный Контур", document.GetProperty("status").GetString());
        Assert.Equal("MOCK", document.GetProperty("ticker").GetString());
        Assert.Equal(trace, document.GetProperty("trace.id").GetString());
    }

    /// <summary>Project named fields from JSON embedded in the middle of a message.</summary>
    [Fact]
    public void MasksAnEscapedFieldWithinAnEmbeddedJsonMessage()
    {
        const string name = "Золивексов Артём";
        const string prefix = "transport summary ";
        const string suffix = " has completed";
        string inner = JsonSerializer.Serialize(new Dictionary<string, string> { ["ФИО"] = name, ["status"] = "ready" });
        string input = JsonSerializer.Serialize(new Dictionary<string, string> { ["message"] = prefix + inner + suffix });
        using var aliases = new Pseudonymizer(new byte[32], "named-person-inline-json");
        var engine = new PrivacyEngine(Policy, aliases);

        var result = engine.SanitizeTypedLogForDisplay(input, LogAnalysisMode.Mixed, null, null);

        Assert.True(result.Allowed);
        using var outer = JsonDocument.Parse(Assert.IsType<string>(result.Text));
        string message = outer.RootElement.GetProperty("message").GetString()!;
        Assert.StartsWith(prefix, message);
        Assert.EndsWith(suffix, message);
        using var decoded = JsonDocument.Parse(message[prefix.Length..^suffix.Length]);
        string value = decoded.RootElement.GetProperty("ФИО").GetString()!;
        Assert.NotEqual(name, value);
        Assert.Equal(name.Length, value.Length);
        Assert.Equal("ready", decoded.RootElement.GetProperty("status").GetString());
    }

    /// <summary>Names configured as another sensitive type keep that rule.</summary>
    [Fact]
    public void HonorsTheCustomFieldPolicy()
    {
        var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1","fields":{"fio":"SECRET","privateContact":"PERSON"}}"""u8);
        using var aliases = new Pseudonymizer(new byte[32], "named-person-policy");
        var engine = new PrivacyEngine(policy, aliases);
        const string input = """{"fio":"xQexample12345","privateContact":"Золивексов Артём","name":"Рабочая Очередь"}""";

        var result = engine.SanitizeTypedLogForDisplay(input, LogAnalysisMode.Mixed, null, null);

        Assert.True(result.Allowed);
        Assert.Equal(1, result.ReplacementsByType!["PERSON"]);
        Assert.Equal(1, result.ReplacementsByType["SECRET"]);
        using var json = JsonDocument.Parse(Assert.IsType<string>(result.Text));
        Assert.Equal("Рабочая Очередь", json.RootElement.GetProperty("name").GetString());
    }
}
