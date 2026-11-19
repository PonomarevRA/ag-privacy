using System.Text.Json;
using System.Text.RegularExpressions;
using Xunit;

namespace AgPrivacy.Tests;

public sealed class GuidMaskingTests
{
    private const string Topic = "00000000-0000-4000-8000-000000000001";
    private const string Id = "00000000-0000-4000-8000-000000000002";
    private const string Master = "00000000-0000-4000-8000-000000000003";

    /// <summary>Check keys and values without changing the original log framing or the MasterId exception.</summary>
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public void MasksJsonAtEachEscapeDepth(int depth)
    {
        using var aliases = new Pseudonymizer(new byte[32], "guid-display-tests");
        var engine = CreateEngine(aliases);
        string bracedTopic = "{" + Topic + "}";
        string bracedMaster = "{" + Master + "}";
        string json = $$$$"""
            {"Records":{"{{{{bracedTopic}}}}":{"Id":"{{{{Id}}}}","MasterId":"{{{{bracedMaster}}}}","RelatedId":"{{{{Master}}}}","Name":"Topic fixture","Parent":null}}}
            """;
        const string method = "/Demo.RecordsService/GetRecords";
        string prefix = $"Unary-запрос {Encode(method, 2)} обработан за \"1\" мс. Ответ: ";
        var result = engine.SanitizeGuidsForDisplay(prefix + Encode(json, depth));

        Assert.True(result.Allowed);
        Assert.False(result.SafeForAgent);
        Assert.Equal("guid-only", result.ProtectionMode);
        Assert.Equal(3, result.Replacements);
        string clean = result.Text!;
        Assert.StartsWith(prefix, clean);
        string payload = clean[prefix.Length..];
        for (int i = 0; i < depth; i++) payload = JsonSerializer.Deserialize<string>(payload)!;
        using var document = JsonDocument.Parse(payload);
        var topic = Assert.Single(document.RootElement.GetProperty("Records").EnumerateObject());
        Assert.Matches(@"^\{\[REDACTED:v1:GUID:[0-9a-f]{64}\]\}$", topic.Name);
        Assert.Matches(@"^\[REDACTED:v1:GUID:[0-9a-f]{64}\]$", topic.Value.GetProperty("Id").GetString()!);
        Assert.Equal("{" + Master + "}", topic.Value.GetProperty("MasterId").GetString());
        Assert.StartsWith("[REDACTED:v1:GUID:", topic.Value.GetProperty("RelatedId").GetString());
        Assert.Equal("Topic fixture", topic.Value.GetProperty("Name").GetString());
        Assert.Equal(JsonValueKind.Null, topic.Value.GetProperty("Parent").ValueKind);

        // Compare against the exact original encoding with just the three matching intervals changed.
        string expected = json.Replace(Topic, topic.Name[1..^1], StringComparison.Ordinal)
            .Replace(Id, topic.Value.GetProperty("Id").GetString(), StringComparison.Ordinal)
            .Replace($"\"RelatedId\":\"{Master}\"", $"\"RelatedId\":\"{topic.Value.GetProperty("RelatedId").GetString()}\"", StringComparison.Ordinal);
        Assert.Equal(prefix + Encode(expected, depth), clean);
    }

    /// <summary>Canonicalize dashed and compact forms, and restrict the exception to whole property values.</summary>
    [Fact]
    public void AliasesStayStableAndExceptionIsLocal()
    {
        using var aliases = new Pseudonymizer(new byte[32], "guid-display-tests");
        var engine = CreateEngine(aliases);
        const string guid = "abcdef00-0000-4000-8000-000000000000";
        string compact = guid.Replace("-", "", StringComparison.Ordinal).ToUpperInvariant();
        string input = $$"""
            {"masterid":"{{compact}}","OtherMasterId":"{{guid}}","nested":{"MasterId":"extra {{guid}}"},"{{guid}}":"{{compact}}","label":"{GUID_UUID_1}"}
            """;

        var result = engine.SanitizeGuidsForDisplay(input);
        Assert.Equal(4, result.Replacements);
        var markers = Regex.Matches(result.Text!, @"\[REDACTED:v1:GUID:[0-9a-f]{64}\]");
        Assert.Equal(4, markers.Count);
        Assert.All(markers, marker => Assert.Equal(markers[0].Value, marker.Value));
        Assert.Contains($"\"masterid\":\"{compact}\"", result.Text);
        Assert.Contains("{GUID_UUID_1}", result.Text);
        Assert.DoesNotContain(guid, result.Text);
    }

    /// <summary>Match the synthetic log serializer's quote escaping without relying on a raw input file.</summary>
    private static string Encode(string text, int depth)
    {
        for (int i = 0; i < depth; i++)
            text = JsonSerializer.Serialize(text, new JsonSerializerOptions
            {
                Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
            });
        return text;
    }

    private static PrivacyEngine CreateEngine(Pseudonymizer aliases) =>
        new(PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8), aliases);
}
