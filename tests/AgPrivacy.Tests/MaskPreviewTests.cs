using System.Text.Json;
using Xunit;

namespace AgPrivacy.Tests;

public sealed class MaskPreviewTests
{
    /// <summary>Track masked keys and exact message fragments without marking pre-existing masks or ordinary numbers.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void JsonPreviewMarksActualReplacements(bool soft)
    {
        using var aliases = new Pseudonymizer(new byte[32], "preview-fixture");
        var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
        var engine = new PrivacyEngine(policy, aliases);
        const string input = """
            {"key@example.invalid":null,"password":"fixture","message":"note \"пример\" 😀 to sample@example.invalid",
             "sequence":9007199254740999,"existing":"****"}
            """;
        var result = soft
            ? new SoftPartMasker(aliases, policy).SanitizeJson(input, policy.DisplayFieldExceptions, includePreview: true)
            : engine.SanitizeJsonForDisplay(input, policy.DisplayFieldExceptions, includePreview: true);

        Assert.True(result.Allowed);
        var preview = Assert.IsType<MaskPreview>(result.Preview);
        Assert.Equal(3, result.Replacements);
        Assert.Equal(result.Replacements, preview.Highlights.Count);
        using var parsed = JsonDocument.Parse(preview.Text);
        Assert.Equal(9007199254740999, parsed.RootElement.GetProperty("sequence").GetInt64());
        Assert.Equal("****", parsed.RootElement.GetProperty("existing").GetString());
        Assert.StartsWith("note \"пример\" 😀 to ", parsed.RootElement.GetProperty("message").GetString());
        Assert.StartsWith("[REDACTED:v1:KEY_EMAIL:", Slice(preview, 0));
        Assert.Equal(result.Data!["password"]!.GetValue<string>(), Slice(preview, 1));
        Assert.StartsWith("[REDACTED:v1:EMAIL:", Slice(preview, 2));
        Assert.DoesNotContain("note", Slice(preview, 2));
        Assert.Null(engine.SanitizeJsonForDisplay(input).Preview);
    }

    /// <summary>Use UTF-16 output offsets for substitutions that have no textual mask marker.</summary>
    [Fact]
    public void LogPreviewMarksShapeSubstitutions()
    {
        using var aliases = new Pseudonymizer(new byte[32], "preview-fixture");
        var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
        var engine = new PrivacyEngine(policy, aliases);
        const string input = """
            {"note":"😀","email":"fixture@example.invalid","agreementNumber":"12-451123/26","existing":"****"}
            """;
        var result = engine.SanitizeTypedLogForDisplay(input, includePreview: true);

        Assert.True(result.Allowed);
        var preview = Assert.IsType<MaskPreview>(result.Preview);
        Assert.Equal(result.Text, preview.Text);
        Assert.Equal(2, preview.Highlights.Count);
        Assert.Matches(@"^[a-z]+@[a-z]+\.[a-z]+$", Slice(preview, 0));
        Assert.Matches(@"^\d\d-\d{6}/\d\d$", Slice(preview, 1));
        Assert.DoesNotContain("REDACTED", preview.Text);
    }

    /// <summary>Read one marked range using the same offset units as browser strings.</summary>
    private static string Slice(MaskPreview preview, int index)
    {
        var highlight = preview.Highlights[index];
        return preview.Text.Substring(highlight.Start, highlight.Length);
    }
}
