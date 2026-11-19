using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AgPrivacy;
using Xunit;

namespace AgPrivacy.Tests;

public class CoreTests
{
    private static readonly byte[] Key = Enumerable.Range(0,32).Select(i => (byte)i).ToArray();
    private static PrivacyPolicy Policy(string config = "") => PrivacyPolicy.Compile(Encoding.UTF8.GetBytes(config.Length == 0 ? "{\"schemaVersion\":\"ag-privacy-policy-v1\"}" : config));
    private static PrivacyEngine Engine(string config = "", IPersonDetector? model = null) => new(Policy(config), new Pseudonymizer(Key,"test-workspace"), model ?? new EmptyModel());
    private static string Wire(PrivacyResult result) => JsonSerializer.Serialize(result, PrivacyJsonContext.Default.PrivacyResult);
    private sealed class EmptyModel : IPersonDetector { public string Version => "synthetic-no-persons"; public IReadOnlyList<EntitySpan> Find(string _) => []; }

    [Fact]
    public void HmacUsesStandardSha256Vectors()
    {
        byte[] digest = HMACSHA256.HashData(Enumerable.Repeat((byte)0x0b,20).ToArray(), Encoding.ASCII.GetBytes("Hi There"));
        Assert.Equal("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",Convert.ToHexStringLower(digest));
    }

    [Fact]
    public void AliasesAreStableAndDomainSeparated()
    {
        using var a = new Pseudonymizer(Key,"scope-one"); using var b = new Pseudonymizer(Key,"scope-two");
        using var c = new Pseudonymizer(Enumerable.Repeat((byte)7,32).ToArray(),"scope-one");
        string value = "SYNTHETIC_VALUE";
        Assert.Equal(a.Replace("SECRET",value), a.Replace("SECRET",value));
        Assert.NotEqual(a.Replace("SECRET",value), b.Replace("SECRET",value));
        Assert.NotEqual(a.Replace("SECRET",value), c.Replace("SECRET",value));
        Assert.NotEqual(a.Replace("PERSON",value), a.Replace("SECRET",value));
        Assert.DoesNotContain(value,a.Replace("SECRET",value));
        Assert.NotEqual(a.Replace("SECRET","a"),a.Replace("SECRET","A"));
    }

    [Fact]
    public void GuidCanonicalizationAndDisposedKeyAreEnforced()
    {
        var a = new Pseudonymizer(Key,"scope");
        Assert.Equal(a.Replace("GUID","12345678123456789abc123456789abc"),a.Replace("GUID","{12345678-1234-5678-9ABC-123456789ABC}"));
        a.Dispose();Assert.Throws<ObjectDisposedException>(()=>a.Replace("GUID","x"));
        Assert.Throws<ArgumentException>(()=>new Pseudonymizer(new byte[8],"scope"));
    }

    [Theory]
    [InlineData("klogin","q-1234567","KLOGIN")]
    [InlineData("trdacc","SYNTHETIC_ACCOUNT_123","TRDACC")]
    [InlineData("инн","123456789012","INN")]
    [InlineData("КПП","123456789","KPP")]
    [InlineData("lastName","Тестович","PERSON")]
    [InlineData("access_token","short-secret","SECRET")]
    [InlineData("pass\u200bword","short-secret","SECRET")]
    public void TypedJsonHidesEntireValue(string field,string original,string type)
    {
        var input = new System.Text.Json.Nodes.JsonObject { [field]=original };
        var result=Engine().SanitizeJson(input.ToJsonString());string wire=Wire(result);
        Assert.True(result.Allowed);Assert.True(result.SafeForAgent);Assert.True(result.OriginalReplaced);
        Assert.DoesNotContain(original,wire);Assert.Contains("REDACTED:v1:",wire);Assert.DoesNotContain("REDACTED:"+type,wire);
    }

    [Fact]
    public void UnknownKeysNumbersBooleansAndSpoofedMarkersCannotBypassStrict()
    {
        var result=Engine().SanitizeJson("{\"PERSON_NAME_CANARY\":{\"card\":1234567890,\"flag\":true,\"fake\":\"[REDACTED:already]\"}}");
        string wire=Wire(result);Assert.True(result.SafeForAgent);
        foreach(string original in new[]{"PERSON_NAME_CANARY","1234567890","[REDACTED:already]"})Assert.DoesNotContain(original,wire);
        Assert.Contains("REDACTED:v1:",wire);
    }

    [Theory]
    [InlineData("https://example.invalid/page?klogin=q-1234567")]
    [InlineData("https://example.invalid/page?a=b&klogin=q-1234567&x=y")]
    [InlineData("https://example.invalid/page?KLOGIN=q-1234567&klogin=w-987654")]
    [InlineData("https://example.invalid/page?%6Blogin=q%2D1234567")]
    [InlineData("https://example.invalid/page?%256Blogin=q%252D1234567")]
    public void UrlParametersAreParsedBeforeHeuristicOutput(string input)
    {
        var result=Engine().SanitizeText(input,true);string wire=Wire(result);
        Assert.True(result.Allowed);Assert.False(result.SafeForAgent);
        Assert.DoesNotContain("q-1234567",wire);Assert.DoesNotContain("q%2D1234567",wire);Assert.DoesNotContain("q%252D1234567",wire);
        Assert.DoesNotContain("w-987654",wire);Assert.Contains("REDACTED:v1:",wire);
    }

    [Fact]
    public void EncodedAndPlainParameterUseSameCanonicalAlias()
    {
        var engine=Engine();
        Assert.Equal(engine.SanitizeText("?klogin=q-1234567",true).Text,engine.SanitizeText("?klogin=q%2D1234567",true).Text);
    }

    [Theory]
    [InlineData("/clients/q-1234567/accounts/12345678-1234-5678-9abc-123456789abc")]
    [InlineData("Log klogin=q-1234567 trdacc=SYNTHETIC_TRDACC")]
    [InlineData("ИНН:123456789012 КПП:123456789")]
    public void FreeTextAndPathsUseCompiledRules(string input)
    {
        var result=Engine().SanitizeText(input,true);Assert.True(result.Allowed);
        foreach(string original in new[]{"q-1234567","SYNTHETIC_TRDACC","123456789012","123456789","12345678-1234-5678-9abc-123456789abc"})Assert.DoesNotContain(original,Wire(result));
    }

    [Fact]
    public void TablesUseHeadersWithoutRelyingOnValueShape()
    {
        var result=Engine().SanitizeTable(["KLOGIN","TRDACC","ИНН","КПП","ФИО"],new IReadOnlyList<string?>[]{new[]{"not-regex-shaped","ACCOUNT_CANARY","INN_CANARY_NOT_DIGITS","KPP_CANARY_NOT_DIGITS","Имя Канарейка"}});
        Assert.True(result.SafeForAgent);string wire=Wire(result);
        foreach(string original in new[]{"not-regex-shaped","ACCOUNT_CANARY","Имя Канарейка","INN_CANARY_NOT_DIGITS","KPP_CANARY_NOT_DIGITS"})Assert.DoesNotContain(original,wire.Replace("v1",""));
        Assert.Contains("REDACTED:v1:",wire);
        foreach(string type in new[]{"KLOGIN","TRDACC","INN","KPP","PERSON"})Assert.DoesNotContain("REDACTED:"+type,wire);
    }

    [Fact]
    public void TrustedCustomFieldsCompileWithoutRetrainingAndPackageExceptionsAreExact()
    {
        var engine=Engine("{\"schemaVersion\":\"ag-privacy-policy-v1\",\"fields\":{\"deskOwner\":\"PERSON\"},\"publicValues\":{\"packageId\":[\"12345678-1234-5678-9abc-123456789abc\"]}}");
        var a=engine.SanitizeJson("{\"deskOwner\":\"CANARY_PERSON\",\"packageId\":\"12345678-1234-5678-9abc-123456789abc\"}");
        Assert.DoesNotContain("CANARY_PERSON",Wire(a));Assert.Contains("12345678-1234-5678-9abc-123456789abc",Wire(a));
        Assert.DoesNotContain("fedcba98-1234-5678-9abc-123456789abc",Wire(engine.SanitizeJson("{\"packageId\":\"fedcba98-1234-5678-9abc-123456789abc\"}")));
        var table=engine.SanitizeTable(["packageId"],new IReadOnlyList<string?>[]{new[]{"12345678-1234-5678-9abc-123456789abc"}});
        Assert.DoesNotContain("12345678-1234-5678-9abc-123456789abc",Wire(table));
    }

    [Fact]
    public void StrictTextIsWholeValueAndErrorsNeverReturnInput()
    {
        string input="Any unknown person, secret or address CANARY_PAYLOAD";
        var result=Engine().SanitizeText(input);Assert.True(result.SafeForAgent);Assert.DoesNotContain("CANARY_PAYLOAD",Wire(result));
        foreach(string broken in new[]{"{BAD_CANARY", "{\"x\":1,\"x\":2}",new string('Z',PrivacyLimits.InputBytes+1),"\\ud800"})
        {
            var bad=Engine().SanitizeJson(broken);Assert.False(bad.Allowed);Assert.Null(bad.Data);Assert.Null(bad.Text);Assert.DoesNotContain(broken,Wire(bad));
        }
        Assert.False(Engine().SanitizeTable(["klogin"],new IReadOnlyList<string?>[]{Array.Empty<string?>()}).Allowed);
        Assert.False(Engine().SanitizeTable(["klogin","trdacc"],new IReadOnlyList<string?>[]{new[]{new string('x',200000),new string('y',200000)}}).Allowed);
    }
}
