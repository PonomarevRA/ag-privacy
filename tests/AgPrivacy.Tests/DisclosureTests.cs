using System.Text;
using AgPrivacy;
using Xunit;
namespace AgPrivacy.Tests;
public class DisclosureTests
{
    private static readonly PrivacyContext Context=new("product","chat","task");
    private static PrivacyPolicy Policy()=>PrivacyPolicy.Compile(Encoding.UTF8.GetBytes("{\"schemaVersion\":\"ag-privacy-policy-v1\"}"));
    private sealed class Clock:TimeProvider {public DateTimeOffset Now=DateTimeOffset.FromUnixTimeSeconds(1800000000);public override DateTimeOffset GetUtcNow()=>Now;}
    [Fact]
    public void GrantBindsExactUnitTaskChatProductPolicyAndExpiry()
    {
        const string raw="{\"inn\":\"991234567890\",\"kpp\":\"991234567\",\"token\":\"SECRET_CANARY\"}";
        var clock=new Clock();var policy=Policy();using var authority=new DisclosureAuthority(new byte[32],clock);
        string token=authority.IssueAfterHumanApproval(Context,["inn"],"test",policy,TimeSpan.FromMinutes(5),DisclosureDocument.Json(raw));
        var grant=authority.Validate(token,Context,policy);Assert.NotNull(grant);
        Assert.Null(authority.Validate(token,Context with {ChatId="other"},policy));
        using var key=new Pseudonymizer(new byte[32],"test");var engine=new PrivacyEngine(policy,key,disclosure:grant);
        var result=engine.SanitizeJson(raw,Context);string wire=result.Data!.ToJsonString();
        Assert.Contains("991234567890",wire);Assert.DoesNotContain("991234567\"",wire);Assert.DoesNotContain("SECRET_CANARY",wire);
        Assert.Equal(new[]{"inn"},result.DisclosedFields);
        Assert.DoesNotContain("991234567890",engine.SanitizeJson(raw).Data!.ToJsonString());
        Assert.DoesNotContain("991234567890",engine.SanitizeJson(raw,Context with {TaskId="other"}).Data!.ToJsonString());
        Assert.DoesNotContain("991234567890",engine.SanitizeJson(raw,Context with {ChatId="other"}).Data!.ToJsonString());
        Assert.DoesNotContain("991234567890",engine.SanitizeJson(raw,Context with {ProductId="other"}).Data!.ToJsonString());
        Assert.DoesNotContain("991234567890",engine.SanitizeJson(raw+" ",Context).Data!.ToJsonString());
        var different=PrivacyPolicy.Compile(Encoding.UTF8.GetBytes("{\"schemaVersion\":\"ag-privacy-policy-v1\",\"fields\":{\"desk\":\"TEXT\"}}"));
        Assert.DoesNotContain("991234567890",new PrivacyEngine(different,key,disclosure:grant).SanitizeJson(raw,Context).Data!.ToJsonString());
        clock.Now=clock.Now.AddMinutes(6);Assert.Null(authority.Validate(token,Context,policy));Assert.DoesNotContain("991234567890",engine.SanitizeJson(raw,Context).Data!.ToJsonString());
    }
    [Fact]
    public void TableApprovalCannotBeReusedForRenamedOrChangedCells()
    {
        var headers=new[]{"ИНН","КПП","token"};IReadOnlyList<IReadOnlyList<string?>> rows=new IReadOnlyList<string?>[]{new[]{"991234567890","991234567","SECRET_CANARY"}};
        var policy=Policy();using var authority=new DisclosureAuthority(new byte[32]);
        string token=authority.IssueAfterHumanApproval(Context,["inn","kpp"],"test",policy,TimeSpan.FromMinutes(5),DisclosureDocument.Table(headers,rows));
        using var key=new Pseudonymizer(new byte[32],"test");var engine=new PrivacyEngine(policy,key,disclosure:authority.Validate(token,Context,policy));
        string wire=engine.SanitizeTable(headers,rows,Context).Data!.ToJsonString();Assert.Contains("991234567890",wire);Assert.DoesNotContain("SECRET_CANARY",wire);
        var changed=new IReadOnlyList<string?>[]{new[]{"998765432100","991234567","SECRET_CANARY"}};
        Assert.DoesNotContain("998765432100",engine.SanitizeTable(headers,changed,Context).Data!.ToJsonString());
        Assert.Throws<ArgumentException>(()=>authority.IssueAfterHumanApproval(Context,["token"],"test",policy,TimeSpan.FromMinutes(5),DisclosureDocument.Table(headers,rows)));
        Assert.Throws<ArgumentException>(()=>authority.IssueAfterHumanApproval(Context,["inn"],"test",policy,TimeSpan.FromHours(2),DisclosureDocument.Table(headers,rows)));
    }
}
