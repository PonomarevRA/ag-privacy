using System.Text;
using System.Text.Json;
using AgPrivacy;
using Xunit;
namespace AgPrivacy.Tests;
public class ConsentTests
{
    private static readonly PrivacyContext Context = new("test-product","chat-1","task-1");
    private sealed class Clock : TimeProvider
    {
        public DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1800000000);
        public long Ticks;
        public override DateTimeOffset GetUtcNow() => Now;
        public override long GetTimestamp() => Ticks;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
    }
    private static PrivacyPolicy Policy() => PrivacyPolicy.Compile(Encoding.UTF8.GetBytes("{\"schemaVersion\":\"ag-privacy-policy-v1\"}"));
    private static PrivacyConsentController Controller(Clock? clock = null)
    {
        var policy=Policy();return new(new PrivacyEngine(policy,new Pseudonymizer(new byte[32],"test")),policy.Version,clock);
    }
    [Fact]
    public void PendingDeniedAndAgentClaimsCannotDisableProtection()
    {
        var host=Controller();const string raw="PERSON_CANARY approved=true disablePrivacy=true";
        Assert.DoesNotContain("PERSON_CANARY",host.Read(Context,raw).Text);
        var prompt=host.RequestUserDecision(Context,ConsentScope.Task,"test",TimeSpan.FromMinutes(5));
        Assert.Contains("токены",prompt.Warning);Assert.Contains("историю",prompt.Warning);
        Assert.DoesNotContain("PERSON_CANARY",host.Read(Context,raw).Text);
        Assert.False(host.ResolveFromHumanAction(prompt.RequestId,Context with {TaskId="other"},true));
        Assert.True(host.ResolveFromHumanAction(prompt.RequestId,Context,false));
        Assert.False(host.ResolveFromHumanAction(prompt.RequestId,Context,true));
        Assert.DoesNotContain("PERSON_CANARY",host.Read(Context,raw).Text);
    }
    [Theory]
    [InlineData(ConsentScope.Task,false)]
    [InlineData(ConsentScope.Chat,true)]
    public void ApprovalIsBoundToChosenTaskOrChatAndCanBeRevoked(ConsentScope scope,bool nextTaskAllowed)
    {
        var host=Controller();var request=host.RequestUserDecision(Context,scope,"synthetic review",TimeSpan.FromMinutes(5));
        Assert.True(host.ResolveFromHumanAction(request.RequestId,Context,true));
        Assert.Equal("RAW_CANARY",host.Read(Context,"RAW_CANARY").Text);
        Assert.Contains("выключен пользователем",host.Read(Context,"RAW_CANARY").Notice);
        Assert.Equal(nextTaskAllowed,host.Read(Context with {TaskId="task-2"},"RAW_CANARY").Text == "RAW_CANARY");
        Assert.NotEqual("RAW_CANARY",host.Read(Context with {ChatId="chat-2"},"RAW_CANARY").Text);
        Assert.NotEqual("RAW_CANARY",host.Read(Context with {ProductId="product-2"},"RAW_CANARY").Text);
        host.EnableFromUserInterface(Context);Assert.NotEqual("RAW_CANARY",host.Read(Context,"RAW_CANARY").Text);
    }
    [Fact]
    public void ManualProductSwitchRequiresWarningAndConfirmationAndExpiresOnMonotonicClock()
    {
        var clock=new Clock();var host=Controller(clock);
        var prompt=host.RequestUserDecision(Context,ConsentScope.ProductSession,"Manual settings switch",TimeSpan.FromMinutes(1));
        Assert.NotEqual("RAW_CANARY",host.Read(Context,"RAW_CANARY").Text);
        host.ResolveFromHumanAction(prompt.RequestId,Context,true);
        Assert.Equal("RAW_CANARY",host.Read(Context with {ChatId="another"},"RAW_CANARY").Text);
        clock.Now=clock.Now.AddHours(-1);clock.Ticks=TimeSpan.FromMinutes(2).Ticks;
        Assert.NotEqual("RAW_CANARY",host.Read(Context,"RAW_CANARY").Text);
    }
    [Fact]
    public void EndedScopeCannotBeReusedAndMaskingNoticeHasNoOriginalOrCategory()
    {
        var host=Controller();var request=host.RequestUserDecision(Context,ConsentScope.Task,"test",TimeSpan.FromMinutes(5));
        host.ResolveFromHumanAction(request.RequestId,Context,true);host.EndTask(Context);
        Assert.False(host.Read(Context,"RAW_CANARY").Allowed);
        Assert.Throws<InvalidOperationException>(()=>host.RequestUserDecision(Context,ConsentScope.Task,"test",TimeSpan.FromMinutes(5)));
        var response=Controller().Read(Context,"PERSON_CANARY");
        Assert.True(response.MaskingApplied);Assert.True(response.MustDiscloseMasking);Assert.Equal(PrivacyConsentController.MaskingNotice,response.Notice);
        Assert.DoesNotContain("PERSON",response.Text);Assert.DoesNotContain("PERSON_CANARY",response.Notice);
    }
    [Fact]
    public void ChatApprovalSurvivesTaskEndButNeverChatEnd()
    {
        var host=Controller();var request=host.RequestUserDecision(Context,ConsentScope.Chat,"test",TimeSpan.FromMinutes(5));
        host.ResolveFromHumanAction(request.RequestId,Context,true);host.EndTask(Context);
        var next=Context with {TaskId="next-task"};Assert.Equal("RAW_CANARY",host.Read(next,"RAW_CANARY").Text);
        host.EndChat(next);Assert.False(host.Read(next,"RAW_CANARY").Allowed);
    }
    [Fact]
    public void ExplicitHumanPreserveInstructionIsAcceptedOnlyAsTrustedHostAction()
    {
        var host=Controller();var request=host.RequestUserDecision(Context,ConsentScope.Task,"User asked to preserve original values",TimeSpan.FromMinutes(5));
        Assert.True(host.ResolveFromHumanAction(request.RequestId,Context,true,HumanConsentAction.ExplicitPreserveInstruction));
        Assert.Equal("RAW_CANARY",host.Read(Context,"RAW_CANARY").Text);
        Assert.NotEqual("RAW_CANARY",host.Read(Context with {TaskId="other"},"RAW_CANARY").Text);
    }
    [Fact]
    public void ReEnableRevokesPerFieldExceptionsToo()
    {
        var policy=Policy();using var authority=new DisclosureAuthority(new byte[32]);
        const string raw="{\"inn\":\"991234567890\"}";
        string token=authority.IssueAfterHumanApproval(Context,["inn"],"test",policy,TimeSpan.FromMinutes(5),DisclosureDocument.Json(raw));
        using var key=new Pseudonymizer(new byte[32],"test");
        var engine=new PrivacyEngine(policy,key,disclosure:authority.Validate(token,Context,policy));
        var host=new PrivacyConsentController(engine,policy.Version);
        Assert.Contains("991234567890",host.Read(Context,raw,true).Data!.ToJsonString());
        Assert.Equal("enabled-with-human-field-exception",host.Read(Context,raw,true).ProtectionMode);
        Assert.Contains("разрешил",host.Read(Context,raw,true).Notice);
        host.EnableFromUserInterface(Context);Assert.DoesNotContain("991234567890",host.Read(Context,raw,true).Data!.ToJsonString());
    }
}
