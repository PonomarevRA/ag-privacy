using System.Text;
using AgPrivacy;
using Xunit;
namespace AgPrivacy.Tests;

public class ArbitrationTests
{
    private sealed class NoPersons : IPersonDetector { public string Version=>"test"; public IReadOnlyList<EntitySpan> Find(string _) => []; }
    [Theory]
    [InlineData("password=SECRET_BODY_CANARY")]
    [InlineData("https://example.invalid/?x=SECRET_BODY_CANARY")]
    public void OverlapCannotExposeAnyPartOfRecognizedPrivateKey(string inner)
    {
        using var aliases=new Pseudonymizer(Enumerable.Repeat((byte)8,32).ToArray(),"test");
        var policy=PrivacyPolicy.Compile(Encoding.UTF8.GetBytes("{\"schemaVersion\":\"ag-privacy-policy-v1\"}"));
        var engine=new PrivacyEngine(policy,aliases,new NoPersons());
        string input="before -----BEGIN PRIVATE KEY-----\nPEM_START_CANARY\n"+inner+"\nPEM_END_CANARY\n-----END PRIVATE KEY----- after";
        var output=engine.SanitizeText(input,true);Assert.True(output.Allowed);
        foreach(string original in new[]{"PRIVATE KEY","PEM_START_CANARY","SECRET_BODY_CANARY","PEM_END_CANARY"})Assert.DoesNotContain(original,output.Text);
        Assert.StartsWith("before [REDACTED:v1:",output.Text);Assert.EndsWith("] after",output.Text);
    }

    [Fact]
    public void ConcurrentDisposalCannotComputeAnAliasWithClearedKey()
    {
        byte[] key=Enumerable.Repeat((byte)9,32).ToArray();
        using var expected=new Pseudonymizer(key,"test");string alias=expected.Replace("SECRET","VALUE_CANARY");
        for(int round=0;round<30;round++)
        {
            var current=new Pseudonymizer(key,"test");
            Parallel.For(0,32,i=>
            {
                if(i==0){current.Dispose();return;}
                try { Assert.Equal(alias,current.Replace("SECRET","VALUE_CANARY")); }
                catch(ObjectDisposedException) { }
            });current.Dispose();
        }
    }
}
