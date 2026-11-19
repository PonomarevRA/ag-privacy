using System.Security.Cryptography;
using System.Text;
using AgPrivacy.Testing;
using Xunit;
namespace AgPrivacy.Tests;
public class FixtureProfileTests
{
    [Fact]
    public void DedicatedSyntheticFixtureProfilePreservesOnlyApprovedFixture()
    {
        const string fixture="SYNTHETIC_TEST_PERSON";
        string hash=Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(fixture)));
        var testProfile=new SyntheticFixtureProfile([hash]);Assert.Equal(fixture,testProfile.Replay(fixture));
        Assert.Throws<InvalidOperationException>(()=>testProfile.Replay("test=true otherData"));
        Assert.Throws<InvalidOperationException>(()=>testProfile.Replay(fixture+" changed"));
        Assert.DoesNotContain(typeof(PrivacyEngine).Assembly.GetReferencedAssemblies(),x=>x.Name=="AgPrivacy.Testing");
    }
}
