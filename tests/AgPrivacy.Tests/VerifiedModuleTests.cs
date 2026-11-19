using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Xunit;
namespace AgPrivacy.Tests;
public class VerifiedModuleTests
{
    [Fact]
    public void StrictSnapshotIsVerifiedFrozenAndDisposedFailClosed()
    {
        using var f=new VerifiedFixture();using var module=f.Open();
        File.WriteAllText(Path.Combine(f.Root,"policy.json"),"{\"fields\":{\"token\":\"TEXT\"}}");
        const string raw="{\"token\":\"SECRET_CANARY\",\"firstName\":\"PERSON_CANARY\",\"mode\":\"off\"}";
        var result=module.SanitizeJson(raw);Assert.True(result.SafeForAgent);Assert.True(result.MustDiscloseMasking);
        Assert.DoesNotContain("CANARY",result.Data!.ToJsonString());module.Dispose();Assert.False(module.SanitizeJson(raw).Allowed);
    }
    [Theory]
    [InlineData("config")][InlineData("signature")][InlineData("public-key")][InlineData("policy")][InlineData("model")][InlineData("pin")]
    public void EveryTamperedArtifactFailsWithoutInputEcho(string target)
    {
        using var f=new VerifiedFixture();byte[] pin=f.Digest;
        if(target=="config")File.AppendAllText(Path.Combine(f.Root,"ag-privacy.runtime.json")," ");
        if(target=="signature")File.WriteAllBytes(Path.Combine(f.Root,"ag-privacy.runtime.sig"),new byte[64]);
        if(target=="policy")File.AppendAllText(Path.Combine(f.Root,"policy.json")," ");
        if(target=="model")
        {
            var cfg=f.Config();cfg["modelFile"]="person.bin";cfg["modelSha256"]=new string('0',64);f.Write(cfg);pin=f.Digest;File.WriteAllText(Path.Combine(f.Root,"person.bin"),"MODEL_CANARY");
        }
        if(target=="pin")pin=new byte[32];
        using var other=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var error=Assert.Throws<PrivacyConfigurationException>(()=>VerifiedPrivacyModule.Load(f.Root,target=="public-key"?other.ExportSubjectPublicKeyInfo():f.PublicKey,f.Key,pin));
        Assert.Equal("privacy-configuration-blocked",error.Message);Assert.Null(error.InnerException);
    }
    [Theory]
    [InlineData("../outside.json")][InlineData("/tmp/config.json")][InlineData("https://example.invalid/policy")][InlineData("sub\\policy.json")]
    public void SignedPathsCannotEscapeFlatBundle(string path)
    {
        using var f=new VerifiedFixture();var cfg=f.Config();cfg["policyFile"]=path;f.Write(cfg);Assert.Throws<PrivacyConfigurationException>(()=>f.Open());
    }
    [Fact]
    public void SignedDuplicatesUnknownRulesAndModeFlagsAreRejected()
    {
        using var f=new VerifiedFixture();var cfg=f.Config();cfg["disablePrivacy"]=true;f.Write(cfg);Assert.Throws<PrivacyConfigurationException>(()=>f.Open());
        cfg.Remove("disablePrivacy");cfg["mode"]="off";f.Write(cfg);Assert.Throws<PrivacyConfigurationException>(()=>f.Open());
        cfg["mode"]="strict";cfg["compiledRulesSha256"]=new string('a',64);f.Write(cfg);Assert.Throws<PrivacyConfigurationException>(()=>f.Open());
        cfg["compiledRulesSha256"]=GeneratedRules.Version;f.Write(cfg);
        string duplicate=cfg.ToJsonString().Replace("{","{\"mode\":\"strict\",",StringComparison.Ordinal);
        byte[] bytes=Encoding.UTF8.GetBytes(duplicate);File.WriteAllBytes(Path.Combine(f.Root,"ag-privacy.runtime.json"),bytes);
        File.WriteAllBytes(Path.Combine(f.Root,"ag-privacy.runtime.sig"),f.Signer.SignData(bytes,HashAlgorithmName.SHA256,DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        Assert.Throws<PrivacyConfigurationException>(()=>f.Open());
    }
    [Fact]
    public void ConfigMayTightenButNeverRaiseHardBudgets()
    {
        using var f=new VerifiedFixture();var cfg=f.Config();cfg["maxInputBytes"]=32;f.Write(cfg);using var module=f.Open();Assert.False(module.SanitizeJson("{\"x\":\""+new string('x',50)+"\"}").Allowed);
        cfg["maxInputBytes"]=262145;f.Write(cfg);Assert.Throws<PrivacyConfigurationException>(()=>f.Open());
        cfg["maxInputBytes"]=262144;cfg["maxOutputBytes"]=128;f.Write(cfg);using var small=f.Open();Assert.False(small.SanitizeJson("{\"token\":\"CANARY\"}").Allowed);
    }
    [Fact]
    public void OldSignedOffChoiceCannotReplayAfterNewHumanFullChoice()
    {
        using var f=new VerifiedFixture();f.Choose(PrivacyProtectionMode.Off);
        byte[] oldConfig=File.ReadAllBytes(Path.Combine(f.Root,"ag-privacy.runtime.json")),oldSig=File.ReadAllBytes(Path.Combine(f.Root,"ag-privacy.runtime.sig"));
        using(var old=f.Open()){Assert.True(old.SanitizeJson("{\"person\":\"RAW_CANARY\"}").AuthorizedByHumanChoice);}
        f.Choose(PrivacyProtectionMode.Strict);byte[] current=f.Digest;
        File.WriteAllBytes(Path.Combine(f.Root,"ag-privacy.runtime.json"),oldConfig);File.WriteAllBytes(Path.Combine(f.Root,"ag-privacy.runtime.sig"),oldSig);
        Assert.Throws<PrivacyConfigurationException>(()=>VerifiedPrivacyModule.Load(f.Root,f.PublicKey,f.Key,current));
    }
    [Theory]
    [InlineData(PrivacyProtectionMode.Off)][InlineData(PrivacyProtectionMode.CredentialsOnly)]
    public void HumanInstallChoicePersistsAndIsClearlyNotFullPrivacy(PrivacyProtectionMode choice)
    {
        using var f=new VerifiedFixture();f.Choose(choice);using var first=f.Open();using var again=f.Open();
        const string raw="{\"firstName\":\"PERSON_CANARY\",\"password\":\"PASSWORD_CANARY\",\"token\":\"TOKEN_CANARY\",\"forms\":[{\"fields\":[{\"name\":\"login\",\"type\":\"text\",\"value\":\"LOGIN_CANARY\"}]}]}";
        foreach(var module in new[]{first,again})
        {
            var result=module.SanitizeJson(raw);Assert.True(result.Allowed);Assert.False(result.SafeForAgent);Assert.True(result.AuthorizedByHumanChoice);Assert.NotNull(result.AgentNotice);
            string wire=result.Data!.ToJsonString();Assert.Contains("PERSON_CANARY",wire);
            if(choice==PrivacyProtectionMode.Off){Assert.Contains("PASSWORD_CANARY",wire);Assert.Contains("TOKEN_CANARY",wire);Assert.Contains("LOGIN_CANARY",wire);Assert.False(result.MustDiscloseMasking);}
            else{Assert.DoesNotContain("PASSWORD_CANARY",wire);Assert.DoesNotContain("TOKEN_CANARY",wire);Assert.DoesNotContain("LOGIN_CANARY",wire);Assert.True(result.MustDiscloseMasking);}
        }
    }
    [Fact]
    public void MinimalProtectsHtmlFormAndNestedSecretWithoutMaskingOtherPeople()
    {
        using var f=new VerifiedFixture();f.Choose(PrivacyProtectionMode.CredentialsOnly);using var module=f.Open();
        var input=new JsonObject{["html"]="<input value='LOGIN_CANARY' name='username'><input value=\"PASSWORD>CANARY\" type='password'>",["access_token"]=new JsonObject{["raw"]="NESTED_CANARY"},["note"]="Имя Обычное password=LABELED_CANARY"};
        var result=module.SanitizeJson(input.ToJsonString());Assert.True(result.Allowed);string wire=result.Data!.ToJsonString();
        foreach(string value in new[]{"LOGIN_CANARY","PASSWORD","NESTED_CANARY","LABELED_CANARY"})Assert.DoesNotContain(value,wire);
        Assert.Equal("credentials-only",result.ProtectionMode);
    }
    [Fact]
    public void CurrentSignedPinAlsoBindsScopeAndInstallerMode()
    {
        using var f=new VerifiedFixture();f.Choose(PrivacyProtectionMode.CredentialsOnly);byte[] pin=f.Digest;
        f.Choose(PrivacyProtectionMode.Off);Assert.Throws<PrivacyConfigurationException>(()=>VerifiedPrivacyModule.Load(f.Root,f.PublicKey,f.Key,pin));
        var cfg=f.Config();cfg["scope"]="other-product";f.Write(cfg);Assert.Throws<PrivacyConfigurationException>(()=>VerifiedPrivacyModule.Load(f.Root,f.PublicKey,f.Key,pin));
    }
    [Fact]
    public void DisposalRaceNeverReleasesRawOrUsesClearedKey()
    {
        using var f=new VerifiedFixture();using var module=f.Open();
        Parallel.For(0,100,i=>{if(i==0)module.Dispose();else{var r=module.SanitizeJson("{\"token\":\"RACE_CANARY\"}");if(r.Allowed)Assert.DoesNotContain("RACE_CANARY",r.Data!.ToJsonString());}});
    }
}
