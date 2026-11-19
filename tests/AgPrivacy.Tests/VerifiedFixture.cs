using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
namespace AgPrivacy.Tests;
/// <summary>Ephemeral synthetic signer/bundle only. No private key or raw real records persist in the repository.</summary>
internal sealed class VerifiedFixture:IDisposable
{
    internal readonly string Root=Path.Combine(Path.GetTempPath(),"agprivacy-unit-"+Guid.NewGuid().ToString("N"));
    internal readonly ECDsa Signer=ECDsa.Create(ECCurve.NamedCurves.nistP256);
    internal readonly byte[] Key=Enumerable.Repeat((byte)17,32).ToArray();
    internal byte[] PublicKey=>Signer.ExportSubjectPublicKeyInfo();
    internal byte[] Digest=>SHA256.HashData(File.ReadAllBytes(Path.Combine(Root,"ag-privacy.runtime.json")));
    internal VerifiedFixture()
    {
        Directory.CreateDirectory(Root);byte[] policy="{\"schemaVersion\":\"ag-privacy-policy-v1\"}"u8.ToArray();File.WriteAllBytes(Path.Combine(Root,"policy.json"),policy);
        var config=new JsonObject { ["schemaVersion"]="ag-privacy-runtime-v1",["mode"]="strict",["scope"]="synthetic-workspace",["maxInputBytes"]=262144,["maxOutputBytes"]=4194304,
            ["compiledRulesSha256"]=GeneratedRules.Version,["policyFile"]="policy.json",["policySha256"]=Convert.ToHexStringLower(SHA256.HashData(policy)) };
        Write(config);
    }
    internal JsonObject Config()=>JsonNode.Parse(File.ReadAllBytes(Path.Combine(Root,"ag-privacy.runtime.json")))!.AsObject();
    internal void Write(JsonObject config)
    {
        byte[] bytes=Encoding.UTF8.GetBytes(config.ToJsonString());
        File.WriteAllBytes(Path.Combine(Root,"ag-privacy.runtime.json"),bytes);
        File.WriteAllBytes(Path.Combine(Root,"ag-privacy.runtime.sig"),Signer.SignData(bytes,HashAlgorithmName.SHA256,DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    }
    internal void Choose(PrivacyProtectionMode mode)
    {
        var choice=InstallationSettings.SignAfterHumanChoice(File.ReadAllBytes(Path.Combine(Root,"ag-privacy.runtime.json")),mode,Signer);
        File.WriteAllBytes(Path.Combine(Root,"ag-privacy.runtime.json"),choice.Configuration);File.WriteAllBytes(Path.Combine(Root,"ag-privacy.runtime.sig"),choice.Signature);
    }
    internal VerifiedPrivacyModule Open()=>VerifiedPrivacyModule.Load(Root,PublicKey,Key,Digest);
    public void Dispose(){Signer.Dispose();CryptographicOperations.ZeroMemory(Key);Directory.Delete(Root,true);}
}
