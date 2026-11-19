using System.Security.Cryptography;
using System.Text.Json;
namespace AgPrivacy;

/// <summary>Signed runtime settings. Signature trust comes only from the caller-pinned public key, never a key inside the mutable bundle.</summary>
public sealed record VerifiedProfile(PrivacyProtectionMode Mode,string Scope,int MaxInputBytes,int MaxOutputBytes,string PolicyFile,string PolicySha256,string? ModelFile,string? ModelSha256)
{
    public const int MaximumConfigBytes=16384;
    public const int MaximumOutputBytes=4*1024*1024;
    /// <summary>Verify exact bytes first, then validate a closed schema. Non-strict modes require signed installer attestation. No network/plugin/heuristic settings are accepted.</summary>
    public static VerifiedProfile Verify(ReadOnlySpan<byte> config,ReadOnlySpan<byte> signature,ReadOnlySpan<byte> pinnedPublicKey)
    {
        if(config.Length is 0 or >MaximumConfigBytes || signature.Length!=64 || pinnedPublicKey.Length is 0 or >512)throw new PrivacyConfigurationException();
        using var verifier=ECDsa.Create();verifier.ImportSubjectPublicKeyInfo(pinnedPublicKey,out int consumed);
        if(consumed!=pinnedPublicKey.Length || verifier.KeySize!=256 || verifier.ExportParameters(false).Curve.Oid.Value!=ECCurve.NamedCurves.nistP256.Oid.Value || !verifier.VerifyData(config,signature,HashAlgorithmName.SHA256,DSASignatureFormat.IeeeP1363FixedFieldConcatenation))throw new PrivacyConfigurationException();
        using var doc=JsonDocument.Parse(config.ToArray(),new JsonDocumentOptions{MaxDepth=4});
        var value=doc.RootElement;var seen=new HashSet<string>(StringComparer.Ordinal);
        string[] allowed=["schemaVersion","mode","scope","maxInputBytes","maxOutputBytes","compiledRulesSha256","policyFile","policySha256","modelFile","modelSha256","humanSetupChoice"];
        if(value.ValueKind!=JsonValueKind.Object)throw new PrivacyConfigurationException();
        foreach(var property in value.EnumerateObject())if(!allowed.Contains(property.Name) || !seen.Add(property.Name))throw new PrivacyConfigurationException();
        if(value.GetProperty("schemaVersion").GetString()!="ag-privacy-runtime-v1" || value.GetProperty("compiledRulesSha256").GetString()!=GeneratedRules.Version)throw new PrivacyConfigurationException();
        string modeName=value.GetProperty("mode").GetString()!;
        var mode=modeName switch {"strict"=>PrivacyProtectionMode.Strict,"credentials-only"=>PrivacyProtectionMode.CredentialsOnly,"off"=>PrivacyProtectionMode.Off,_=>throw new PrivacyConfigurationException()};
        bool approved=value.TryGetProperty("humanSetupChoice",out var choice);
        if((mode!=PrivacyProtectionMode.Strict&&!approved)||(approved&&choice.GetString()!=modeName))throw new PrivacyConfigurationException();
        string scope=value.GetProperty("scope").GetString()!;
        int input=value.GetProperty("maxInputBytes").GetInt32(),output=value.GetProperty("maxOutputBytes").GetInt32();
        if(string.IsNullOrWhiteSpace(scope) || scope.Length>128 || input<1 || input>PrivacyLimits.InputBytes || output<128 || output>MaximumOutputBytes)throw new PrivacyConfigurationException();
        string policy=FileName(value.GetProperty("policyFile").GetString());
        string policyHash=Digest(value.GetProperty("policySha256").GetString());
        string? model=null,modelHash=null;
        bool hasModel=value.TryGetProperty("modelFile",out var modelValue),hasModelHash=value.TryGetProperty("modelSha256",out var hashValue);
        if(hasModel!=hasModelHash)throw new PrivacyConfigurationException();
        if(hasModel){model=FileName(modelValue.GetString());modelHash=Digest(hashValue.GetString());}
        if(model==policy)throw new PrivacyConfigurationException();
        return new(mode,scope,input,output,policy,policyHash,model,modelHash);
    }
    /// <summary>Only flat artifact names, no paths/URLs/traversal or config self-reference.</summary>
    private static string FileName(string? value)
    {
        if(value is null || value.Length is 0 or >96 || value.Contains("..") || value[0]=='.' || value.Any(c=>!(char.IsAsciiLetterOrDigit(c)||c is '-' or '_' or '.')) || value is "ag-privacy.runtime.json" or "ag-privacy.runtime.sig")throw new PrivacyConfigurationException();
        return value;
    }
    private static string Digest(string? value)
    {
        if(value is null || value.Length!=64 || value.Any(c=>!char.IsAsciiHexDigit(c)))throw new PrivacyConfigurationException();
        return value.ToLowerInvariant();
    }
}
/// <summary>Fixed failure metadata; never attach untrusted config, filenames, parser details or inner exceptions.</summary>
public sealed class PrivacyConfigurationException:Exception
{
    public PrivacyConfigurationException():base("privacy-configuration-blocked"){}
}
