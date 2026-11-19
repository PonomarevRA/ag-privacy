using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
namespace AgPrivacy;

/// <summary>Reusable, verified, data plane with signed human install choices. Frozen policy/model snapshots; no runtime control-plane or agent-origin settings.</summary>
public sealed class VerifiedPrivacyModule:IDisposable
{
    private readonly object sync=new();
    private readonly Pseudonymizer aliases;
    private readonly PrivacyEngine engine;
    private readonly VerifiedProfile profile;
    private bool disposed;
    public PrivacyProtectionMode Mode=>profile.Mode;
    private readonly PrivacyPolicy policy;
    public int MaxInputBytes=>profile.MaxInputBytes;
    public string PolicyVersion {get;}
    public string ModelVersion {get;}
    private VerifiedPrivacyModule(VerifiedProfile profile,PrivacyPolicy policy,IPersonDetector? model,ReadOnlySpan<byte> key)
    {
        this.profile=profile;this.policy=policy;aliases=new(key,profile.Scope);engine=new(policy,aliases,model);
        PolicyVersion=policy.Version;ModelVersion=model?.Version??"none";
    }
    /// <summary>Load one bounded signed snapshot. Public key and current approved config SHA256 must be pinned outside this writable directory; this prevents old signed mode replay. Missing/invalid artifacts never fall back.</summary>
    public static VerifiedPrivacyModule Load(string directory,ReadOnlySpan<byte> pinnedPublicKey,ReadOnlySpan<byte> key,ReadOnlySpan<byte> approvedConfigurationSha256)
    {
        try
        {
            string root=Path.GetFullPath(directory);
            if((OperatingSystem.IsWindows()&&root.StartsWith(@"\\",StringComparison.Ordinal)) || !Directory.Exists(root) || new DirectoryInfo(root).LinkTarget is not null)throw new PrivacyConfigurationException();
            byte[] config=ReadArtifact(root,"ag-privacy.runtime.json",VerifiedProfile.MaximumConfigBytes);
            if(approvedConfigurationSha256.Length!=32 || !CryptographicOperations.FixedTimeEquals(SHA256.HashData(config),approvedConfigurationSha256))throw new PrivacyConfigurationException();
            byte[] signature=ReadArtifact(root,"ag-privacy.runtime.sig",64);
            var profile=VerifiedProfile.Verify(config,signature,pinnedPublicKey);
            // The same verified byte arrays are compiled/loaded, never a second read of a mutable path.
            byte[] policyBytes=ReadVerified(root,profile.PolicyFile,65536,profile.PolicySha256);
            var policy=PrivacyPolicy.Compile(policyBytes);
            IPersonDetector? model=null;
            if(profile.ModelFile is not null)
            {
                byte[] modelBytes=ReadVerified(root,profile.ModelFile,MicroPersonModel.MaximumFileBytes,profile.ModelSha256!);
                if(profile.Mode==PrivacyProtectionMode.Strict)model=MicroPersonModel.Load(modelBytes);
            }
            return new(profile,policy,model,key);
        }
        catch(Exception) {throw new PrivacyConfigurationException();}
    }
    /// <summary>One complete unit. Serializes disposal with work; configured limits only tighten hard ceilings. Never exposes unapproved heuristic output.</summary>
    public PrivacyResult SanitizeJson(string json)
    {
        long started = PrivacyMetrics.Start();
        PrivacyResult? result = null;
        try { return result = SanitizeJsonCore(json); }
        finally
        {
            // Publish outside the disposal lock. This timing includes time waiting to enter it.
            string mode = profile.Mode switch
            {
                PrivacyProtectionMode.Off => "verified_off",
                PrivacyProtectionMode.CredentialsOnly => "verified_credentials_only",
                _ => "verified_strict"
            };
            PrivacyMetrics.Record(started, mode, result);
        }
    }

    /// <summary>Apply the signed profile and validate the complete response before reporting its outcome.</summary>
    private PrivacyResult SanitizeJsonCore(string json)
    {
        lock(sync)
        {
            if(disposed)return Blocked();
            try
            {
                if(new UTF8Encoding(false,true).GetByteCount(json)>profile.MaxInputBytes)return Blocked();
                PrivacyResult result;
                if(profile.Mode!=PrivacyProtectionMode.Strict)ValidateStructureBudget(json);
                if(profile.Mode==PrivacyProtectionMode.Off)
                {
                    var raw=System.Text.Json.Nodes.JsonNode.Parse(json,new System.Text.Json.Nodes.JsonNodeOptions(),new JsonDocumentOptions{MaxDepth=PrivacyLimits.Depth});
                    result=new(true,false,"disabled-by-human-installation-choice",null,raw,0,PolicyVersion,ModelVersion,[],null);
                }
                else if(profile.Mode==PrivacyProtectionMode.CredentialsOnly)
                {
                    var cleaned=new CredentialsRedactor(aliases,policy).Redact(json);
                    result=new(true,false,"credentials-only-human-installation-choice",null,cleaned.Data,cleaned.Count,PolicyVersion,ModelVersion,[],null);
                }
                else result=engine.SanitizeVerifiedJson(json);
                if(!result.Allowed || (profile.Mode==PrivacyProtectionMode.Strict&&!result.SafeForAgent))return Blocked();
                byte[] output=JsonSerializer.SerializeToUtf8Bytes(result,PrivacyJsonContext.Default.PrivacyResult);
                return output.Length>profile.MaxOutputBytes?Blocked():result;
            }
            catch(Exception){return Blocked();}
        }
    }
    /// <summary>Zero owned key once; further operations fail closed. Caller still owns original key and managed input lifetime.</summary>
    public void Dispose(){lock(sync){if(disposed)return;aliases.Dispose();disposed=true;}}
    /// <summary>Disabling privacy never disables parser safety limits; count tokens before allocating a raw/reduced JSON tree.</summary>
    private static void ValidateStructureBudget(string json)
    {
        byte[] utf8=new UTF8Encoding(false,true).GetBytes(json);
        var reader=new Utf8JsonReader(utf8,new JsonReaderOptions{MaxDepth=PrivacyLimits.Depth});int count=0;
        while(reader.Read())if(++count>PrivacyLimits.Nodes)throw new PrivacyConfigurationException();
    }
    private PrivacyResult Blocked()=>new(false,false,"privacy-processing-blocked",null,null,0,PolicyVersion,ModelVersion,[],null);
    /// <summary>Bound the read on the opened stream, then check actual bytes against the signed expected digest.</summary>
    private static byte[] ReadVerified(string root,string name,int maximum,string expected)
    {
        byte[] bytes=ReadArtifact(root,name,maximum);
        byte[] wanted=Convert.FromHexString(expected),actual=SHA256.HashData(bytes);
        if(!CryptographicOperations.FixedTimeEquals(wanted,actual))throw new PrivacyConfigurationException();
        return bytes;
    }
    private static byte[] ReadArtifact(string root,string name,int maximum)
    {
        return BoundedArtifactReader.Read(Path.Combine(root,name),maximum);
    }
}
