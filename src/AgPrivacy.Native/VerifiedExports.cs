using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using AgPrivacy;
namespace AgPrivacy.Native;

/// <summary>Versioned reusable C ABI. Opaque IDs are process-local resources, not authentication tokens or dereferenceable pointers.</summary>
public static unsafe class VerifiedExports
{
    /// <summary>Return ABI version1. Caller must still match operating system and processor architecture.</summary>
    [UnmanagedCallersOnly(EntryPoint="ag_privacy_abi_version",CallConvs=[typeof(CallConvCdecl)])]
    public static int Version()=>1;
    /// <summary>Create at most64 live verified modules. Caller pins the public key outside the writable configuration bundle.</summary>
    [UnmanagedCallersOnly(EntryPoint="ag_privacy_create_verified",CallConvs=[typeof(CallConvCdecl)])]
    public static long Create(byte* directory,int directoryLength,byte* publicKey,int publicKeyLength,byte* key,int keyLength,byte* approvedDigest,int approvedDigestLength)
    {
        try
        {
            if(!Range(directory,directoryLength,1,16384)||!Range(publicKey,publicKeyLength,1,512)||!Range(key,keyLength,32,128)||!Range(approvedDigest,approvedDigestLength,32,32))return 0;
            string root=new UTF8Encoding(false,true).GetString(new ReadOnlySpan<byte>(directory,directoryLength));
            return ModuleRegistry.Create(root,new ReadOnlySpan<byte>(publicKey,publicKeyLength),new ReadOnlySpan<byte>(key,keyLength),new ReadOnlySpan<byte>(approvedDigest,approvedDigestLength));
        }
        catch{return 0;}
    }
    /// <summary>Strict complete-unit processing; stale/invalid handles return null, never touch arbitrary native addresses.</summary>
    [UnmanagedCallersOnly(EntryPoint="ag_privacy_process_json",CallConvs=[typeof(CallConvCdecl)])]
    public static byte* Process(long handle,byte* input,int inputLength,int* outputLength)
    {
        if(outputLength==null)return null;*outputLength=0;
        try
        {
            if(!Range(input,inputLength,0,PrivacyLimits.InputBytes))return null;
            var module=ModuleRegistry.Find(handle);if(module is null)return null;
            string json=new UTF8Encoding(false,true).GetString(new ReadOnlySpan<byte>(input,inputLength));
            var result=module.SanitizeJson(json);
            byte[] bytes=JsonSerializer.SerializeToUtf8Bytes(result,PrivacyJsonContext.Default.PrivacyResult);
            var output=(byte*)NativeMemory.Alloc((nuint)bytes.Length);if(output==null)return null;
            bytes.CopyTo(new Span<byte>(output,bytes.Length));*outputLength=bytes.Length;return output;
        }
        catch{return null;}
    }
    /// <summary>Idempotent close; active work completes or fails closed under the module lifecycle lock.</summary>
    [UnmanagedCallersOnly(EntryPoint="ag_privacy_destroy",CallConvs=[typeof(CallConvCdecl)])]
    public static void Destroy(long handle){try{ModuleRegistry.Close(handle);}catch{}}
    /// <summary>Current frozen mode:0 strict,1 credentials-only,2 off; invalid handle returns-1.</summary>
    [UnmanagedCallersOnly(EntryPoint="ag_privacy_mode",CallConvs=[typeof(CallConvCdecl)])]
    public static int Mode(long handle){try{return ModuleRegistry.Find(handle) is { } module?(int)module.Mode:-1;}catch{return -1;}}
    private static bool Range(byte* pointer,int length,int minimum,int maximum)=>pointer!=null&&length>=minimum&&length<=maximum;
}

/// <summary>Bounded process-local ownership. Reservations bound concurrent opens; filesystem IO never holds the registry lock.</summary>
internal static class ModuleRegistry
{
    private static readonly object Gate=new();
    private static readonly Dictionary<long,VerifiedPrivacyModule> Modules=[];
    private static long next;
    private static int pending;
    /// <summary>Reserve capacity under lock, then perform all IO outside it. Failed opens cannot stall existing live modules.</summary>
    internal static long Create(string root,ReadOnlySpan<byte> publicKey,ReadOnlySpan<byte> key,ReadOnlySpan<byte> approvedDigest)
    {
        lock(Gate){if(Modules.Count+pending>=64 || next==long.MaxValue)return 0;pending++;}
        VerifiedPrivacyModule? module=null;
        try
        {
            module=VerifiedPrivacyModule.Load(root,publicKey,key,approvedDigest);
            lock(Gate)
            {
                if(next==long.MaxValue)return 0;
                long handle=++next;Modules.Add(handle,module);module=null;return handle;
            }
        }
        finally {lock(Gate)pending--;module?.Dispose();}
    }
    internal static VerifiedPrivacyModule? Find(long handle){lock(Gate)return Modules.GetValueOrDefault(handle);}
    internal static void Close(long handle)
    {
        VerifiedPrivacyModule? module;lock(Gate)Modules.Remove(handle,out module);
        module?.Dispose();
    }
}
