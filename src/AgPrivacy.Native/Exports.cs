using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using AgPrivacy;
namespace AgPrivacy.Native;
/// <summary>Host-only stateless C ABI. Valid readable pointer/length pairs and single free of returned buffers are caller obligations.</summary>
public static unsafe class Exports
{
    /// <summary>Strict JSON boundary. Returns owned UTF-8 buffer or null; no exception/error message/raw fallback crosses ABI.</summary>
    [UnmanagedCallersOnly(EntryPoint="ag_privacy_sanitize_json",CallConvs=[typeof(CallConvCdecl)])]
    public static byte* SanitizeJson(byte* input,int inputLength,byte* key,int keyLength,byte* scope,int scopeLength,byte* policy,int policyLength,int* outputLength)
    {
        if(outputLength==null)return null;*outputLength=0;
        try
        {
            if(!ValidRange(input,inputLength,0,PrivacyLimits.InputBytes))return null;
            if(!ValidRange(key,keyLength,32,128))return null;
            if(!ValidRange(scope,scopeLength,1,512))return null;
            if(!ValidRange(policy,policyLength,1,65536))return null;
            var utf8=new UTF8Encoding(false,true);
            var compiled=PrivacyPolicy.Compile(new ReadOnlySpan<byte>(policy,policyLength));
            using var aliases=new Pseudonymizer(new ReadOnlySpan<byte>(key,keyLength),utf8.GetString(new ReadOnlySpan<byte>(scope,scopeLength)));
            var result=new PrivacyEngine(compiled,aliases).SanitizeJson(utf8.GetString(new ReadOnlySpan<byte>(input,inputLength)));
            byte[] bytes=JsonSerializer.SerializeToUtf8Bytes(result,PrivacyJsonContext.Default.PrivacyResult);
            var output=(byte*)NativeMemory.Alloc((nuint)bytes.Length);if(output==null)return null;
            bytes.CopyTo(new Span<byte>(output,bytes.Length));*outputLength=bytes.Length;return output;
        }
        catch {return null;}
    }
    /// <summary>Check byte-length contract only; native caller still owns pointer validity.</summary>
    private static bool ValidRange(byte* pointer,int length,int minimum,int maximum) => pointer!=null && length>=minimum && length<=maximum;
    /// <summary>Free exactly once a buffer returned by ag_privacy_sanitize_json, or null. Never pass caller-owned memory.</summary>
    [UnmanagedCallersOnly(EntryPoint="ag_privacy_free",CallConvs=[typeof(CallConvCdecl)])]
    public static void Free(byte* buffer)=>NativeMemory.Free(buffer);
}
