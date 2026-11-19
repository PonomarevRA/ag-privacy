using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
namespace AgPrivacy;
/// <summary>Local regular-file reads only. Unix nonblocking/no-follow open rejects FIFO and symlink races before any data read.</summary>
internal static partial class BoundedArtifactReader
{
    // Values verified against Darwin SDK sys/fcntl.h and Linux asm-generic/fcntl.h for supported x64/arm64 targets.
    private const int DarwinFlags=0x00000004|0x00000100|0x01000000;
    private const int LinuxFlags=(1<<11)|(1<<17)|(1<<19);
    [LibraryImport("libc",EntryPoint="open",StringMarshalling=StringMarshalling.Utf8,SetLastError=true)]
    private static partial int Open(string path,int flags);
    /// <summary>Read a bounded snapshot from the exact opened regular file; no content/error text leaves this API.</summary>
    internal static byte[] Read(string path,int maximum)
    {
        if(new FileInfo(path).LinkTarget is not null)throw new PrivacyConfigurationException();
        using var handle=OpenHandle(path);
        using var stream=new FileStream(handle,FileAccess.Read);
        if(!stream.CanSeek || stream.Length>maximum)throw new PrivacyConfigurationException();
        var bytes=new byte[maximum+1];int length=0;
        while(length<bytes.Length){int count=stream.Read(bytes,length,bytes.Length-length);if(count==0)break;length+=count;}
        if(length>maximum)throw new PrivacyConfigurationException();
        return bytes[..length];
    }
    private static SafeFileHandle OpenHandle(string path)
    {
        if(OperatingSystem.IsWindows())return File.OpenHandle(path,FileMode.Open,FileAccess.Read,FileShare.Read);
        if(!OperatingSystem.IsMacOS()&&!OperatingSystem.IsLinux())throw new PrivacyConfigurationException();
        int fd=Open(path,OperatingSystem.IsMacOS()?DarwinFlags:LinuxFlags);
        if(fd<0)throw new PrivacyConfigurationException();
        return new SafeFileHandle((IntPtr)fd,ownsHandle:true);
    }
}
