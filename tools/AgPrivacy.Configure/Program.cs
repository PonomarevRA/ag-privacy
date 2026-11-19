using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using AgPrivacy;
// Trusted admin utility, never registered as an agent tool. Non-strict installation choices have no CLI switch.
try
{
    if(args.Length==3&&args[0]=="keygen")
    {
        using var signer=ECDsa.Create(ECCurve.NamedCurves.nistP256);byte[] secret=signer.ExportPkcs8PrivateKey();
        try{var options=new FileStreamOptions{Mode=FileMode.CreateNew,Access=FileAccess.Write,Share=FileShare.None};if(!OperatingSystem.IsWindows())options.UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite;using var stream=new FileStream(args[1],options);stream.Write(secret);}
        finally{CryptographicOperations.ZeroMemory(secret);}
        using var publicFile=new FileStream(args[2],FileMode.CreateNew,FileAccess.Write,FileShare.None);publicFile.Write(signer.ExportSubjectPublicKeyInfo());
        Console.WriteLine("signer-created; pin the public key outside the mutable bundle");return 0;
    }
    if(args.Length is 3 or 4&&args[0]=="prepare")
    {
        string root=Path.GetFullPath(args[1]);Directory.CreateDirectory(root);
        byte[] policy=Read(args[2],65536);PrivacyPolicy.Compile(policy);File.WriteAllBytes(Path.Combine(root,"policy.json"),policy);
        var config=new JsonObject{["schemaVersion"]="ag-privacy-runtime-v1",["mode"]="strict",["scope"]="product-scope",["maxInputBytes"]=262144,["maxOutputBytes"]=4194304,["compiledRulesSha256"]=GeneratedRules.Version,["policyFile"]="policy.json",["policySha256"]=Hex(policy)};
        if(args.Length==4){byte[] model=Read(args[3],MicroPersonModel.MaximumFileBytes);MicroPersonModel.Load(model);File.WriteAllBytes(Path.Combine(root,"person.bin"),model);config["modelFile"]="person.bin";config["modelSha256"]=Hex(model);}
        File.WriteAllText(Path.Combine(root,"ag-privacy.runtime.json"),config.ToJsonString());Console.WriteLine("profile-prepared; edit trusted settings then sign");return 0;
    }
    if(args.Length==3&&args[0]=="sign")
    {
        byte[] config=Read(Path.Combine(args[1],"ag-privacy.runtime.json"),VerifiedProfile.MaximumConfigBytes);
        byte[] privateBytes=ReadPrivateKey(args[2]);
        using var signer=ECDsa.Create();try{signer.ImportPkcs8PrivateKey(privateBytes,out int consumed);if(consumed!=privateBytes.Length)throw new PrivacyConfigurationException();}finally{CryptographicOperations.ZeroMemory(privateBytes);}
        byte[] signature=signer.SignData(config,HashAlgorithmName.SHA256,DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        var profile=VerifiedProfile.Verify(config,signature,signer.ExportSubjectPublicKeyInfo());
        if(profile.Mode!=PrivacyProtectionMode.Strict)throw new PrivacyConfigurationException();
        File.WriteAllBytes(Path.Combine(args[1],"ag-privacy.runtime.sig"),signature);
        Console.WriteLine("approved-config-sha256:"+Hex(config));return 0;
    }
    Console.Error.WriteLine("usage: keygen PRIVATE_PKCS8 PUBLIC_SPKI | prepare DIR POLICY [MODEL] | sign DIR PRIVATE_PKCS8");return 2;
}
catch{Console.Error.WriteLine("privacy-configuration-blocked");return 2;}
/// <summary>Bound local admin input; output never contains file content or parser exceptions.</summary>
static byte[] Read(string path,int maximum)
{
    using var stream=File.OpenRead(path);return ReadStream(stream,maximum);
}
static byte[] ReadStream(Stream stream,int maximum)
{
    var bytes=new byte[maximum+1];int length=0;
    while(length<bytes.Length){int count=stream.Read(bytes,length,bytes.Length-length);if(count==0)break;length+=count;}
    if(length>maximum)throw new PrivacyConfigurationException();return bytes[..length];
}
/// <summary>Same checked handle for private-key mode and bytes; clear every temporary key buffer.</summary>
static byte[] ReadPrivateKey(string path)
{
    using var handle=File.OpenHandle(path,FileMode.Open,FileAccess.Read,FileShare.Read);
    if(!OperatingSystem.IsWindows()&&(File.GetUnixFileMode(handle)&(UnixFileMode.GroupRead|UnixFileMode.GroupWrite|UnixFileMode.GroupExecute|UnixFileMode.OtherRead|UnixFileMode.OtherWrite|UnixFileMode.OtherExecute))!=0)throw new PrivacyConfigurationException();
    using var stream=new FileStream(handle,FileAccess.Read);var buffer=new byte[4097];
    try{int length=0;while(length<buffer.Length){int count=stream.Read(buffer,length,buffer.Length-length);if(count==0)break;length+=count;}if(length is 0 or >4096)throw new PrivacyConfigurationException();return buffer[..length];}
    finally{CryptographicOperations.ZeroMemory(buffer);}
}
static string Hex(byte[] value)=>Convert.ToHexStringLower(SHA256.HashData(value));
