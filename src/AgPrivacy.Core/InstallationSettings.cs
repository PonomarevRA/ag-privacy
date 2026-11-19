using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
namespace AgPrivacy;
public enum PrivacyProtectionMode { Strict, CredentialsOnly, Off }
public sealed record SignedInstallationSettings(byte[] Configuration,byte[] Signature);
/// <summary>Trusted installer control plane only, never an agent tool. Host authenticates actual user selection; library cannot prove a UI click.</summary>
public static class InstallationSettings
{
    public const string ReducedProtectionWarning="Минимальный режим скрывает только распознанные токены, пароли и логины форм. Остальные персональные данные могут получить агент и провайдер модели.";
    public const string OffWarning="ag-privacy будет выключен по вашему выбору. Агент и провайдер модели смогут получить оригинальные персональные данные и секреты. Включить защиту можно в настройках продукта.";
    /// <summary>Sign the chosen install default only after an authenticated human setup action. Caller must isolate signing key and this method from agents.</summary>
    public static SignedInstallationSettings SignAfterHumanChoice(ReadOnlySpan<byte> template,PrivacyProtectionMode mode,ECDsa installerKey)
    {
        if(template.Length>VerifiedProfile.MaximumConfigBytes || !Enum.IsDefined(mode) || installerKey.KeySize!=256)throw new PrivacyConfigurationException();
        try
        {
            // Verify the template as well: duplicate/unknown properties cannot disappear during a JSON rewrite.
            byte[] templateSignature=installerKey.SignData(template,HashAlgorithmName.SHA256,DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            VerifiedProfile.Verify(template,templateSignature,installerKey.ExportSubjectPublicKeyInfo());
            var value=JsonNode.Parse(template)!.AsObject();
            string name=mode switch{PrivacyProtectionMode.Strict=>"strict",PrivacyProtectionMode.CredentialsOnly=>"credentials-only",_=>"off"};
            value["mode"]=name;value["humanSetupChoice"]=name;
            byte[] bytes=Encoding.UTF8.GetBytes(value.ToJsonString());
            byte[] signature=installerKey.SignData(bytes,HashAlgorithmName.SHA256,DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            VerifiedProfile.Verify(bytes,signature,installerKey.ExportSubjectPublicKeyInfo());
            return new(bytes,signature);
        }
        catch(Exception){throw new PrivacyConfigurationException();}
    }
}
