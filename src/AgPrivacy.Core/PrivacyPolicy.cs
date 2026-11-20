using System.Collections.Frozen;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AgPrivacy;

/// <summary>Проверенная локальная политика полей. Не должна создаваться из недоверенного агентского запроса.</summary>
public sealed class PrivacyPolicy
{
    public static readonly IReadOnlySet<string> EntityTypes = new[]
        { "TEXT", "KEY", "NUMBER", "BOOLEAN", "KLOGIN", "TRDACC", "INN", "KPP", "OGRN", "BIK", "ACCOUNT", "URL", "PATH", "PERSON", "SECRET", "GUID", "IDENTIFIER", "EMAIL", "PHONE", "ADDRESS", "IP" }.ToFrozenSet(StringComparer.Ordinal);
    private readonly Dictionary<string, string> fields;
    private readonly Dictionary<string, HashSet<string>> publicValues;
    public string Version { get; }
    public DisplayFieldExceptions DisplayFieldExceptions { get; }

    private PrivacyPolicy(Dictionary<string, string> fields, Dictionary<string, HashSet<string>> publicValues, string version, DisplayFieldExceptions displayFieldExceptions)
    { this.fields = fields; this.publicValues = publicValues; Version = version; DisplayFieldExceptions = displayFieldExceptions; }

    /// <summary>Нормализует только имя поля, включая форматные Unicode символы; значения секретов не меняет.</summary>
    public static string NormalizeField(string name)
    {
        var output = new StringBuilder();
        foreach (char c in name.Normalize(NormalizationForm.FormC))
            if (char.IsLetterOrDigit(c) && char.GetUnicodeCategory(c) != UnicodeCategory.Format) output.Append(char.ToLowerInvariant(c));
        return output.ToString();
    }

    /// <summary>Возвращает тип доверенной схемы; имя packageId само по себе не даёт исключения.</summary>
    public string? FieldType(string name) => fields.GetValueOrDefault(NormalizeField(name));
    public bool IsKnownField(string name) => fields.ContainsKey(NormalizeField(name)) || publicValues.ContainsKey(NormalizeField(name));
    public bool IsApprovedPublicValue(string name, string value) => publicValues.TryGetValue(NormalizeField(name), out var allowed) && allowed.Contains(value);

    /// <summary>Компилирует ограниченный policy pack с полями и точными public values; regex находятся в отдельном source-generated build pack.</summary>
    public static PrivacyPolicy Compile(ReadOnlySpan<byte> utf8)
    {
        if (utf8.Length > 65536) throw new ArgumentException("policy-limit");
        using JsonDocument doc = JsonDocument.Parse(utf8.ToArray(), new JsonDocumentOptions { MaxDepth = 8 });
        JsonElement root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object) throw new ArgumentException("invalid-policy");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in root.EnumerateObject())
            if (!seen.Add(property.Name) || property.Name is not ("schemaVersion" or "fields" or "publicValues" or "displayFieldExceptions")) throw new ArgumentException("invalid-policy");
        if (root.GetProperty("schemaVersion").GetString() != "ag-privacy-policy-v1") throw new ArgumentException("invalid-policy");
        var fields = Defaults();
        if (root.TryGetProperty("fields", out var configured))
        {
            if (configured.ValueKind != JsonValueKind.Object) throw new ArgumentException("invalid-policy");
            int count = 0;
            var normalized = new HashSet<string>();
            foreach (var field in configured.EnumerateObject())
            {
                string name = NormalizeField(field.Name); string? type = field.Value.GetString();
                if (++count > 256 || name.Length is 0 or > 96 || !normalized.Add(name) || type is null || !EntityTypes.Contains(type)) throw new ArgumentException("invalid-policy");
                fields[name] = type;
            }
        }
        var values = new Dictionary<string, HashSet<string>>();
        if (root.TryGetProperty("publicValues", out var approved))
        {
            if (approved.ValueKind != JsonValueKind.Object) throw new ArgumentException("invalid-policy");
            int count = 0;
            foreach (var property in approved.EnumerateObject())
            {
                string name = NormalizeField(property.Name);
                if (++count > 64 || name.Length is 0 or > 96 || fields.ContainsKey(name) || values.ContainsKey(name) || property.Value.ValueKind != JsonValueKind.Array) throw new ArgumentException("invalid-policy");
                var entries = new HashSet<string>(StringComparer.Ordinal);
                foreach (var entry in property.Value.EnumerateArray())
                {
                    string? value = entry.GetString();
                    if (entries.Count >= 128 || value is null || value.Length > 256 || !entries.Add(value)) throw new ArgumentException("invalid-policy");
                }
                values.Add(name, entries);
            }
        }
        var exceptions = root.TryGetProperty("displayFieldExceptions", out var exceptionList)
            ? DisplayFieldExceptions.Compile(exceptionList)
            : DisplayFieldExceptions.Default;
        return new(fields, values, Convert.ToHexStringLower(SHA256.HashData(utf8)), exceptions);
    }

    /// <summary>Стандартные поля из общего MCP-сценария; дополнительные поля не требуют переобучать NER.</summary>
    private static Dictionary<string, string> Defaults()
    {
        var result = new Dictionary<string, string>();
        foreach (string name in new[] { "firstName", "lastName", "surname", "middleName", "patronymic", "fullName", "fio", "фио", "фамилия", "имя", "отчество", "author", "commentAuthor", "agentFullNameRus", "agentFullNameEng" }) result[NormalizeField(name)] = "PERSON";
        foreach (string name in new[] { "password", "passwd", "pwd", "secret", "apiKey", "accessToken", "refreshToken", "idToken", "sessionToken", "clientSecret", "xApiKey", "csrfToken", "xsrfToken", "privateKey", "authorization", "bearer", "token", "cookie", "setCookie", "connectionString" }) result[NormalizeField(name)] = "SECRET";
        foreach (string name in new[] { "clientId", "personId", "accountId", "sessionId", "agreementNumber", "bankAccount", "snils", "passport", "documentNumber" }) result[NormalizeField(name)] = "IDENTIFIER";
        foreach (string name in new[] { "email", "mail" }) result[name] = "EMAIL";
        foreach (string name in new[] { "phone", "mobile", "telephone" }) result[name] = "PHONE";
        foreach (string name in new[] { "address", "addressRus" }) result[NormalizeField(name)] = "ADDRESS";
        foreach (string type in new[] { "KLOGIN", "TRDACC", "INN", "KPP", "OGRN", "BIK", "ACCOUNT", "URL", "PATH" }) result[NormalizeField(type)] = type;
        foreach (var pair in new[] { ("инн", "INN"), ("кпп", "KPP"), ("логин", "KLOGIN") }) result[pair.Item1] = pair.Item2;
        return result;
    }
}
