using System.Collections.Frozen;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace AgPrivacy;

/// <summary>Field-based JSON masking for the DIB display profile. Its output can contain original data.</summary>
public sealed class SoftPartMasker(Pseudonymizer aliases, PrivacyPolicy policy, IPersonDetector? persons)
{
    private const string Version = "dib-soft-part-v6";
    private static readonly PrivacyPolicy DefaultPolicy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private static readonly FrozenDictionary<string, FieldRule> Rules = BuildRules();

    private readonly TextRedactor logRedactor = new(aliases, policy, persons);

    /// <summary>Create a soft-part masker with the default field policy.</summary>
    public SoftPartMasker(Pseudonymizer aliases) : this(aliases, DefaultPolicy, null) { }

    /// <summary>Create a soft-part masker with formal patterns and the configured field policy.</summary>
    public SoftPartMasker(Pseudonymizer aliases, PrivacyPolicy policy) : this(aliases, policy, null) { }

    /// <summary>Check whether the normalized field already has a soft-part rule.</summary>
    internal static bool HasFieldRule(string field) => Rules.ContainsKey(PrivacyPolicy.NormalizeField(field));

    /// <summary>Apply the profile to one bounded document, preserving arrays, objects and nulls.</summary>
    public PrivacyResult SanitizeJson(string input) => SanitizeJson(input, policy.DisplayFieldExceptions);

    /// <summary>Apply an explicit list to this display request only.</summary>
    public PrivacyResult SanitizeJson(string input, DisplayFieldExceptions exceptions) =>
        SanitizeJson(input, exceptions, includePreview: false);

    /// <summary>Include the JSON preview and its replacement offsets when requested.</summary>
    public PrivacyResult SanitizeJson(string input, DisplayFieldExceptions exceptions, bool includePreview)
    {
        long started = PrivacyMetrics.Start();
        PrivacyResult? result = null;
        try { return result = SanitizeJsonCore(input, exceptions, includePreview); }
        finally { PrivacyMetrics.Record(started, "soft_part", result); }
    }

    /// <summary>Mask one bounded JSON document with the selected exceptions.</summary>
    private PrivacyResult SanitizeJsonCore(string input, DisplayFieldExceptions exceptions, bool includePreview)
    {
        try
        {
            if (Utf8.GetByteCount(input) <= PrivacyLimits.InputBytes)
            {
                using var document = JsonDocument.Parse(input, new JsonDocumentOptions { MaxDepth = PrivacyLimits.Depth });
                var state = new WalkState(exceptions) { Preview = includePreview ? new() : null };
                var data = MaskNode(document.RootElement, null, state);
                return new(true, false, "soft-part-redaction", null, data, state.Replacements, Version, persons?.Version ?? "none", [], null) { ReplacementsByType = state.ReplacementsByType, Preview = state.Preview?.Build(data) };
            }
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or JsonException or RegexMatchTimeoutException)
        {
            // Never return a partial document or an exception message that might contain input.
        }

        return new(false, false, "privacy-processing-blocked", null, null, 0, Version, persons?.Version ?? "none", [], null);
    }

    /// <summary>Use the current field for array elements, and resolve each object member independently.</summary>
    private JsonNode? MaskNode(JsonElement node, FieldRule? rule, WalkState state, bool allowValueFallback = true, LogField logField = LogField.None, string? fieldName = null)
    {
        if (++state.Nodes > PrivacyLimits.Nodes) throw new InvalidOperationException("document-limit");

        switch (node.ValueKind)
        {
            case JsonValueKind.Null:
                return null;
            case JsonValueKind.Object:
                // A named rule takes precedence over inference and primitive preservation below it.
                bool allowChildFallback = allowValueFallback && rule is null;
                var obj = new JsonObject();
                var recognizedFields = new HashSet<string>(StringComparer.Ordinal);
                var taxIdRule = ReadTaxIdRule(node);
                string? linkedPhone = ReadLinkedPhoneField(node);
                foreach (var property in node.EnumerateObject())
                {
                    string field = PrivacyPolicy.NormalizeField(property.Name);
                    if (Rules.TryGetValue(field, out var fieldRule) && !recognizedFields.Add(field))
                        throw new InvalidOperationException("duplicate-field");

                    if (field is "inn" or "инн" or "tin")
                        fieldRule = fieldRule! with { Mask = taxIdRule };
                    else if (property.Name == linkedPhone)
                        fieldRule = new("PHONE", SoftPartFormats.LinkedPhone);
                    else if (fieldRule is null && policy.IsKnownField(property.Name))
                        fieldRule = new(DisplayMaskRules.ForField(property.Name, policy.FieldType(property.Name) ?? "TEXT"), SoftPartFormats.Full);

                    string key = MaskKey(property.Name, state);
                    if (key != property.Name) state.Preview?.RecordKey(obj, key);
                    obj.Add(key, MaskNode(property.Value, fieldRule, state, allowChildFallback, LogMasking.FieldFor(logField, property.Name), property.Name));
                }
                return obj;
            case JsonValueKind.Array:
                var array = new JsonArray();
                foreach (var item in node.EnumerateArray())
                    array.Add(MaskNode(item, rule, state, allowValueFallback, logField, fieldName));
                return array;
            case JsonValueKind.String:
                string original = node.GetString()!;
                if (rule is null && allowValueFallback)
                {
                    if (logField == LogField.Message)
                    {
                        List<MaskHighlight>? fragments = state.Preview is null ? null : [];
                        var maskedLog = logRedactor.RedactLogMessage(original, state.Exceptions, state.ReplacementsByType, fragments);
                        state.Replacements += maskedLog.Count;
                        return MaskPreviewBuilder.Value(maskedLog.Text, state.Preview, fragments);
                    }
                    if (logField == LogField.TraceId)
                    {
                        state.Record("TRACE_ID");
                        return MaskPreviewBuilder.Value(LogMasking.TraceId(aliases, original), state.Preview);
                    }
                }
                string? code = rule?.Code;
                string masked;
                if (rule is not null) masked = rule.Mask(original);
                else if (allowValueFallback)
                {
                    bool skipPersonDetection = state.Exceptions.Contains(fieldName) && LogMasking.CanSkipPersonDetection(fieldName, original);
                    code = DisplayValueFormats.RuleForText(original, policy, skipPersonDetection ? null : persons);
                    masked = DisplayValueFormats.Mask(original, code);
                }
                else masked = SoftPartFormats.FullMask;

                if (masked == original) return JsonValue.Create(original);
                state.Record(code ?? "TEXT");
                return MaskPreviewBuilder.Value(masked, state.Preview);
            default:
                if (rule is null && allowValueFallback && DisplayValueFormats.IsOrdinaryPrimitive(node.ValueKind))
                    return JsonValue.Create(node.Clone());

                state.Record(rule?.Code ?? "TEXT");
                return MaskPreviewBuilder.Value(SoftPartFormats.FullMask, state.Preview);
        }
    }

    /// <summary>Preserve schema labels and mask a key only when it contains an email address or phone number.</summary>
    private string MaskKey(string key, WalkState state)
    {
        string? rule = JsonFieldNames.ContactRule(key);
        if (rule is null) return key;

        state.Record(rule);
        return aliases.ReplaceForDisplay("KEY", key, rule);
    }

    /// <summary>Resolve the Boolean flag only when the object has exactly one eligible phone field.</summary>
    private static string? ReadLinkedPhoneField(JsonElement obj)
    {
        if (!obj.TryGetProperty("phoneLinkedToFs", out var link) || link.ValueKind != JsonValueKind.True)
            return null;

        string? phone = null;
        foreach (var property in obj.EnumerateObject())
        {
            string field = PrivacyPolicy.NormalizeField(property.Name);
            if (field is not ("phone" or "телефон")) continue;
            if (phone is not null || property.Value.ValueKind != JsonValueKind.String) return null;
            phone = property.Name;
        }
        return phone;
    }

    /// <summary>Use the declared client type for the current object and mask fully when context is unknown.</summary>
    private static Func<string, string> ReadTaxIdRule(JsonElement obj)
    {
        if (!obj.TryGetProperty("clientType", out var field) || field.ValueKind != JsonValueKind.String)
            return SoftPartFormats.Full;

        string type = field.GetString()!;
        if (type.Equals("individual", StringComparison.OrdinalIgnoreCase) || type.Equals("ФЛ", StringComparison.OrdinalIgnoreCase))
            return SoftPartFormats.Registration;
        if (type.Equals("legalEntity", StringComparison.OrdinalIgnoreCase) || type.Equals("ЮЛ", StringComparison.OrdinalIgnoreCase))
            return SoftPartFormats.Keep;
        return SoftPartFormats.Full;
    }

    /// <summary>Bind trusted field names to display rules. Unknown fields use the full mask.</summary>
    private static FrozenDictionary<string, FieldRule> BuildRules()
    {
        var rules = new Dictionary<string, FieldRule>(StringComparer.Ordinal);
        Add("PERSON", SoftPartFormats.FullName, "fullName", "fio", "фио", "agentFullNameRus", "agentFullNameEng");
        Add("PERSON", SoftPartFormats.Initial, "lastName", "surname", "фамилия");
        Add("ADDRESS", SoftPartFormats.Initial, "postalCode", "zipCode", "индекс", "city", "город",
            "locality", "settlement", "населённый пункт", "населенный пункт", "street", "улица");
        Add("PERSON", SoftPartFormats.Keep, "firstName", "имя", "middleName", "patronymic", "отчество");
        Add("ADDRESS", SoftPartFormats.Keep, "birthPlace", "место рождения");
        Add("TEXT", SoftPartFormats.Keep, "signatureSample", "образец подписи", "passportIssuer", "орган выдачи паспорта");
        Add("DATE", SoftPartFormats.Date, "birthDate", "dateOfBirth", "дата рождения", "issueDate", "documentIssueDate",
            "дата выдачи документа", "agreementDate", "дата заключения договора", "date", "дата");
        Add("IDENTIFIER", SoftPartFormats.Registration, "registrationNumber", "documentSeries", "documentNumber", "passport", "паспорт",
            "passportSeries", "passportNumber", "departmentCode", "код подразделения", "snils", "снилс");
        // Register tax ID field names so the object can choose their rule from clientType.
        Add("INN", SoftPartFormats.Full, "inn", "инн");
        Add("TIN", SoftPartFormats.Full, "tin");
        Add("PHONE", SoftPartFormats.Phone, "phone", "mobile", "mobilePhone", "homePhone", "workPhone", "telephone", "телефон", "fax", "факс");
        Add("EMAIL", SoftPartFormats.Email, "email", "mail");
        Add("KLOGIN", SoftPartFormats.Login, "klogin", "login", "логин");
        Add("AGREEMENT", SoftPartFormats.Agreement, "agreementNumber", "contractNumber", "номер договора");
        Add("AGREEMENT", SoftPartFormats.NonstandardAgreement, "nonstandardAgreementNumber", "forwardContractNumber", "structuredProductAgreementNumber");
        Add("TRDACC", SoftPartFormats.BrokerAccount, "trdacc", "brokerAccount", "brokerAccountNumber", "номер брокерского счёта");
        Add("ACCOUNT", SoftPartFormats.ClientAccount, "account", "bankAccount", "accountNumber", "personalAccount", "clientAccount",
            "cardNumber", "номер карты", "номер счёта", "счёт клиента", "счет клиента");
        Add("TEXT", SoftPartFormats.Partial, "fixturePartial", "partialValue");
        Add("URL", SoftPartFormats.Full, "url", "website", "сайт");
        Add("ADDRESS", SoftPartFormats.Full, "address", "fullAddress", "addressRus", "адрес");
        Add("SECRET", SoftPartFormats.Full, "codeWord", "otp", "cvv", "password", "apiKey", "accessToken");
        Add("TEXT", SoftPartFormats.Full, "skype", "icq", "paymentPurpose", "назначение платежа", "clientType", "phoneLinkedToFs");
        return rules.ToFrozenDictionary(StringComparer.Ordinal);

        /// <summary>Canonicalize aliases with the same rules applied to input field names.</summary>
        void Add(string code, Func<string, string> mask, params string[] names)
        {
            var rule = new FieldRule(code, mask);
            foreach (string name in names)
                rules.Add(PrivacyPolicy.NormalizeField(name), rule);
        }
    }

    private sealed record FieldRule(string Code, Func<string, string> Mask);

    private sealed class WalkState(DisplayFieldExceptions exceptions)
    {
        public DisplayFieldExceptions Exceptions { get; } = exceptions;
        public int Nodes;
        public MaskPreviewBuilder? Preview;
        public int Replacements;
        public Dictionary<string, int> ReplacementsByType { get; } = new(StringComparer.Ordinal);

        /// <summary>Record the rule that changed a value or key in this result.</summary>
        public void Record(string code)
        {
            Replacements++;
            ReplacementsByType[code] = ReplacementsByType.GetValueOrDefault(code) + 1;
        }
    }
}
