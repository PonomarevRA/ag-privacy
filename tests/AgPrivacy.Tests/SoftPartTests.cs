using System.Text.Json.Nodes;
using AgPrivacy;
using Xunit;

namespace AgPrivacy.Tests;

public class SoftPartTests
{
    /// <summary>Compare the same 26 synthetic values previously checked against strict mode.</summary>
    [Theory]
    [InlineData("fullName", "Тестов Тест Тестович", "Т***** Тест Тестович")]
    [InlineData("lastName", "Тестов", "Т*****")]
    [InlineData("firstName", "Тест", "Тест")]
    [InlineData("middleName", "Тестович", "Тестович")]
    [InlineData("birthDate", "29-02-2004", "29-02-****")]
    [InlineData("birthDate", "2004-02-29", "****-02-29")]
    [InlineData("birthDate", "29/02/2004 00:00:00", "29/02/**** 00:00:00")]
    [InlineData("documentNumber", "01234567", "0******7")]
    [InlineData("phone", "+70012345678", "+7001****678")]
    [InlineData("url", "https://example.invalid", "****")]
    [InlineData("email", "abcdef@example.invalid", "abc***@")]
    [InlineData("email", "ab@example.invalid", "a*@")]
    [InlineData("email", "a@example.invalid", "*@")]
    [InlineData("address", "Тестовый адрес", "****")]
    [InlineData("city", "Тестоград", "Т********")]
    [InlineData("klogin", "k-123456", "k-****56")]
    [InlineData("agreementNumber", "ДО-123459/13-л", "ДО-****59/13-л")]
    [InlineData("agreementNumber", "ABCD12345XYZ", "ABCD*****XYZ")]
    [InlineData("trdacc", "DEMO0093", "******93")]
    [InlineData("bankAccount", "00000000000000004333", "****************4333")]
    [InlineData("paymentPurpose", "Синтетический платёж", "****")]
    [InlineData("fixturePartial", "АБВГД", "А***Д")]
    [InlineData("otp", "000000", "****")]
    [InlineData("birthPlace", "Тестоград", "Тестоград")]
    [InlineData("signatureSample", "Синтетическая подпись", "Синтетическая подпись")]
    [InlineData("passportIssuer", "Синтетический орган", "Синтетический орган")]
    public void MasksSyntheticConfluenceCase(string field, string original, string expected)
    {
        using var aliases = new Pseudonymizer(new byte[32], "test-soft-part");
        var input = new JsonObject { [field] = original };
        var result = new SoftPartMasker(aliases).SanitizeJson(input.ToJsonString());

        Assert.True(result.Allowed);
        Assert.False(result.SafeForAgent);
        Assert.Equal("soft-part", result.ProtectionMode);
        Assert.Equal(expected, result.Data![field]!.GetValue<string>());
        Assert.Equal(original == expected ? 0 : 1, result.Replacements);
    }

    /// <summary>Keep document shape and avoid releasing unknown values or malformed identifiers.</summary>
    [Fact]
    public void UnsupportedFormatsAndUnknownFieldsUseFullMask()
    {
        using var aliases = new Pseudonymizer(new byte[32], "test-soft-part");
        var result = new SoftPartMasker(aliases).SanitizeJson("""
            {"phone":["+7 001 234-56-78", "123456", null], "birthDate":"31-02-2004",
             "inn":"000000000000", "unknown":[12345,true,{"bankAccount":"1234","email":"invalid"}]}
            """);

        Assert.True(result.Allowed);
        var data = result.Data!.AsObject();
        Assert.Equal("+7 001 ***-*6-78", data["phone"]![0]!.GetValue<string>());
        Assert.Equal("****", data["phone"]![1]!.GetValue<string>());
        Assert.Null(data["phone"]![2]);
        Assert.Equal("****", data["birthDate"]!.GetValue<string>());
        Assert.Equal("****", data["inn"]!.GetValue<string>());
        var unknown = data["unknown"]!.AsArray();
        Assert.Equal(12345, unknown[0]!.GetValue<int>());
        Assert.True(unknown[1]!.GetValue<bool>());
        Assert.Equal("****", unknown[2]!["bankAccount"]!.GetValue<string>());
        Assert.Equal("****", unknown[2]!["email"]!.GetValue<string>());
    }

    /// <summary>Choose tax ID treatment from the client type in the same record.</summary>
    [Theory]
    [InlineData("individual", "0**********0", "0******7")]
    [InlineData("ФЛ", "0**********0", "0******7")]
    [InlineData("legalEntity", "000000000000", "01234567")]
    [InlineData("ЮЛ", "000000000000", "01234567")]
    [InlineData("unknown", "****", "****")]
    public void MasksTaxIdsUsingClientType(string clientType, string expectedInn, string expectedTin)
    {
        using var aliases = new Pseudonymizer(new byte[32], "test-soft-part");
        var input = new JsonObject { ["ИНН"] = "000000000000", ["TIN"] = "01234567", ["clientType"] = clientType };
        var result = new SoftPartMasker(aliases).SanitizeJson(input.ToJsonString());

        Assert.True(result.Allowed);
        Assert.False(result.SafeForAgent);
        Assert.Equal(expectedInn, result.Data!["ИНН"]!.GetValue<string>());
        Assert.Equal(expectedTin, result.Data!["TIN"]!.GetValue<string>());
    }

    /// <summary>Only the explicit Boolean flag preserves the designated phone.</summary>
    [Theory]
    [InlineData("true", "+70012345678")]
    [InlineData("false", "+7001****678")]
    [InlineData("\"true\"", "+7001****678")]
    public void LimitsFsExceptionToTheDesignatedPhone(string flag, string expected)
    {
        using var aliases = new Pseudonymizer(new byte[32], "test-soft-part");
        var result = new SoftPartMasker(aliases).SanitizeJson($$"""
            {"phone":"+70012345678","workPhone":"+70012345678","phoneLinkedToFs":{{flag}},
             "contact":{"phone":"+70012345678","tin":"01234567"},"clientType":"individual"}
            """);

        Assert.True(result.Allowed);
        Assert.Equal(expected, result.Data!["phone"]!.GetValue<string>());
        Assert.Equal("+7001****678", result.Data!["workPhone"]!.GetValue<string>());
        var contact = result.Data!["contact"]!;
        Assert.Equal("+7001****678", contact["phone"]!.GetValue<string>());
        Assert.Equal("****", contact["tin"]!.GetValue<string>());
    }

    /// <summary>Keep the exemption narrow when a record contains a list or invalid phone value.</summary>
    [Fact]
    public void FsExceptionDoesNotReleaseArraysOrInvalidNumbers()
    {
        using var aliases = new Pseudonymizer(new byte[32], "test-soft-part");
        var result = new SoftPartMasker(aliases).SanitizeJson("""
            [{"phone":["+70012345678"],"phoneLinkedToFs":true},
             {"телефон":"synthetic-not-a-number","phoneLinkedToFs":true},
             {"phone":"+70012345678","телефон":"+70012345678","phoneLinkedToFs":true}]
            """);

        Assert.True(result.Allowed);
        Assert.Equal("+7001****678", result.Data![0]!["phone"]![0]!.GetValue<string>());
        Assert.Equal("****", result.Data![1]!["телефон"]!.GetValue<string>());
        Assert.Equal("+7001****678", result.Data![2]!["phone"]!.GetValue<string>());
        Assert.Equal("+7001****678", result.Data![2]!["телефон"]!.GetValue<string>());
    }

    /// <summary>Both display modes preserve ordinary labels and pseudonymize contact data inside keys.</summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void MasksOnlyKeysThatContainEmailOrPhone(bool softPart)
    {
        using var aliases = new Pseudonymizer(new byte[32], "test-display-keys");
        const string input = """
            {"tags":["synthetic"],"email":"a@example.invalid","workPhone":"+70012345678",
             "secret":"synthetic-secret","section_x-123":null,"799-123-456 01":null,
             "key-fixture@example.invalid":null,"contact +70012345678":null,
             "8 (000) 123-45-67":null}
            """;
        var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
        var engine = new PrivacyEngine(policy, aliases);
        var result = softPart ? new SoftPartMasker(aliases).SanitizeJson(input) : engine.SanitizeJsonForDisplay(input);

        Assert.True(result.Allowed);
        Assert.False(result.SafeForAgent);
        Assert.Equal(softPart ? "soft-part" : "strict", result.ProtectionMode);
        var data = result.Data!.AsObject();
        Assert.NotNull(data["tags"]![0]);
        string email = data["email"]!.GetValue<string>();
        string workPhone = data["workPhone"]!.GetValue<string>();
        if (softPart)
        {
            Assert.Equal("*@", email);
            Assert.Equal("+7001****678", workPhone);
        }
        else
        {
            Assert.Matches(@"^\[REDACTED:v1:EMAIL:[a-f0-9]{64}\]$", email);
            Assert.Matches(@"^\[REDACTED:v1:PHONE:[a-f0-9]{64}\]$", workPhone);
        }
        Assert.True(data.ContainsKey("secret"));
        Assert.True(data.ContainsKey("section_x-123"));
        Assert.True(data.ContainsKey("799-123-456 01"));
        foreach (string key in new[] { "key-fixture@example.invalid", "contact +70012345678", "8 (000) 123-45-67" })
            Assert.False(data.ContainsKey(key));
        Assert.Single(data, pair => pair.Key.StartsWith("[REDACTED:v1:KEY_EMAIL:", StringComparison.Ordinal));
        Assert.Equal(2, data.Count(pair => pair.Key.StartsWith("[REDACTED:v1:KEY_PHONE:", StringComparison.Ordinal)));

        var sdk = engine.SanitizeJson(input);
        Assert.True(sdk.SafeForAgent);
        Assert.False(sdk.Data!.AsObject().ContainsKey("tags"));
    }

    /// <summary>Describe the strict rule and use the same numeric contract template regardless of input length.</summary>
    [Fact]
    public void ExplainsAndMasksNumericAgreementForDisplay()
    {
        using var aliases = new Pseudonymizer(new byte[32], "test-display-rules");
        const string input = """
            {"agreementNumber":["12-451123/26","1-123/2026"],"birthDate":"29-02-2004","tags":["synthetic"]}
            """;
        var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
        var engine = new PrivacyEngine(policy, aliases);
        var strict = engine.SanitizeJsonForDisplay(input);
        var soft = new SoftPartMasker(aliases).SanitizeJson(input);

        Assert.True(strict.Allowed);
        Assert.True(soft.Allowed);
        foreach (var agreement in strict.Data!["agreementNumber"]!.AsArray())
            Assert.Matches(@"^\[REDACTED:v1:AGREEMENT:[a-f0-9]{64}\]$", agreement!.GetValue<string>());
        foreach (var agreement in soft.Data!["agreementNumber"]!.AsArray())
            Assert.Equal("00-000000/00", agreement!.GetValue<string>());

        Assert.StartsWith("[REDACTED:v1:DATE:", strict.Data!["birthDate"]!.GetValue<string>());
        Assert.Equal("synthetic", strict.Data!["tags"]![0]!.GetValue<string>());
        Assert.Contains("AGREEMENT", DisplayMaskRules.Descriptions.Keys);
        var sdk = engine.SanitizeJson(input);
        Assert.Matches(@"^\[REDACTED:v1:[a-f0-9]{64}\]$", sdk.Data!["agreementnumber"]![0]!.GetValue<string>());
    }

    /// <summary>Recognize standalone formats in arbitrary fields without changing known field rules.</summary>
    [Theory]
    [InlineData("itemA", "sample@example.invalid", "EMAIL", "sam***@")]
    [InlineData("itemB", "+70012345678", "PHONE", "+7001****678")]
    [InlineData("itemC", "1-123/2026", "AGREEMENT", "00-000000/00")]
    [InlineData("itemD", "ДО-123459/13-л", "AGREEMENT", "ДО-****59/13-л")]
    [InlineData("note", "Email sample@example.invalid", "TEXT", "****")]
    [InlineData("note", "Phone +70012345678", "TEXT", "****")]
    [InlineData("note", "Договор ДО-123459/13-л", "TEXT", "****")]
    [InlineData("note", "Bearer synthetic-token", "TEXT", "****")]
    [InlineData("note", "password: synthetic-password", "TEXT", "****")]
    [InlineData("privateKey", "sample@example.invalid", "SECRET", "****")]
    [InlineData("paymentPurpose", "+70012345678", "TEXT", "****")]
    public void InfersDisplayRuleOnlyForUnknownFields(string field, string value, string code, string expectedSoft)
    {
        using var aliases = new Pseudonymizer(new byte[32], "test-display-inference");
        var input = new JsonObject { [field] = value }.ToJsonString();
        var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
        var engine = new PrivacyEngine(policy, aliases);
        var strict = engine.SanitizeJsonForDisplay(input);
        var soft = new SoftPartMasker(aliases, policy).SanitizeJson(input);

        Assert.True(strict.Allowed);
        Assert.True(soft.Allowed);
        string marker = strict.Data![field]!.GetValue<string>();
        Assert.StartsWith($"[REDACTED:v1:{code}:", marker);
        Assert.DoesNotContain(value, marker);
        Assert.Equal(expectedSoft, soft.Data![field]!.GetValue<string>());
    }

    /// <summary>Unknown fields under a fully masked field keep the conservative fallback.</summary>
    [Fact]
    public void FullMaskFieldDoesNotInferPartialMasksForUnknownDescendants()
    {
        using var aliases = new Pseudonymizer(new byte[32], "test-display-inference");
        var result = new SoftPartMasker(aliases).SanitizeJson("""
            {"privateKey":{"part":"sample@example.invalid"},"other":{"part":"sample@example.invalid"}}
            """);

        Assert.True(result.Allowed);
        Assert.Equal("****", result.Data!["privateKey"]!["part"]!.GetValue<string>());
        Assert.Equal("sam***@", result.Data!["other"]!["part"]!.GetValue<string>());
    }

    /// <summary>Retain technical primitives in both displays, including their numeric precision.</summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void KeepsOrdinaryNumbersAndFlagsWhileMaskingSensitiveFields(bool softPart)
    {
        using var aliases = new Pseudonymizer(new byte[32], "test-display-primitives");
        const string input = """
            {"numberId":9007199254740993,"active":true,"stats":[-1,1.234567890123456789,false,null],
             "inn":123456789012,"clientId":1234,"phone":[70012345678],
             "privateKey":{"part":55,"enabled":true},"note":"synthetic"}
            """;
        var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
        var engine = new PrivacyEngine(policy, aliases);
        var result = softPart ? new SoftPartMasker(aliases, policy).SanitizeJson(input) : engine.SanitizeJsonForDisplay(input);

        Assert.True(result.Allowed);
        Assert.Equal("9007199254740993", result.Data!["numberId"]!.ToJsonString());
        Assert.True(result.Data!["active"]!.GetValue<bool>());
        Assert.Equal("[-1,1.234567890123456789,false,null]", result.Data!["stats"]!.ToJsonString());
        Assert.DoesNotContain("123456789012", result.Data!["inn"]!.GetValue<string>());
        Assert.NotEqual("1234", result.Data!["clientId"]!.GetValue<string>());
        Assert.DoesNotContain("70012345678", result.Data!["phone"]![0]!.GetValue<string>());
        Assert.Equal("synthetic", result.Data!["note"]!.GetValue<string>());
        Assert.Equal(5, result.Replacements);

        var sdk = engine.SanitizeJson(input);
        Assert.True(sdk.SafeForAgent);
        Assert.DoesNotContain("9007199254740993", sdk.Data!.ToJsonString());
    }

    /// <summary>Preserve ordinary strings at any depth when the live name model and formal rules find no sensitive data.</summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void KeepsOrdinaryStringsWithThePlaygroundModel(bool softPart)
    {
        using var aliases = new Pseudonymizer(new byte[32], "test-display-text");
        const string input = """
            {"status":"approved","nested":{"category":"reporting","values":["synthetic","ABCD12345XYZ"]},
             "email":"not-a-formatted-address","note":"Email sample@example.invalid"}
            """;
        var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
        var model = MicroPersonModel.Load(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "person-default.bin")));
        var engine = new PrivacyEngine(policy, aliases, model);
        var result = softPart ? new SoftPartMasker(aliases, policy, model).SanitizeJson(input) : engine.SanitizeJsonForDisplay(input);

        Assert.True(result.Allowed);
        Assert.False(result.SafeForAgent);
        Assert.Equal("approved", result.Data!["status"]!.GetValue<string>());
        Assert.Equal("reporting", result.Data!["nested"]!["category"]!.GetValue<string>());
        Assert.Equal("synthetic", result.Data!["nested"]!["values"]![0]!.GetValue<string>());
        Assert.Equal("ABCD12345XYZ", result.Data!["nested"]!["values"]![1]!.GetValue<string>());
        Assert.NotEqual("not-a-formatted-address", result.Data!["email"]!.GetValue<string>());
        Assert.DoesNotContain("sample@example.invalid", result.Data!["note"]!.GetValue<string>());
        Assert.Equal(2, result.Replacements);

        var sdk = engine.SanitizeJson(input);
        Assert.DoesNotContain("approved", sdk.Data!.ToJsonString());
    }

    /// <summary>Reject a document atomically when its JSON or normalized keys are ambiguous.</summary>
    [Theory]
    [InlineData("{")]
    [InlineData("""{"lastName":"Тестов","last_name":"Тестин"}""")]
    [InlineData("""{"clientType":"individual","clientType":"legalEntity","inn":"000000000000"}""")]
    [InlineData("""{"phoneLinkedToFs":false,"phoneLinkedToFs":true,"phone":"+70012345678"}""")]
    public void RejectsAmbiguousDocument(string json)
    {
        using var aliases = new Pseudonymizer(new byte[32], "test-soft-part");
        var result = new SoftPartMasker(aliases).SanitizeJson(json);
        Assert.False(result.Allowed);
        Assert.Null(result.Data);
        Assert.Equal("privacy-processing-blocked", result.Status);
    }
}
