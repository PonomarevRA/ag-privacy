using System.Text;
using System.Xml.Linq;
using Xunit;

namespace AgPrivacy.Tests;

public sealed class StructuredPrivacyMaskerTests
{
    private const string Person = "Zorva Teluin";
    private const string Client = "UXC67013";
    private const string Secret = "qPLmT92v";
    private const string Trace = "00000000-0000-4000-8000-000000000001";

    /// <summary>Only the header identifies the role, including repeated headers and mixed CSV quoting.</summary>
    [Theory]
    [InlineData(',')]
    [InlineData(';')]
    [InlineData('\t')]
    public async Task CsvUsesHeaderForAllRows(char separator)
    {
        string header = string.Join(separator, "ФИО клиента", "client_id", "api-key", "status", "trace.id", "customField", "client_id", "birth_date", "date");
        string first = string.Join(separator, Person, Client, Secret, "\"ready" + separator + " \"\"quote\"\"\nnext\"", Trace, "Keller", Client, "1999-01-02", "2026-02-03");
        string second = string.Join(separator, Person, Client, Secret, "ready", Trace, "", Client, "", "2026-02-03");
        var result = await Run(header + "\r\n" + first + "\n" + second, csv: true, separator, bom: true);

        Assert.StartsWith(header + "\r\n", result.Output);
        Assert.Contains("\"ready" + separator + " \"\"quote\"\"\nnext\"", result.Output);
        Assert.Contains(Trace, result.Output);
        Assert.Contains("2026-02-03", result.Output);
        Assert.DoesNotContain("1999-01-02", result.Output);
        foreach (string source in new[] { Person, Client, Secret, "Keller" })
        {
            Assert.DoesNotContain(source, result.Output);
            Assert.DoesNotContain(source, result.Journal);
        }
        Assert.Equal(10, result.Count);
        Assert.Equal(2, result.Rules["PERSON"]);
        Assert.Equal(4, result.Rules["IDENTIFIER"]);
        Assert.Equal(3, result.Rules["SECRET"]);
        Assert.Equal(1, result.Rules["DATE"]);
        Assert.Equal(5, result.Journal.Split('\n', StringSplitOptions.RemoveEmptyEntries).Length);
        Assert.False(result.SafeForAgent);
    }

    /// <summary>Reject a malformed row before emitting any of its cells.</summary>
    [Theory]
    [InlineData("status,apiKey\nready,qPLmT92v,extra")]
    [InlineData("status,apiKey\nready")]
    [InlineData("status,apiKey\nready,\"qPLmT92v")]
    [InlineData("status,apiKey\nready,\"qPLmT92v\"tail")]
    public async Task CsvRejectsMalformedRows(string data)
    {
        using var aliases = new Pseudonymizer(new byte[32], "structured-fixture");
        using var input = new MemoryStream(Encoding.UTF8.GetBytes(data));
        using var output = new MemoryStream();
        var masker = new StructuredPrivacyMasker(Policy(), aliases);
        await Assert.ThrowsAsync<InvalidDataException>(() => masker.MaskCsvAsync(input, output));
        Assert.Equal("status,apiKey\r\n", Encoding.UTF8.GetString(output.ToArray()));
    }

    /// <summary>Match XML local names and combine adjacent text, CDATA and character references before masking.</summary>
    [Fact]
    public async Task XmlMasksElementsAttributesAndSensitiveDescendants()
    {
        string xml = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <a:r xmlns:a="urn:fixture" a:api-key="{Secret}" status="ready">
              <a:fullName>Zorva<![CDATA[ Tel]]>&#117;in</a:fullName>
              <clientId><part value="{Client}">{Client}</part></clientId>
              <trace id="{Trace}"><id>{Trace}</id></trace>
              <birthDate>1999-01-02</birthDate><date>2026-02-03</date>
              <message>left &amp; right</message><empty />
              <!-- comments can carry private values -->
              <?fixture comment?>
            </a:r>
            """;
        var result = await Run(xml, csv: false);
        var root = XDocument.Parse(result.Output).Root!;
        XNamespace ns = "urn:fixture";
        Assert.Equal(ns + "r", root.Name);
        Assert.Equal("ready", root.Attribute("status")!.Value);
        Assert.NotEqual(Person, root.Element(ns + "fullName")!.Value);
        Assert.Equal("left & right", root.Element("message")!.Value);
        Assert.Equal(Trace, root.Element("trace")!.Attribute("id")!.Value);
        Assert.Equal(Trace, root.Element("trace")!.Element("id")!.Value);
        Assert.Equal("2026-02-03", root.Element("date")!.Value);
        Assert.NotNull(root.Element("empty"));
        Assert.DoesNotContain("1999-01-02", result.Output);
        Assert.DoesNotContain(Client, result.Output);
        Assert.DoesNotContain(Secret, result.Output);
        Assert.DoesNotContain("<!--", result.Output);
        Assert.DoesNotContain("<?fixture", result.Output);
        Assert.Equal(5, result.Count);
    }

    /// <summary>Reject DTD and malformed XML with no raw input in the output.</summary>
    [Theory]
    [InlineData("<!DOCTYPE root [<!ENTITY data 'qPLmT92v'>]><root>&data;</root>")]
    [InlineData("<root><apiKey>qPLmT92v")]
    public async Task XmlRejectsMalformedDocuments(string data)
    {
        using var aliases = new Pseudonymizer(new byte[32], "structured-fixture");
        using var input = new MemoryStream(Encoding.UTF8.GetBytes(data));
        using var output = new MemoryStream();
        var masker = new StructuredPrivacyMasker(Policy(), aliases);
        await Assert.ThrowsAsync<System.Xml.XmlException>(() => masker.MaskXmlAsync(input, output));
        Assert.DoesNotContain(Secret, Encoding.UTF8.GetString(output.ToArray()));
    }

    /// <summary>Preserve long ordinary content while the header or element still masks the sensitive value.</summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task MasksPastReaderBufferBoundaries(bool csv)
    {
        string longValue = new('z', 23000);
        string ordinary = new string(' ', 8500) + "ready";
        string data = csv ? $"api_key,status,isin,ticker\n{longValue},{ordinary},US0000000001,ABCD"
            : $"<r><apiKey>{longValue}</apiKey><status>{ordinary}</status><isin>US0000000001</isin><ticker>ABCD</ticker></r>";
        var result = await Run(data, csv);
        Assert.DoesNotContain(longValue, result.Output);
        Assert.Contains(ordinary, result.Output);
        Assert.Contains("US0000000001", result.Output);
        Assert.Contains("ABCD", result.Output);
        Assert.Equal(1, result.Count);
    }

    /// <summary>Fail without returning an over-limit unit, keeping earlier complete CSV records.</summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task RejectsOversizedUnit(bool csv)
    {
        string longValue = new('z', 262145);
        string data = csv ? $"api_key,status\n{longValue},ready"
            : $"<root><apiKey>{longValue}</apiKey></root>";
        using var aliases = new Pseudonymizer(new byte[32], "structured-fixture");
        using var input = new MemoryStream(Encoding.UTF8.GetBytes(data));
        using var output = new MemoryStream();
        var masker = new StructuredPrivacyMasker(Policy(), aliases);
        await Assert.ThrowsAsync<InvalidDataException>(() => csv ? masker.MaskCsvAsync(input, output) : masker.MaskXmlAsync(input, output));
        Assert.DoesNotContain(new string('z', 30), Encoding.UTF8.GetString(output.ToArray()));
    }

    /// <summary>Detect recognizable API data in unknown fields without inferring from ordinary numbers.</summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task DetectsValuesWhenFieldIsUnknown(bool csv)
    {
        string data = csv ? "a,b,c,d\nexample@example.invalid,192.0.2.17,001234,ready"
            : "<root><a>example@example.invalid</a><b>192.0.2.17</b><c>001234</c><d>ready</d></root>";
        var result = await Run(data, csv);
        Assert.DoesNotContain("example@example.invalid", result.Output);
        Assert.DoesNotContain("192.0.2.17", result.Output);
        Assert.Contains("001234", result.Output);
        Assert.Contains("ready", result.Output);
        Assert.Equal(2, result.Count);
    }

    private static PrivacyPolicy Policy() => PrivacyPolicy.Compile(
        """{"schemaVersion":"ag-privacy-policy-v1","fields":{"customField":"SECRET"}}"""u8);

    /// <summary>Capture masked data and the metadata journal with independent synthetic inputs.</summary>
    private static async Task<(string Output, string Journal, long Count, bool SafeForAgent, IReadOnlyDictionary<string, long> Rules)> Run(
        string text, bool csv, char separator = ',', bool bom = false)
    {
        using var aliases = new Pseudonymizer(new byte[32], "structured-fixture");
        using var input = new MemoryStream(Encoding.UTF8.GetBytes(bom ? "\uFEFF" + text : text));
        using var output = new MemoryStream();
        using var journal = new StringWriter();
        var masker = new StructuredPrivacyMasker(Policy(), aliases);
        var result = csv ? await masker.MaskCsvAsync(input, output, separator, journal)
            : await masker.MaskXmlAsync(input, output, journal);
        return (Encoding.UTF8.GetString(output.ToArray()), journal.ToString(), result.Replacements, result.SafeForAgent, result.ReplacementsByType!);
    }
}
