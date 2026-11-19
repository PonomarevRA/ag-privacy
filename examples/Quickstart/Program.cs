using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using AgPrivacy;

string outputDirectory = Path.GetFullPath(args.Length == 0 ? "demo-output" : args[0]);
Directory.CreateDirectory(outputDirectory);
var policy = PrivacyPolicy.Compile(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "default-policy.json")));
var model = MicroPersonModel.Load(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "person-default.bin")));
var prose = MicroPersonModel.Load(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "person-prose.bin")));

// A fresh private key makes this demo safe to rerun. Applications supply their own persistent secret.
byte[] privateKey = RandomNumberGenerator.GetBytes(32);
using var aliases = new Pseudonymizer(privateKey, "generated-public-demo");
CryptographicOperations.ZeroMemory(privateKey);
var engine = new PrivacyEngine(policy, aliases, model);
var partial = new SoftPartMasker(aliases, policy, model);
var structured = new StructuredPrivacyMasker(policy, aliases);
var jsonOptions = new JsonSerializerOptions
{
    WriteIndented = true,
    Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
};

// All values below are invented fixtures. Reserved domains and example IP ranges identify test data.
var record = new Dictionary<string, object>
{
    ["status"] = "approved",
    ["category"] = "demo",
    ["numberId"] = 42,
    ["tags"] = new[] { "demo", "sample" },
    ["email"] = "sample.person@example.test",
    ["customContact"] = "another.person@example.test",
    ["customPhone"] = "+7 999 123-45-67",
    ["customAgreement"] = "12-451123/26",
    ["sample.key@example.test"] = "ordinary value",
    ["+7 999 765-43-21"] = "ordinary value",
    ["isin"] = "US0378331005",
    ["ticker"] = "DEMO"
};
string json = JsonSerializer.Serialize(record, jsonOptions);
Write("json_before.json", json);
var display = engine.SanitizeJsonForDisplay(json);
var soft = partial.SanitizeJson(json);
if (!display.Allowed || !soft.Allowed || display.Data is null || soft.Data is null)
    throw new InvalidOperationException("demo-masking-blocked");
Write("json_strict_display.json", display.Data.ToJsonString(jsonOptions));
Write("json_soft_part.json", soft.Data.ToJsonString(jsonOptions));

string[] messages =
[
    "client: Alina Sokolova; email=sample.person@example.test; status=approved",
    "ФИО: Алина Зорничева-Левчанова; дата рождения: 14.08.1987; дата подписания: 14.08.1987",
    "service account login=sokolova_io; api-key=fixtureOnlyToken0001",
    "recipient: sample.person@example.test; source IP: 192.0.2.42; completed"
];
string ndjson = string.Join('\n', messages.Select(message => JsonSerializer.Serialize(
    new Dictionary<string, object>
    {
        ["trace.id"] = "demo-trace-0001",
        ["status"] = "ok",
        ["message"] = message
    }))) + "\n";
Write("logs_before.ndjson", ndjson);
using var logInput = new MemoryStream(Encoding.UTF8.GetBytes(ndjson));
using var logOutput = new MemoryStream();
using var journal = new StringWriter();
var stream = new StreamingPrivacyMasker(policy, aliases, model, null, null, null, prose);
var logCounts = await stream.MaskAsync(logInput, logOutput, journal);
string maskedLogs = Encoding.UTF8.GetString(logOutput.ToArray());
foreach (string line in maskedLogs.Split('\n', StringSplitOptions.RemoveEmptyEntries))
{
    using var parsed = JsonDocument.Parse(line);
    if (parsed.RootElement.GetProperty("trace.id").GetString() != "demo-trace-0001")
        throw new InvalidOperationException("demo-trace-correlation");
}
if (maskedLogs.Contains("sample.person@example.test", StringComparison.Ordinal) ||
    maskedLogs.Contains("fixtureOnlyToken0001", StringComparison.Ordinal))
    throw new InvalidOperationException("demo-sensitive-value-retained");
Write("logs_after.ndjson", maskedLogs);

const string csv = "fullName;email;status;trace.id\nFixture Person;sample.person@example.test;approved;demo-trace-0001\n";
const string xml = "<records><record><fullName>Fixture Person</fullName><email>sample.person@example.test</email><status>approved</status></record></records>";
using var csvInput = new MemoryStream(Encoding.UTF8.GetBytes(csv));
using var csvOutput = new MemoryStream();
var csvCounts = await structured.MaskCsvAsync(csvInput, csvOutput, ';');
using var xmlInput = new MemoryStream(Encoding.UTF8.GetBytes(xml));
using var xmlOutput = new MemoryStream();
var xmlCounts = await structured.MaskXmlAsync(xmlInput, xmlOutput);
Write("table_before.csv", csv);
Write("table_after.csv", Encoding.UTF8.GetString(csvOutput.ToArray()));
Write("document_before.xml", xml);
Write("document_after.xml", Encoding.UTF8.GetString(xmlOutput.ToArray()));
Write("summary.json", JsonSerializer.Serialize(new
{
    synthetic = true,
    display = display.ReplacementsByType,
    softPart = soft.ReplacementsByType,
    logReplacements = logCounts.Replacements,
    logConservativeMasks = logCounts.ConservativeMasks,
    csv = csvCounts.ReplacementsByType,
    xml = xmlCounts.ReplacementsByType
}, jsonOptions));
Console.WriteLine("Generated 10 synthetic example files. Trace correlation and sensitive-value checks passed.");

/// <summary>Write a generated fixture with a consistent UTF-8 representation.</summary>
void Write(string name, string content)
{
    File.WriteAllText(Path.Combine(outputDirectory, name), content.TrimEnd('\r', '\n') + "\n", new UTF8Encoding(false));
}
