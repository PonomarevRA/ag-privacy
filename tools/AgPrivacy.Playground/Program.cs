using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using AgPrivacy;

const int Port = 47832;
const string Host = "127.0.0.1:47832";
const string Origin = "http://" + Host;

var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions
{
    ContentRootPath = AppContext.BaseDirectory
});
// This tool accepts raw input. Disable request and exception logging in this host.
builder.Logging.ClearProviders();
builder.Configuration.Sources.Clear();
builder.WebHost.ConfigureKestrel(options =>
{
    options.Listen(IPAddress.Loopback, Port);
    options.Limits.MaxRequestBodySize = PrivacyLimits.InputBytes;
    options.AddServerHeader = false;
});

var policyPath = Path.Combine(AppContext.BaseDirectory, "default-policy.json");
var policy = PrivacyPolicy.Compile(File.ReadAllBytes(policyPath));
using var aliases = CreatePseudonymizer();
var personModelPath = Path.Combine(AppContext.BaseDirectory, "person-default.bin");
var persons = MicroPersonModel.Load(File.ReadAllBytes(personModelPath));
var engine = new PrivacyEngine(policy, aliases, persons);
var softPart = new SoftPartMasker(aliases, policy, persons);
var structured = new StructuredPrivacyMasker(policy, aliases);

using var metrics = new PrometheusMetrics();
await using var app = builder.Build();
app.Use(async (context, next) =>
{
    var headers = context.Response.Headers;
    headers.CacheControl = "no-store";
    headers.ContentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'none'; base-uri 'none'";
    headers.XContentTypeOptions = "nosniff";
    headers["Referrer-Policy"] = "no-referrer";

    // An exact Host check blocks DNS rebinding even when the remote address is loopback.
    if (context.Request.Host.Value != Host)
    {
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        return;
    }

    await next(context);
});
app.UseDefaultFiles();
app.UseStaticFiles();
app.MapGet("/metrics", () => Results.Text(metrics.Collect(), PrometheusMetrics.ContentType));
app.MapGet("/mask/rules", () =>
{
    var descriptions = new JsonObject();
    foreach (var entry in DisplayMaskRules.Descriptions)
        descriptions.Add(entry.Key, entry.Value);

    return Results.Json(descriptions, PrivacyJsonContext.Default.JsonNode);
});
app.MapGet("/mask/field-exceptions", () =>
{
    var fields = new JsonArray();
    foreach (string field in policy.DisplayFieldExceptions.Fields.Order(StringComparer.OrdinalIgnoreCase))
        fields.Add(field);
    return Results.Json(fields, PrivacyJsonContext.Default.JsonNode);
});
app.MapPost("/mask/csv", (HttpRequest request) => MaskStructuredAsync(request, structured, csv: true));
app.MapPost("/mask/xml", (HttpRequest request) => MaskStructuredAsync(request, structured, csv: false));
app.MapPost("/mask/{format}", (string format, HttpRequest request) =>
    MaskAsync(format, request, engine, softPart, policy.DisplayFieldExceptions));

await app.StartAsync();
Console.WriteLine($"ag-privacy: {Origin}");
await app.WaitForShutdownAsync();

/// <summary>Keep aliases comparable within one server run without retaining the key across restarts.</summary>
static Pseudonymizer CreatePseudonymizer()
{
    byte[] key = RandomNumberGenerator.GetBytes(32);
    try
    {
        return new Pseudonymizer(key, "local-masking-playground");
    }
    finally
    {
        CryptographicOperations.ZeroMemory(key);
    }
}

/// <summary>Read one bounded UTF-8 document and return the result for the explicitly selected route or a fixed error.</summary>
static async Task<IResult> MaskAsync(string format, HttpRequest request, PrivacyEngine engine, SoftPartMasker softPart, DisplayFieldExceptions defaults)
{
    if (request.Headers.Origin != Origin)
        return Results.StatusCode(StatusCodes.Status403Forbidden);
    if (format is not ("text" or "json" or "soft-part" or "guid-only" or "log-types"))
        return Results.NotFound();

    var exceptions = defaults;
    if ((format is "json" or "soft-part") && request.Headers.TryGetValue("X-Display-Field-Exceptions", out var values))
    {
        if (values.Count != 1 || values[0] is not { Length: > 0 and <= 29000 } encoded)
            return Results.BadRequest();
        try
        {
            using var list = JsonDocument.Parse(Uri.UnescapeDataString(encoded), new JsonDocumentOptions { MaxDepth = 2 });
            exceptions = DisplayFieldExceptions.Compile(list.RootElement);
        }
        catch (Exception exception) when (exception is ArgumentException or JsonException or UriFormatException)
        {
            return Results.BadRequest();
        }
    }

    string input;
    try
    {
        using var reader = new StreamReader(request.Body, new UTF8Encoding(false, true), detectEncodingFromByteOrderMarks: false, leaveOpen: true);
        input = await reader.ReadToEndAsync(request.HttpContext.RequestAborted);
    }
    catch (BadHttpRequestException exception)
    {
        return Results.StatusCode(exception.StatusCode);
    }
    catch (DecoderFallbackException)
    {
        return Results.BadRequest();
    }

    bool includePreview = request.Headers["X-Mask-Preview"] == "1";
    var result = format switch
    {
        "soft-part" => softPart.SanitizeJson(input, exceptions, includePreview),
        "json" => engine.SanitizeJsonForDisplay(input, exceptions, includePreview),
        "guid-only" => engine.SanitizeGuidsForDisplay(input),
        "log-types" => engine.SanitizeTypedLogForDisplay(input, includePreview),
        _ => engine.SanitizeText(input)
    };
    if (!result.Allowed)
        return Results.UnprocessableEntity();

    return Results.Json(result, PrivacyJsonContext.Default.PrivacyResult);
}

/// <summary>Mask a bounded file using the streaming library, returning only complete output and rule counts.</summary>
static async Task<IResult> MaskStructuredAsync(HttpRequest request, StructuredPrivacyMasker masker, bool csv)
{
    if (request.Headers.Origin != Origin)
        return Results.StatusCode(StatusCodes.Status403Forbidden);

    char separator = ',';
    if (csv)
    {
        separator = request.Query["delimiter"].ToString() switch
        {
            "" or "comma" => ',',
            "semicolon" => ';',
            "tab" => '\t',
            _ => '\0'
        };
        if (separator == '\0') return Results.BadRequest();
    }

    using var output = new MemoryStream();
    StreamMaskResult masked;
    try
    {
        masked = csv
            ? await masker.MaskCsvAsync(request.Body, output, separator, cancellationToken: request.HttpContext.RequestAborted)
            : await masker.MaskXmlAsync(request.Body, output, cancellationToken: request.HttpContext.RequestAborted);
    }
    catch (BadHttpRequestException exception)
    {
        return Results.StatusCode(exception.StatusCode);
    }
    catch (Exception exception) when (exception is InvalidDataException or DecoderFallbackException
        or System.Xml.XmlException or System.Text.RegularExpressions.RegexMatchTimeoutException or InvalidOperationException)
    {
        return Results.UnprocessableEntity();
    }

    var counts = new JsonObject();
    if (masked.ReplacementsByType is { } rules)
        foreach (var (rule, count) in rules)
            counts.Add(rule, count);
    var response = new JsonObject
    {
        ["Text"] = Encoding.UTF8.GetString(output.GetBuffer().AsSpan(0, (int)output.Length)),
        ["Replacements"] = masked.Replacements,
        ["SafeForAgent"] = masked.SafeForAgent,
        ["ReplacementsByType"] = counts,
        ["AgentNotice"] = "Маскировка выборочная. Нераспознанные значения могут остаться в исходном виде."
    };
    return Results.Json(response, PrivacyJsonContext.Default.JsonNode);
}
