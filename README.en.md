# ag-privacy

[Русский](README.ru.md) · [English](README.en.md) · [FI/FIO recall preview](docs/recall337-preview.en.md) · [FI/FIO model v1.0.0](docs/fi-fio-model-v1.en.md) · [Lowercase FIO preview](docs/fio-lowercase-preview.en.md) · [Default FI/FIO model v2.0.0](docs/fi-fio-model-v2.en.md)

A local .NET 10 library for masking JSON, log messages, CSV, TSV and XML. It provides a streaming CLI, a local UI, ONNX Runtime integration and a browser person detector using WebNN. Surname lists are external training inputs. Inference uses model weights, format rules and context.

## Install

Use .NET SDK 10.0.102 or a compatible 10.0.1xx SDK.

```sh
git clone https://github.com/PonomarevRA/ag-privacy.git
cd ag-privacy
dotnet build src/AgPrivacy.Core -c Release
dotnet build src/AgPrivacy.Cli -c Release
```

To install a locally built NuGet package, run these commands from the repository root.

```sh
dotnet pack src/AgPrivacy.Core -c Release -o ./packages
dotnet new console --framework net10.0 -o ./demo-app
dotnet add ./demo-app package AgPrivacy.Core --version 0.2.0 --source ./packages
```

## Local UI

```sh
dotnet run --project tools/AgPrivacy.Playground -c Release
```

Open [127.0.0.1:47832](http://127.0.0.1:47832). The «Сравнить режимы» button compares strict display masking, soft-part and typed substitution side by side, with replacement highlights and rule counts. In this UI, strict refers to the JSON display mode.

CSV, TSV and XML files can be uploaded and downloaded. The UI detects UTF-8 or Windows-1251 and the table delimiter. Downloads preserve the selected delimiter and add `_masked` to the filename.

The [synthetic before-and-after examples](https://github.com/PonomarevRA/ag-privacy/tree/main/examples/generated) contain actual generated output and document observed detector limitations.

## Integrate with C#

```sh
dotnet add /path/to/your-app reference /path/to/ag-privacy/src/AgPrivacy.Core/AgPrivacy.Core.csproj
```

```csharp
using System.Security.Cryptography;
using AgPrivacy;

var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
byte[] key = RandomNumberGenerator.GetBytes(32);
using var aliases = new Pseudonymizer(key, "my-application");
CryptographicOperations.ZeroMemory(key);
var engine = new PrivacyEngine(policy, aliases);

var result = engine.SanitizeJsonForDisplay(
    """{"email":"sample.person@example.test","status":"approved"}""");
if (!result.Allowed) throw new InvalidOperationException("Masking failed");
Console.WriteLine(result.Data!.ToJsonString());
```

The host owns the secret key and substitution scope. The same key, scope, type and value produce a stable substitution. Keep the key in protected application storage when substitutions must remain consistent across runs.

## Streaming CLI

The following Linux/macOS example uses Python 3 to create a private key file. The key and journal paths must be new.

```sh
python3 -c 'import os,secrets; f=os.open(".demo.key",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600); os.write(f,secrets.token_bytes(32)); os.close(f)'
dotnet run --project src/AgPrivacy.Cli -c Release -- stream-log \
  policies/default.json .demo.key demo-scope demo-journal.ndjson \
  < examples/Onnx/input.ndjson > masked.ndjson
```

stdout contains the masked UTF-8 stream. A separate journal records rule types, substitutions and opaque identifiers. `stream-log` preserves `trace.id` for event correlation. Use `stream-csv` with `comma`, `semicolon` or `tab` for CSV, and `stream-xml` for XML.

## ONNX Runtime

```sh
dotnet run --project examples/Onnx -c Release -- \
  models/person-default.onnx models/person-prose.onnx \
  < examples/Onnx/input.ndjson > onnx-masked.ndjson
```

The [ONNX guide](docs/onnx.en.md) covers the `AgPrivacy.Onnx` adapter, local packages, exporting trained weights and the graph contract.

## WebNN in the browser

Start a loopback static server from the repository root.

```sh
python3 -m http.server 47833 --bind 127.0.0.1
```

Open the [browser example](http://127.0.0.1:47833/examples/WebNN/index.html). It reports the active backend. In `auto` mode, unavailable WebNN falls back to JavaScript and reports the reason. The «Только WebNN» option requires WebNN and returns an error when the API or device fails.

The [WebNN guide](docs/webnn.en.md) describes the JavaScript API, browser requirements and verification results. WebNN uses the original `person-default.bin` and `person-prose.bin` weights. The browser adapter returns person spans. The main pipeline supplies rules for other data types and performs substitution.

## Tests and limits

JavaScript tests require Node.js 20 or newer.

```sh
dotnet test tests/AgPrivacy.Tests -c Release
dotnet test tests/AgPrivacy.Onnx.Tests -c Release
node --test tests/javascript/*.test.mjs
```

`PrivacyEngine.SanitizeJson` provides the strict disclosure boundary. Display modes and the browser detector can miss sensitive data and produce false masks. Check `Allowed`, `SafeForAgent` and the selected API contract before passing results onward.

Open-data sources and third-party licenses are listed in [the notices](notices/THIRD-PARTY-NOTICES.TXT). Inference runs locally. The browser example loads static assets from the same server.

## Masking person names in JSON logs

The PERSON field policy covers values under `fio`, `ФИО` and `fullName`, as well as component fields such as `firstName`, `lastName` / `surname` and `middleName` / `patronymic`. It works with ordinary JSON, escaped Unicode, and embedded JSON inside a `message` string. Property names and accompanying `trace.id`, `ticker` and `status` values are preserved in the tested cases.

Use `SanitizeTypedLogForDisplay` with `LogAnalysisMode.Mixed` to pass separate detectors for prose and decoded JSON values. Explicit PERSON fields also work without a detector.
