# Run person models with ONNX

[Русский](onnx.md) · [English](onnx.en.md)

`AgPrivacy.Onnx` connects ONNX Runtime CPU to the `IPersonDetector` interface. The repository includes `models/person-default.onnx` and `models/person-prose.onnx`. Use them with `PrivacyEngine` and `StreamingPrivacyMasker`.

## Run the example

Use the .NET SDK specified by `global.json`. Run from the repository root.

```sh
dotnet run --project examples/Onnx -c Release -- \
  models/person-default.onnx models/person-prose.onnx \
  < examples/Onnx/input.ndjson > masked.ndjson
```

The executable reads UTF-8 NDJSON from stdin and writes masked records to stdout. The supplied input is synthetic. This example generates a session-local key. Applications that require stable substitutions across runs supply their own protected key and scope.

## Integrate with .NET

```sh
dotnet add /path/to/your-app reference /path/to/ag-privacy/src/AgPrivacy.Onnx/AgPrivacy.Onnx.csproj
```

```csharp
using System.Security.Cryptography;
using AgPrivacy;

using var model = OnnxPersonDetector.Load(File.ReadAllBytes("models/person-default.onnx"));
using var prose = OnnxPersonDetector.Load(File.ReadAllBytes("models/person-prose.onnx"));
var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
byte[] key = RandomNumberGenerator.GetBytes(32);
using var aliases = new Pseudonymizer(key, "my-application");
CryptographicOperations.ZeroMemory(key);

var stream = new StreamingPrivacyMasker(policy, aliases, model, null, null, null, prose);
await stream.MaskAsync(Console.OpenStandardInput(), Console.OpenStandardOutput());
```

A detector owns a reusable ONNX Runtime session. Dispose it after use. Calls on one instance are synchronized with disposal. `AgPrivacy.Onnx` depends on `Microsoft.ML.OnnxRuntime` 1.27.0, including the native runtime for the application platform.

To install local NuGet packages, run these commands.

```sh
dotnet pack src/AgPrivacy.Core -c Release -o ./packages
dotnet pack src/AgPrivacy.Onnx -c Release -o ./packages
dotnet add /path/to/your-app package AgPrivacy.Onnx --version 0.2.0 --source ./packages
```

## Export trained weights

The exporter accepts the `APNER001` format produced by `AgPrivacy.Train`. Use Python 3.10 or newer.

```sh
python3 -m venv .onnx-venv
.onnx-venv/bin/python -m pip install -r tools/onnx/requirements.txt
.onnx-venv/bin/python tools/onnx/export_person.py \
  models/person-prose.bin models/person-prose.onnx
```

On Windows, the environment's Python executable is `.onnx-venv\Scripts\python.exe`. Export again after training. `SourceModelVersion` identifies the source `.bin` SHA-256, while `Version` identifies the loaded `.onnx` SHA-256.

## Graph contract

The int64 `features` input has shape `[tokens, 3, 12]`. Each token has feature views for all three preceding BIO labels. The adapter uses the core tokenizer and feature hashes.

The graph sums int32 coefficients and uses `Scan` to predict labels sequentially. Ties select the first label. The int64 `labels` output has shape `[tokens]`. Files use ONNX IR 9 and opset 17 with embedded weights.

.NET performs tokenization and converts labels to UTF-16 spans. The ag-privacy pipeline handles format rules, field exceptions, context and substitutions. The graph contains the person perceptron. The surname-shape classifier and shadow observers are separate pipeline components.

Export uses the trained weights and requires no surname dataset. The adapter loads a trusted local graph up to one MiB. Token limits match `MicroPersonModel`. Backend errors are normalized to exceptions handled by the usual masking entry points.

## Verify

```sh
dotnet test tests/AgPrivacy.Onnx.Tests -c Release
.onnx-venv/bin/python -m unittest discover -s tools/onnx -p 'test_*.py'
```

Each model is compared on 200 synthetic strings. Tests also cover previous-label feedback, ties, empty input, 8192 tokens, concurrency, disposal and backend failure. Streaming tests compare complete output bytes for 80 records with different escaping.

These tests establish equivalence on their inputs. Detection quality depends on the trained weights and rules. Measure performance with your message sizes and application configuration.

See [ONNX Runtime C#](https://onnxruntime.ai/docs/tutorials/csharp/basic_csharp.html) and [ONNX Scan](https://onnx.ai/onnx/operators/onnx__Scan.html) for the underlying APIs.
