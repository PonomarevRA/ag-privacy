# WebNN person models

[Русский](webnn.md) · [English](webnn.en.md)

The browser adapter runs `person-default.bin` and `person-prose.bin` using WebNN or JavaScript. It returns `PERSON` spans measured in UTF-16 code units. The example replaces these spans with `[PERSON]` markers.

## Run the example

```sh
python3 -m http.server 47833 --bind 127.0.0.1
```

Open [127.0.0.1:47833/examples/WebNN/index.html](http://127.0.0.1:47833/examples/WebNN/index.html). Select the model and execution mode. The requested device is passed to WebNN as `cpu`, `gpu` or `npu`. Availability depends on the browser, OS and operator implementation.

WebNN requires a secure context, `navigator.ml.createContext`, `MLGraphBuilder` and float32 `matmul` support. HTTPS and loopback satisfy the example's hosting requirement. Browsers with experimental implementations may require enabling WebNN. The isolated Chromium test used `--enable-features=WebMachineLearningNeuralNetwork`.

## JavaScript API

```javascript
import { createPersonDetector } from "./adapters/web/person-detector.mjs";

const response = await fetch("./models/person-prose.bin");
if (!response.ok) throw new Error("model-unavailable");
const detector = await createPersonDetector(await response.arrayBuffer(), {
  backend: "auto",
  deviceType: "cpu"
});
try {
  const spans = await detector.find("Contact: Alina Zornicheva");
  console.log(spans);
  console.log(detector.status);
} finally {
  await detector.dispose();
}
```

| `backend` | Behavior |
| --- | --- |
| `auto` | Attempts WebNN, then uses JavaScript on failure and records the reason |
| `webnn` | Requires WebNN and rejects graph initialization or inference failures |
| `javascript` | Uses the portable local scorer |

`status.activeBackend` identifies the API actually used. `requestedDevice` records the device preference passed to the browser. `fallbackReason` reports an unavailable API, initialization failure, changed numerical scores or inference failure.

## Computation

The graph performs float32 matrix multiplication. Each token has three feature views for the possible preceding BIO labels. The input matrix stores feature-bucket counts. A constant matrix stores the model coefficients. JavaScript performs greedy label decoding, including transitions across batch boundaries.

The default batch contains 16 tokens. Set `batchTokens` from 1 to 32. With 8192 buckets, the default input matrix occupies 1.5 MiB. Tensors are reused and `find` calls are queued. `dispose` drains pending calls before releasing the graph and context.

Signed int16 coefficients are converted to float32. The sum of twelve coefficients fits within the exact-integer range of float32. A control matrix checks the graph before use. Changed scores make `auto` select JavaScript. This check complements comparisons on the target data and device.

Tokenization, Unicode casing, feature hashing and BIO decoding are checked against .NET. Limits match `MicroPersonModel` — 256 KiB of UTF-8 input, 8192 tokens and 256 UTF-16 code units per token. Inference uses model weights without a surname list.

## Integration boundary

This adapter implements the person model. The main ag-privacy pipeline provides contextual rules, email, phone, secret and identifier rules, and pseudonymization. Model spans can include misses and false positives.

The example loads static modules and weights from the same server. Entered text stays in the browser. The automated browser check observed only GET requests for assets.

## Verification

The JavaScript tests require Node.js 20 or newer.

```sh
node --test tests/javascript/*.test.mjs
dotnet run --project test-support/AgPrivacy.WebFixtures -c Release -- \
  tests/javascript/fixtures/person-model-parity.json
```

JavaScript and WebNN are checked against saved .NET results for 400 synthetic examples. Separate tests using a software implementation of the API contract exercise device loss, cleanup, queuing and fallback reasons.

On macOS arm64, isolated Chromium without the experimental flag exercised JavaScript fallback. With the flag enabled, both models passed all 400 comparisons through the real WebNN API with a CPU preference. This verifies that environment. GPU/NPU availability and performance depend on the target system.

See the official [WebNN specification](https://www.w3.org/TR/webnn/) for API requirements.
