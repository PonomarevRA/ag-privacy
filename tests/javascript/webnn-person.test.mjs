import assert from "node:assert/strict";
import fs from "node:fs/promises";
import test from "node:test";
import { createPersonDetector } from "../../adapters/web/person-detector.mjs";
import { features, readPersonModel, tokenize } from "../../adapters/web/person-model.mjs";

const fixtures = JSON.parse(await fs.readFile(new URL("./fixtures/person-model-parity.json", import.meta.url), "utf8"));

/** Load shipped numerical weights from a repository-relative location. */
async function modelBytes(name = "person-prose") {
  return fs.readFile(new URL("../../models/" + name + ".bin", import.meta.url));
}

/** Emulate the WebNN resource contract and matrix operation for control-flow tests only. */
function installWebNN({ failBuild = false, corrupt = false } = {}) {
  const oldNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  const oldBuilder = Object.getOwnPropertyDescriptor(globalThis, "MLGraphBuilder");
  const state = { destroyed: 0, dispatches: 0, failDispatch: false, outstanding: 0, maxOutstanding: 0 };

  class Context {
    async createTensor(descriptor) {
      return { descriptor, data: null, destroy() { state.destroyed++; } };
    }
    writeTensor(tensor, values) { tensor.data = values.slice(); }
    dispatch(graph, inputs, outputs) {
      if (state.failDispatch) throw new Error("simulated-device-loss");
      state.dispatches++;
      state.outstanding++;
      state.maxOutstanding = Math.max(state.maxOutstanding, state.outstanding);
      const [rows, buckets] = inputs.features.descriptor.shape;
      const scores = new Float32Array(rows * 3);
      const values = inputs.features.data;
      const weights = graph.weights;
      for (let row = 0; row < rows; row++) {
        for (let feature = 0; feature < buckets; feature++) {
          const count = values[row * buckets + feature];
          if (count === 0) continue;
          for (let label = 0; label < 3; label++) {
            scores[row * 3 + label] += count * weights[feature * 3 + label];
          }
        }
      }
      if (corrupt) scores[0] += 0.5;
      outputs.scores.data = scores;
    }
    async readTensor(tensor) {
      await new Promise(resolve => setImmediate(resolve));
      state.outstanding--;
      return tensor.data.buffer.slice(0);
    }
    destroy() { state.destroyed++; }
  }
  class Builder {
    input(name, descriptor) { return { name, descriptor }; }
    constant(descriptor, values) { return { descriptor, values }; }
    matmul(input, weights) { return { input, weights }; }
    async build(outputs) {
      if (failBuild) throw new Error("simulated-build-failure");
      return { weights: outputs.scores.weights.values, destroy() { state.destroyed++; } };
    }
  }
  Object.defineProperty(globalThis, "navigator", {
    configurable: true, value: { ml: { async createContext(options) { state.deviceType = options.deviceType; return new Context(); } } }
  });
  Object.defineProperty(globalThis, "MLGraphBuilder", { configurable: true, value: Builder });
  return {
    state,
    restore() {
      if (oldNavigator) Object.defineProperty(globalThis, "navigator", oldNavigator);
      else delete globalThis.navigator;
      if (oldBuilder) Object.defineProperty(globalThis, "MLGraphBuilder", oldBuilder);
      else delete globalThis.MLGraphBuilder;
    }
  };
}

test("Unicode token boundaries, invariant case and all hashed features match .NET", () => {
  const expected = fixtures.unicode.tokens;
  const tokens = tokenize(fixtures.unicode.text);
  assert.equal(tokens.length, expected.length);
  for (let index = 0; index < tokens.length; index++) {
    const item = expected[index];
    assert.deepEqual(tokens[index], { start: item.start, length: item.length, word: item.word, lower: item.lower });
    for (let previous = 0; previous < 3; previous++) {
      assert.deepEqual(features(tokens, index, previous, 8192), item.features[previous]);
    }
  }
});

test("both JavaScript model versions reproduce all 400 .NET synthetic cases", async () => {
  for (const [name, fixture] of Object.entries(fixtures.models)) {
    const detector = await createPersonDetector(await modelBytes(name), { backend: "javascript" });
    assert.equal(detector.version, fixture.sha256);
    for (const example of fixture.examples) {
      assert.deepEqual(await detector.find(example.text), example.spans, "model-span-parity");
    }
    assert.deepEqual(await detector.find(""), []);
    await detector.dispose();
  }
});

test("WebNN contract path preserves greedy state across padded batches", async () => {
  const fake = installWebNN();
  try {
    for (const [name, fixture] of Object.entries(fixtures.models)) {
      const detector = await createPersonDetector(await modelBytes(name), { backend: "webnn", batchTokens: 2 });
      assert.equal(detector.status.activeBackend, "webnn");
      for (const example of fixture.examples) {
        assert.deepEqual(await detector.find(example.text), example.spans, "matrix-span-parity");
      }
      await detector.dispose();
    }
    assert.ok(fake.state.dispatches > 400);
  } finally { fake.restore(); }
});

test("auto fallback exposes missing WebNN and explicit WebNN rejects it", async () => {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  Object.defineProperty(globalThis, "navigator", { configurable: true, value: {} });
  try {
    const bytes = await modelBytes();
    const detector = await createPersonDetector(bytes);
    assert.deepEqual(detector.status, {
      requestedBackend: "auto", activeBackend: "javascript", requestedDevice: "cpu", fallbackReason: "webnn-unavailable"
    });
    await assert.rejects(createPersonDetector(bytes, { backend: "webnn" }), /webnn-unavailable/);
    await detector.dispose();
  } finally {
    if (descriptor) Object.defineProperty(globalThis, "navigator", descriptor);
    else delete globalThis.navigator;
  }
});

test("failed initialization and numerically changed scores trigger a reported fallback", async () => {
  for (const options of [{ failBuild: true }, { corrupt: true }]) {
    const fake = installWebNN(options);
    try {
      const detector = await createPersonDetector(await modelBytes());
      assert.equal(detector.status.activeBackend, "javascript");
      assert.equal(detector.status.fallbackReason,
        options.corrupt ? "webnn-numerics-mismatch" : "webnn-initialization-failed");
      assert.ok(fake.state.destroyed > 0);
      await detector.dispose();
    } finally { fake.restore(); }
  }
});

test("device loss switches auto to JavaScript and explicit WebNN blocks output", async () => {
  for (const backend of ["auto", "webnn"]) {
    const fake = installWebNN();
    try {
      const detector = await createPersonDetector(await modelBytes(), { backend });
      fake.state.failDispatch = true;
      const example = fixtures.models["person-prose"].examples[5];
      if (backend === "auto") {
        assert.deepEqual(await detector.find(example.text), example.spans);
        assert.equal(detector.status.activeBackend, "javascript");
        assert.equal(detector.status.fallbackReason, "webnn-inference-failed");
      } else {
        await assert.rejects(detector.find(example.text), /webnn-inference-failed/);
        assert.equal(detector.status.activeBackend, null);
        await assert.rejects(detector.find(example.text), /webnn-inference-failed/);
      }
      await detector.dispose();
    } finally { fake.restore(); }
  }
});

test("queued inference and disposal do not reuse a destroyed tensor", async () => {
  const fake = installWebNN();
  try {
    const detector = await createPersonDetector(await modelBytes(), { backend: "webnn", deviceType: "gpu" });
    const sample = fixtures.models["person-prose"].examples[8];
    const first = detector.find(sample.text);
    const second = detector.find(sample.text);
    const disposed = detector.dispose();
    assert.deepEqual(await first, sample.spans);
    assert.deepEqual(await second, sample.spans);
    await disposed;
    assert.equal(fake.state.maxOutstanding, 1);
    assert.equal(fake.state.deviceType, "gpu");
    assert.ok(fake.state.destroyed >= 4);
    await assert.rejects(detector.find(sample.text), /disposed/);
    await detector.dispose();
  } finally { fake.restore(); }
});

test("model headers, options, input byte limits and UTF-16 are validated", async () => {
  const bytes = await modelBytes();
  assert.throws(() => readPersonModel(1000000), /invalid-person-model/);
  assert.throws(() => readPersonModel(bytes.subarray(0, 20)), /invalid-person-model/);
  await assert.rejects(createPersonDetector(bytes, { backend: "unknown" }), /options/);
  await assert.rejects(createPersonDetector(bytes, { batchTokens: 33 }), /options/);
  await assert.rejects(createPersonDetector(new Uint8Array(1000000)), /invalid-person-model/);
  const detector = await createPersonDetector(bytes, { backend: "javascript" });
  await assert.rejects(detector.find("\ud800"), /invalid-person-input/);
  await assert.rejects(detector.find("a".repeat(257)), /token-limit/);
  await assert.rejects(detector.find("a ".repeat(8193)), /token-limit/);
  await assert.rejects(detector.find("я".repeat(140000)), /input-limit/);
  await detector.find("a ".repeat(8192));
  await detector.dispose();
});
