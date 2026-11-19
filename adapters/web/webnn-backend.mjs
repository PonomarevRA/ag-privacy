import { features } from "./person-model.mjs";

/** Release partially created WebNN resources without hiding the inference error. */
function destroyAll(resources) {
  for (const resource of resources) {
    try { resource?.destroy(); } catch { /* A lost context can already own destroyed tensors. */ }
  }
}

/** Build a bounded float32 matrix scorer. Sequence decoding belongs to the caller. */
export async function createWebNNBackend(model, { deviceType, batchTokens }) {
  if (!globalThis.navigator?.ml?.createContext || typeof globalThis.MLGraphBuilder !== "function") {
    throw new Error("webnn-unavailable");
  }
  const rows = batchTokens * 3;
  let context;
  let graph;
  let input;
  let output;
  try {
    context = await navigator.ml.createContext({ deviceType });
    const builder = new MLGraphBuilder(context);
    const descriptor = { dataType: "float32", shape: [rows, model.buckets] };
    const values = builder.input("features", descriptor);
    const weights = builder.constant({ dataType: "float32", shape: [model.buckets, 3] },
      Float32Array.from(model.weights));
    graph = await builder.build({ scores: builder.matmul(values, weights) });
    input = await context.createTensor({ ...descriptor, writable: true });
    output = await context.createTensor({ dataType: "float32", shape: [rows, 3], readable: true });
    const counts = new Float32Array(rows * model.buckets);

    /** Execute one whole matrix, retaining bounded reusable tensors. */
    async function runMatrix() {
      context.writeTensor(input, counts);
      context.dispatch(graph, { features: input }, { scores: output });
      const scores = new Float32Array(await context.readTensor(output));
      if (scores.length !== rows * 3) throw new Error("webnn-invalid-output");
      for (const score of scores) {
        if (!Number.isInteger(score) || Math.abs(score) > 12 * 32768) {
          throw new Error("webnn-numerics-mismatch");
        }
      }
      return scores;
    }

    // Every score is an integer within float32's exact range. Reject a backend that changes these values.
    for (let row = 0; row < rows; row++) {
      for (let feature = 0; feature < 12; feature++) {
        counts[row * model.buckets + (row * 17 + feature * 31) % model.buckets]++;
      }
    }
    const probe = await runMatrix();
    for (let row = 0; row < rows; row++) {
      for (let label = 0; label < 3; label++) {
        let expected = 0;
        for (let feature = 0; feature < 12; feature++) {
          expected += model.weights[((row * 17 + feature * 31) % model.buckets) * 3 + label];
        }
        if (probe[row * 3 + label] !== expected) throw new Error("webnn-numerics-mismatch");
      }
    }

    return {
      /** Score all previous-label views in fixed-size batches, including a padded final batch. */
      async predict(tokens) {
        const result = new Float32Array(tokens.length * 9);
        for (let start = 0; start < tokens.length; start += batchTokens) {
          counts.fill(0);
          const end = Math.min(start + batchTokens, tokens.length);
          for (let index = start; index < end; index++) {
            for (let previous = 0; previous < 3; previous++) {
              const row = (index - start) * 3 + previous;
              for (const feature of features(tokens, index, previous, model.buckets)) {
                counts[row * model.buckets + feature]++;
              }
            }
          }
          const scores = await runMatrix();
          result.set(scores.subarray(0, (end - start) * 9), start * 9);
        }
        return result;
      },
      /** Release graph, tensors and context after the owner drains in-flight calls. */
      destroy() {
        counts.fill(0);
        destroyAll([input, output, graph, context]);
      }
    };
  } catch (error) {
    destroyAll([input, output, graph, context]);
    if (error?.message === "webnn-numerics-mismatch") throw error;
    throw new Error("webnn-initialization-failed");
  }
}
