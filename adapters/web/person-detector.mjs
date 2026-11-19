import { bestLabel, decode, predictJavaScript, readPersonModel, tokenize } from "./person-model.mjs";
import { createWebNNBackend } from "./webnn-backend.mjs";

/** Create a local detector with explicit WebNN, portable JavaScript, or reported automatic fallback. */
export async function createPersonDetector(modelBytes, options = {}) {
  const { backend = "auto", deviceType = "cpu", batchTokens = 16 } = options;
  if (!["auto", "webnn", "javascript"].includes(backend) ||
      !["cpu", "gpu", "npu"].includes(deviceType) ||
      !Number.isInteger(batchTokens) || batchTokens < 1 || batchTokens > 32) {
    throw new Error("invalid-person-options");
  }
  if (!(modelBytes instanceof Uint8Array || modelBytes instanceof ArrayBuffer) ||
      modelBytes.byteLength > 16 + 8192 * 6) {
    throw new Error("invalid-person-model");
  }
  const snapshot = new Uint8Array(modelBytes instanceof Uint8Array ? modelBytes : new Uint8Array(modelBytes));
  const model = readPersonModel(snapshot);
  const digest = await crypto.subtle.digest("SHA-256", snapshot);
  const version = Array.from(new Uint8Array(digest), value => value.toString(16).padStart(2, "0")).join("");
  let native = null;
  let activeBackend = "javascript";
  let fallbackReason = null;
  let disposed = false;
  let tail = Promise.resolve();

  if (backend !== "javascript") {
    try {
      native = await createWebNNBackend(model, { deviceType, batchTokens });
      activeBackend = "webnn";
    } catch (error) {
      if (backend === "webnn") throw error;
      fallbackReason = error.message;
    }
  }

  /** Run a single queued inference while preserving the previous label across batches. */
  async function run(text) {
    const tokens = tokenize(text);
    if (tokens.length === 0) return [];
    if (native) {
      try {
        const scores = await native.predict(tokens);
        let previous = 0;
        const labels = [];
        for (let index = 0; index < tokens.length; index++) {
          previous = bestLabel(scores, index * 9 + previous * 3);
          labels.push(previous);
        }
        return decode(tokens, labels);
      } catch {
        native.destroy();
        native = null;
        if (backend === "webnn") {
          activeBackend = null;
          throw new Error("webnn-inference-failed");
        }
        activeBackend = "javascript";
        fallbackReason = "webnn-inference-failed";
      }
    }
    if (activeBackend === null) throw new Error("webnn-inference-failed");
    return predictJavaScript(model, tokens);
  }

  return {
    version,
    /** Report the active API and requested device without claiming a specific physical processor. */
    get status() {
      return { requestedBackend: backend, activeBackend, requestedDevice: deviceType, fallbackReason };
    },
    /** Return PERSON intervals in UTF-16 coordinates. The detector does not authorize disclosure. */
    find(text) {
      if (disposed) return Promise.reject(new Error("person-detector-disposed"));
      const result = tail.then(() => run(text));
      tail = result.catch(() => {});
      return result;
    },
    /** Wait for queued operations, then free native resources and reject subsequent calls. */
    async dispose() {
      if (disposed) return tail;
      disposed = true;
      await tail;
      native?.destroy();
      native = null;
    }
  };
}
