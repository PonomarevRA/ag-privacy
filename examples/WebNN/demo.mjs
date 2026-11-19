import { createPersonDetector } from "../../adapters/web/person-detector.mjs";

const controls = {
  model: document.querySelector("#model"),
  backend: document.querySelector("#backend"),
  device: document.querySelector("#device"),
  source: document.querySelector("#source"),
  run: document.querySelector("#run"),
  status: document.querySelector("#status"),
  result: document.querySelector("#result"),
  counts: document.querySelector("#counts")
};
let detector = null;
let configuration = "";
const reasons = {
  "webnn-unavailable": "WebNN отсутствует в этом браузере.",
  "webnn-initialization-failed": "WebNN не смог создать граф для выбранного устройства.",
  "webnn-numerics-mismatch": "Проверка точности WebNN не прошла.",
  "webnn-inference-failed": "Вычисление WebNN завершилось ошибкой."
};

/** Render only text nodes and fixed mask labels, keeping user input out of HTML parsing. */
function render(text, spans) {
  controls.result.replaceChildren();
  let offset = 0;
  for (const span of spans) {
    controls.result.append(document.createTextNode(text.slice(offset, span.start)));
    const replacement = document.createElement("mark");
    replacement.textContent = "[PERSON]";
    controls.result.append(replacement);
    offset = span.start + span.length;
  }
  controls.result.append(document.createTextNode(text.slice(offset)));
}

/** Reuse one detector for the selected model/backend configuration and display its actual state. */
async function run() {
  controls.run.disabled = true;
  controls.status.textContent = "Проверка…";
  controls.result.textContent = "—";
  controls.counts.textContent = "";
  try {
    const key = [controls.model.value, controls.backend.value, controls.device.value].join("/");
    if (!detector || key !== configuration) {
      await detector?.dispose();
      detector = null;
      const response = await fetch("../../models/" + controls.model.value + ".bin", { credentials: "omit" });
      if (!response.ok) throw new Error("model-unavailable");
      detector = await createPersonDetector(await response.arrayBuffer(), {
        backend: controls.backend.value, deviceType: controls.device.value
      });
      configuration = key;
    }
    const text = controls.source.value;
    const spans = await detector.find(text);
    render(text, spans);
    const state = detector.status;
    const active = state.activeBackend === "webnn" ? "WebNN" : "JavaScript";
    const explanation = state.fallbackReason ? " " + reasons[state.fallbackReason] : "";
    controls.status.textContent = "Фактический backend: " + active + "." + explanation;
    controls.counts.textContent = "Фрагментов PERSON: " + spans.length + ". Результат распознавания может содержать ошибки.";
  } catch (error) {
    controls.status.textContent = reasons[error.message] || "Проверка не выполнена. Проверьте модель, вход и параметры.";
  } finally {
    controls.run.disabled = false;
  }
}
controls.run.addEventListener("click", run);
