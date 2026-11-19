import { decodeCsv, encodeDownload } from "./csv-encoding.js";
import { exceptionHeaders, loadExceptions, setExceptionsBusy, showExceptions } from "./field-exceptions.js";

const form = document.querySelector("#mask-form");
const mode = document.querySelector("#mode");
const modeSetting = document.querySelector("#mode-setting");
const delimiterSetting = document.querySelector("#delimiter-setting");
const delimiter = document.querySelector("#delimiter");
const fileSetting = document.querySelector("#file-setting");
const sourceFile = document.querySelector("#source-file");
const modeHelp = document.querySelector("#mode-help");
const format = document.querySelector("#format");
const formatHelp = document.querySelector("#format-help");
const input = document.querySelector("#input");
const result = document.querySelector("#result");
const download = document.querySelector("#download-result");
const resultInfo = document.querySelector("#result-info");
const singleOutput = document.querySelector("#single-output");
const comparison = document.querySelector("#comparison");
const comparisonOutputs = [
  { route: "json", value: document.querySelector("#strict-result"), info: document.querySelector("#strict-info") },
  { route: "soft-part", value: document.querySelector("#soft-result"), info: document.querySelector("#soft-info") },
  { route: "log-types", value: document.querySelector("#log-types-result"), info: document.querySelector("#log-types-info") },
];
const compare = document.querySelector("#compare");
const rules = document.querySelector("#rules");
const ruleList = document.querySelector("#rule-list");
const rulesStatus = document.querySelector("#rules-status");
const status = document.querySelector("#status");
const mask = document.querySelector("#mask");
const example = document.querySelector("#example");
const clear = document.querySelector("#clear");
let activeRequest;
let downloadableText;
let strictFormat = "json";
let fileRead = 0;
let fileSource;
let sourceName;
let sourceEncoding = "utf-8";
let readingFile = false;
const maxInputBytes = 256 * 1024;
const csvSeparators = { comma: ",", semicolon: ";", tab: "\t" };

const examples = {
  json: JSON.stringify({
    fullName: "Тестов Тест Тестович",
    birthDate: "29-02-2004",
    clientType: "individual",
    inn: "000000000000",
    tin: "01234567",
    phone: "+70012345678",
    phoneLinkedToFs: true,
    workPhone: "+70023456789",
    tags: ["синтетика"],
    email: "abcdef@example.invalid",
    "key-fixture@example.invalid": null,
    "+70000000000": null,
    bankAccount: "00000000000000004333",
    agreementNumber: "12-451123/26",
    itemA: "sample@example.invalid",
    itemB: "+70012345678",
    itemC: "1-123/2026",
    numberId: 42,
    active: true,
    status: "approved",
    category: "reporting",
    message: "routing the draft to mira tracewell for review; isin=US0378331005 ticker=AAPL",
    isin: "US0378331005",
    ticker: "AAPL",
    trace: { id: "3a0e1ab96f8c400caf6a5e8000000000" },
  }, null, 2),
  xml: `<?xml version="1.0" encoding="UTF-8"?>
<export xmlns:api="urn:example">
  <record status="ready">
    <api:fullName>Zorva Teluin</api:fullName>
    <api:clientId>UXC67013</api:clientId>
    <api:apiKey>qPLmT92v</api:apiKey>
    <numberId>001234</numberId>
  </record>
</export>`,
  text: "Тестовый Пользователь\nПочта: demo@example.invalid",
};

/** Generate the same synthetic table with the selected CSV dialect. */
function csvExample() {
  const rows = [
    ["ФИО клиента", "client_id", "api-key", "status", "numberId"],
    ["Zorva Teluin", "UXC67013", "qPLmT92v", "ready", "001234"],
    ["Zorva Teluin", "UXC80451", "vR9sT20q", "queued", "001235"],
  ];
  return rows.map(row => row.join(csvSeparators[delimiter.value])).join("\n");
}

/** Construct a synthetic gRPC response encoded as a JSON string inside a log line. */
function typedLogExample() {
  const method = "/Demo.RecordsService/GetRecords";
  const response = {
    Records: {
      "{00000000-0000-4000-8000-000000000001}": {
        Id: "{00000000-0000-4000-8000-000000000002}",
        MasterId: "{00000000-0000-4000-8000-000000000003}",
        Name: "Консультация клиента",
        Email: "fixture@example.invalid",
        Phone: "+70012345678",
        AgreementNumber: "12-451123/26",
        Parent: null,
      },
    },
  };
  return `Unary-запрос ${JSON.stringify(JSON.stringify(method))} обработан за "1" мс. Ответ: ${JSON.stringify(JSON.stringify(response))}`;
}

const formatHints = {
  json: "Обычные значения сохраняются. Чувствительные поля и распознанные значения маскируются.",
  csv: "Маскирует значения по заголовкам столбцов и распознанным форматам.",
  xml: "Маскирует значения по именам тегов, атрибутов и распознанным форматам.",
  text: "Весь текст, включая несколько строк, заменяется одним маркером.",
};

/** CSV and XML share the library's selective document rules. */
function isStructured() {
  return format.value === "csv" || format.value === "xml";
}

/** Invalidate any pending file read before replacing the input. */
function clearFile({ keepName = false } = {}) {
  fileRead++;
  sourceFile.value = "";
  fileSource = undefined;
  if (!keepName) {
    sourceName = undefined;
    sourceEncoding = "utf-8";
  }
  readingFile = false;
  mask.disabled = Boolean(activeRequest);
  delimiter.disabled = Boolean(activeRequest);
}

/** Clear stale output when the input or format changes. */
function clearResult() {
  downloadableText = undefined;
  download.hidden = true;
  result.value = "";
  resultInfo.textContent = "";
  for (const output of comparisonOutputs) {
    output.value.replaceChildren();
    output.info.textContent = "";
  }
  comparison.hidden = true;
  singleOutput.hidden = false;
  status.textContent = "";
}

/** Keep structured file extensions and insert the suffix before the final extension. */
function maskedFileName() {
  const fallbackExtension = `.${format.value}`;
  if (!sourceName) return `masked${fallbackExtension}`;

  const dot = sourceName.lastIndexOf(".");
  if (dot <= 0) return `${sourceName}_masked${fallbackExtension}`;

  const extension = sourceName.slice(dot);
  const lower = extension.toLowerCase();
  const matchesFormat = lower === fallbackExtension || (format.value === "csv" && lower === ".tsv");
  return `${sourceName.slice(0, dot)}_masked${matchesFormat ? extension : fallbackExtension}`;
}

/** Download the masked text returned by the server without textarea newline normalization. */
function downloadResult() {
  if (downloadableText === undefined || !isStructured()) return;
  const name = maskedFileName();
  let type = "application/xml";
  if (format.value === "csv") {
    type = name.toLowerCase().endsWith(".tsv") ? "text/tab-separated-values" : "text/csv";
  }
  const charset = sourceEncoding === "windows-1251" ? sourceEncoding : "utf-8";
  let parts;
  try {
    parts = encodeDownload(downloadableText, sourceEncoding);
  } catch (error) {
    if (!(error instanceof RangeError)) throw error;
    status.textContent = "Результат содержит символы за пределами Windows-1251. Удалите их из исходного текста и повторите маскирование.";
    return;
  }
  status.textContent = "";
  const url = URL.createObjectURL(new Blob(parts, { type: `${type};charset=${charset}` }));
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.click();
  // Allow the browser to open the Blob before releasing it.
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** Clear visible inputs and results before leaving the page or on explicit reset. */
function resetEditors() {
  clearFile();
  input.value = "";
  clearResult();
}

/** Keep the submitted input and format stable until the matching result arrives. */
function setBusy(busy) {
  input.readOnly = busy;
  mode.disabled = busy;
  format.disabled = busy || mode.value !== "strict";
  sourceFile.disabled = busy;
  delimiter.disabled = busy;
  mask.disabled = busy;
  compare.disabled = busy || format.value !== "json";
  example.disabled = busy;
  clear.disabled = busy;
  setExceptionsBusy(busy);
}

/** Select the required format for each profile and keep the strict format preference. */
function updateMode() {
  const partial = mode.value === "soft-part";
  const typedLog = mode.value === "log-types";
  if (typedLog) format.value = "text";
  else format.value = partial ? "json" : strictFormat;
  format.disabled = mode.value !== "strict";
  compare.disabled = format.value !== "json";
  compare.hidden = isStructured();
  document.querySelector("#compare-help").hidden = isStructured();
  modeSetting.hidden = isStructured();
  delimiterSetting.hidden = format.value !== "csv";
  fileSetting.hidden = !isStructured();
  sourceFile.accept = format.value === "csv" ? ".csv,.tsv,text/csv,text/tab-separated-values" : ".xml,application/xml,text/xml";
  showExceptions(format.value === "json");

  if (typedLog) {
    modeHelp.textContent = "Подменяет буквы и цифры в распознанных фрагментах лога. Сводка показывает количество замен по типам. GUID в MasterId сохраняется.";
    formatHelp.textContent = "Можно вставить весь лог, включая экранированный JSON ответа.";
  } else if (partial) {
    modeHelp.textContent = "Маскирует JSON по правилам ДИБ. В результате могут остаться исходные данные.";
    formatHelp.textContent = "Обычные значения сохраняются. Для чувствительных данных применяется частичная маска, где есть правило.";
  } else {
    modeHelp.textContent = "Заменяет чувствительные значения целиком.";
    formatHelp.textContent = formatHints[format.value];
  }
  clearResult();
}

/** Request a masked result and map server errors to fixed UI messages. */
async function requestMask(route, source, signal, headers) {
  const response = await fetch(`/mask/${route}`, { method: "POST", body: source, signal, headers });
  if (!response.ok) throw new Error(String(response.status));
  const payload = await response.text();
  if (headers?.["X-Mask-Preview"] === "1") return JSON.parse(payload);
  // Use the original JSON numeric token so large IDs and precise decimals display as received.
  return JSON.parse(payload, (_key, value, context) =>
    typeof value === "number" && context?.source && typeof JSON.rawJSON === "function"
      ? JSON.rawJSON(context.source)
      : value);
}

/** Include the server's notice next to the result it describes. */
function describeResult(masked) {
  const count = `Замен: ${JSON.stringify(masked.Replacements)}.`;
  const types = Object.entries(masked.ReplacementsByType ?? {}).sort(([a], [b]) => a.localeCompare(b));
  const summary = types.length ? ` ${types.map(([type, total]) => `${type} × ${JSON.stringify(total)}`).join(" · ")}.` : "";
  return `${count}${summary}${masked.AgentNotice ? ` ${masked.AgentNotice}` : ""}`;
}

/** Render server-provided replacement offsets as text and semantic highlights. */
function renderPreview(output, preview) {
  const content = document.createDocumentFragment();
  let offset = 0;
  for (const { Start, Length } of preview.Highlights) {
    content.append(preview.Text.slice(offset, Start));
    const highlight = document.createElement("mark");
    highlight.textContent = preview.Text.slice(Start, Start + Length);
    content.append(highlight);
    offset = Start + Length;
  }
  content.append(preview.Text.slice(offset));
  output.replaceChildren(content);
}

/** Show all three results together, preserving the typed log's text formatting. */
function showComparison(results) {
  for (const [index, output] of comparisonOutputs.entries()) {
    const masked = results[index];
    renderPreview(output.value, masked.Preview);
    output.info.textContent = describeResult(masked);
  }
  singleOutput.hidden = true;
  comparison.hidden = false;
  status.textContent = "Сравнение готово.";
}

/** Mask one input snapshot in the selected mode or in all comparison modes. */
async function runMasking(compareModes = false) {
  if (activeRequest || readingFile || (compareModes && format.value !== "json")) return;
  const request = new AbortController();
  activeRequest = request;
  const source = fileSource ?? input.value;
  clearResult();
  setBusy(true);
  status.textContent = "Выполняется маскирование…";
  let headers = {};
  try {
    if (format.value === "json") {
      await exceptionsReady;
      if (request.signal.aborted) return;
      headers = exceptionHeaders();
    }
    if (compareModes) {
      const previewHeaders = { "X-Mask-Preview": "1" };
      const jsonPreviewHeaders = { ...headers, ...previewHeaders };
      const results = await Promise.all(comparisonOutputs.map(({ route }) =>
        requestMask(route, source, request.signal, route === "log-types" ? previewHeaders : jsonPreviewHeaders)));
      if (!request.signal.aborted) showComparison(results);
      return;
    }

    const route = format.value === "csv" ? `csv?delimiter=${delimiter.value}`
      : mode.value === "strict" ? format.value : mode.value;
    const masked = await requestMask(route, source, request.signal, headers);
    if (request.signal.aborted) return;
    result.value = format.value === "json" ? JSON.stringify(masked.Data, null, 2) : masked.Text;
    resultInfo.textContent = describeResult(masked);
    if (isStructured()) {
      downloadableText = masked.Text;
      download.hidden = false;
    }
    status.textContent = "";
  } catch (error) {
    if (request.signal.aborted) return;
    request.abort();
    if (error.message === "413") {
      status.textContent = "Ввод превышает 256 КиБ. Сократите его и попробуйте снова.";
    } else if (error.message === "400" && Object.keys(headers).length) {
      status.textContent = "Проверьте список исключений полей и примените его снова.";
    } else if (isStructured() && (error.message === "400" || error.message === "422")) {
      status.textContent = format.value === "csv"
        ? "CSV не обработан. Проверьте UTF-8, разделитель, кавычки и число столбцов."
        : "XML не обработан. Проверьте UTF-8 и структуру документа. DTD запрещён.";
    } else if (error.message === "422") {
      status.textContent = "Движок отклонил ввод. Проверьте выбранный формат и структуру данных.";
    } else {
      status.textContent = "Проверка не выполнена. Проверьте, что локальный сервер запущен.";
    }
  } finally {
    if (activeRequest === request) {
      activeRequest = undefined;
      setBusy(false);
    }
  }
}

/** Load the rule descriptions from the library the first time the glossary is opened. */
async function loadRules() {
  if (!rules.open || ruleList.childElementCount || rulesStatus.dataset.loading) return;
  rulesStatus.dataset.loading = "true";
  rulesStatus.textContent = "Загружается справочник…";
  try {
    const response = await fetch("/mask/rules");
    if (!response.ok) throw new Error("rules-request-failed");
    const descriptions = await response.json();
    const items = document.createDocumentFragment();
    for (const code of Object.keys(descriptions).sort()) {
      const term = document.createElement("dt");
      const description = document.createElement("dd");
      term.textContent = code;
      description.textContent = descriptions[code];
      items.append(term, description);
    }
    ruleList.append(items);
    rulesStatus.textContent = "";
  } catch {
    rulesStatus.textContent = "Справочник недоступен. Закройте его и откройте снова.";
  } finally {
    delete rulesStatus.dataset.loading;
  }
}

/** Check for a consistent multi-column CSV dialect across the first twelve logical records. */
function matchesCsvSeparator(text, separator) {
  let fields = 1;
  let expectedFields = 0;
  let records = 0;
  let field = "start";
  for (let i = 0; i <= text.length; i++) {
    const ch = text[i];
    if (field === "quoted") {
      if (ch === undefined) return false;
      if (ch === '"') {
        if (text[i + 1] === '"') i++;
        else field = "closed";
      }
      continue;
    }
    if (ch === separator) {
      fields++;
      field = "start";
      continue;
    }
    if (ch === "\r" || ch === "\n" || ch === undefined) {
      // A final line ending already completed the last record.
      if (ch === undefined && field === "start" && fields === 1 && records > 0) break;
      if (fields < 2 || (expectedFields && fields !== expectedFields)) return false;
      if (ch === "\r" && text[i + 1] === "\n") i++;
      expectedFields = fields;
      fields = 1;
      field = "start";
      if (++records === 12) break;
      continue;
    }
    if (field === "closed") return false;
    if (ch === '"') {
      if (field !== "start") return false;
      field = "quoted";
    } else {
      field = "unquoted";
    }
  }
  return records > 0;
}

/** Apply a detected dialect or use the file extension when there is no unique match. */
function applyCsvDelimiter(text, fileName) {
  const matches = Object.entries(csvSeparators).filter(([, separator]) => matchesCsvSeparator(text, separator));
  if (matches.length === 1) {
    delimiter.value = matches[0][0];
    const label = delimiter.selectedOptions[0].textContent.toLowerCase();
    return `Файл загружен. Разделитель: ${label}.`;
  }
  delimiter.value = fileName.toLowerCase().endsWith(".tsv") ? "tab" : "comma";
  return "Файл загружен. Разделитель не определён однозначно. При необходимости выберите его вручную.";
}

/** Decode a local file into the editor and ignore stale reads after edits or navigation. */
async function loadFile() {
  const file = sourceFile.files[0];
  if (!file) return;
  clearFile();
  const reading = fileRead;
  input.value = "";
  clearResult();
  if (file.size > maxInputBytes) {
    status.textContent = "Файл превышает 256 КиБ.";
    return;
  }
  readingFile = true;
  mask.disabled = true;
  delimiter.disabled = true;
  status.textContent = "Читается файл…";
  try {
    const bytes = await file.arrayBuffer();
    if (reading !== fileRead) return;
    if (format.value === "csv") {
      const decoded = decodeCsv(new Uint8Array(bytes));
      fileSource = decoded.text;
      sourceEncoding = decoded.encoding;
    } else {
      fileSource = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    }
    sourceName = file.name;
    input.value = fileSource;
    if (!fileSource) status.textContent = "Файл пуст.";
    else if (format.value === "csv") {
      const encodingLabel = { "utf-8": "UTF-8", "utf-8-bom": "UTF-8 с BOM", "windows-1251": "Windows-1251" };
      status.textContent = `${applyCsvDelimiter(fileSource, file.name)} Кодировка ${encodingLabel[sourceEncoding]}.`;
    }
    else status.textContent = "Файл загружен.";
    input.focus();
  } catch {
    if (reading === fileRead) {
      status.textContent = format.value === "csv"
        ? "Файл не прочитан. Сохраните его в UTF-8 или Windows-1251."
        : "Файл не прочитан. Проверьте кодировку UTF-8.";
    }
  } finally {
    if (reading === fileRead) {
      readingFile = false;
      mask.disabled = false;
      delimiter.disabled = false;
    }
  }
}

form.addEventListener("submit", event => {
  event.preventDefault();
  runMasking();
});
compare.addEventListener("click", () => {
  if (form.reportValidity()) runMasking(true);
});
rules.addEventListener("toggle", loadRules);
download.addEventListener("click", downloadResult);
input.addEventListener("input", () => {
  clearFile({ keepName: true });
  clearResult();
});
sourceFile.addEventListener("change", loadFile);
delimiter.addEventListener("change", clearResult);
mode.value = "strict";
updateMode();
const exceptionsReady = loadExceptions(clearResult);
mode.addEventListener("change", () => {
  clearFile();
  updateMode();
});
format.addEventListener("change", () => {
  clearFile();
  strictFormat = format.value;
  updateMode();
});
example.addEventListener("click", () => {
  clearFile();
  if (format.value === "csv") input.value = csvExample();
  else input.value = mode.value === "log-types" ? typedLogExample() : examples[format.value];
  clearResult();
  input.focus();
});
clear.addEventListener("click", () => {
  resetEditors();
  input.focus();
});
window.addEventListener("pagehide", () => {
  activeRequest?.abort();
  activeRequest = undefined;
  resetEditors();
  mode.value = "strict";
  setBusy(false);
  updateMode();
});
