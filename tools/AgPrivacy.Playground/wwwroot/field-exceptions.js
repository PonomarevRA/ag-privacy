const panel = document.querySelector("#field-exceptions");
const editor = document.querySelector("#exception-list");
const save = document.querySelector("#save-exceptions");
const reset = document.querySelector("#reset-exceptions");
const status = document.querySelector("#exception-status");
const storageKey = "ag-privacy.display-field-exceptions.v1";
const fieldName = /^[\p{L}_][\p{L}\p{Nd}_.-]{0,95}$/u;
let defaults;
let applied;
let busy = false;

/** Accept property names only, mirroring the server limit and excluding wildcard paths. */
function valid(fields) {
  return Array.isArray(fields) && fields.length <= 32 &&
    fields.every(name => typeof name === "string" && name.length <= 96 && Array.from(name).length === name.length && fieldName.test(name)) &&
    new Set(fields.map(name => name.toLowerCase())).size === fields.length;
}

/** Read the server configuration and restore a previously applied browser list, if present. */
export async function loadExceptions(onChange) {
  save.addEventListener("click", () => {
    const fields = editor.value.split("\n").map(name => name.trim()).filter(Boolean);
    if (!valid(fields)) {
      editor.setAttribute("aria-invalid", "true");
      status.textContent = "Укажите до 32 уникальных имён. Допустимы буквы, цифры, точка, дефис и подчёркивание. Начните имя с буквы или подчёркивания.";
      return;
    }
    apply(fields, onChange);
  });
  reset.addEventListener("click", () => apply(undefined, onChange));
  try {
    const response = await fetch("/mask/field-exceptions");
    if (!response.ok) throw new Error();
    const fields = await response.json();
    if (!valid(fields)) throw new Error();
    defaults = fields;
  } catch {
    status.textContent = "Список из конфига недоступен. Обновите страницу, чтобы изменить исключения.";
    return;
  }

  try {
    const stored = JSON.parse(localStorage.getItem(storageKey));
    if (valid(stored)) applied = stored;
  } catch {
    // Browser storage may be unavailable. The server configuration remains usable.
  }
  editor.value = (applied ?? defaults).join("\n");
  updateControls();
}

/** Apply one list for subsequent requests, keeping only field names in browser storage. */
function apply(fields, onChange) {
  applied = fields;
  editor.value = (fields ?? defaults).join("\n");
  editor.removeAttribute("aria-invalid");
  status.textContent = fields ? "Список применён для обоих режимов." : "Используется список из конфига.";
  try {
    if (fields) localStorage.setItem(storageKey, JSON.stringify(fields));
    else localStorage.removeItem(storageKey);
  } catch {
    status.textContent += " Настройка действует до закрытия или обновления страницы.";
  }
  onChange();
}

/** Keep a comparison on one applied settings snapshot. */
export function exceptionHeaders() {
  return applied ? { "X-Display-Field-Exceptions": encodeURIComponent(JSON.stringify(applied)) } : {};
}

export function setExceptionsBusy(value) {
  busy = value;
  updateControls();
}

/** Disable settings until the config has loaded or while a request is running. */
function updateControls() {
  editor.disabled = save.disabled = reset.disabled = busy || !defaults;
}

export function showExceptions(json) {
  panel.hidden = !json;
}
