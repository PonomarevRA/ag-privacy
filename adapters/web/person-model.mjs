const magic = "APNER001";
const letter = /^\p{L}$/u;
const letterOrDigit = /^[\p{L}\p{Nd}]$/u;
const upper = /^\p{Lu}$/u;
const lower = /^\p{Ll}$/u;

export const inputByteLimit = 262144;
export const tokenLimit = 8192;

/** Validate a bounded APNER001 model and copy its signed weights. */
export function readPersonModel(source) {
  if (!(source instanceof Uint8Array || source instanceof ArrayBuffer)) {
    throw new Error("invalid-person-model");
  }
  const bytes = source instanceof Uint8Array ? source : new Uint8Array(source);
  if (bytes.byteLength < 16 || bytes.byteLength > 16 + 8192 * 6 ||
      String.fromCharCode(...bytes.subarray(0, 8)) !== magic) {
    throw new Error("invalid-person-model");
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const buckets = view.getInt32(8, true);
  if (buckets < 256 || buckets > 8192 || (buckets & (buckets - 1)) !== 0 ||
      view.getInt32(12, true) !== 1 || bytes.byteLength !== 16 + buckets * 6) {
    throw new Error("invalid-person-model");
  }
  const weights = new Int16Array(buckets * 3);
  for (let index = 0; index < weights.length; index++) {
    weights[index] = view.getInt16(16 + index * 2, true);
  }
  return { buckets, weights };
}

/** Apply simple invariant lowercase mapping without contextual sigma or expanding UTF-16 characters. */
function invariantLower(value) {
  let result = "";
  for (let index = 0; index < value.length; index++) {
    const converted = value[index].toLowerCase();
    result += converted.length === 1 ? converted : value[index];
  }
  return result;
}

/** Reject malformed UTF-16 and preserve the core model's UTF-8 byte limit. */
function validateText(text) {
  if (typeof text !== "string") throw new TypeError("invalid-person-input");
  if (text.length > inputByteLimit) throw new Error("input-limit");
  for (let index = 0; index < text.length; index++) {
    const value = text.charCodeAt(index);
    if (value >= 0xd800 && value <= 0xdbff) {
      const next = text.charCodeAt(++index);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new Error("invalid-person-input");
    } else if (value >= 0xdc00 && value <= 0xdfff) {
      throw new Error("invalid-person-input");
    }
  }
  if (new TextEncoder().encode(text).byteLength > inputByteLimit) throw new Error("input-limit");
}

/** Tokenize BMP letters and decimal digits with the .NET detector's UTF-16 offsets and limits. */
export function tokenize(text) {
  validateText(text);
  const tokens = [];
  for (let index = 0; index < text.length;) {
    if (!letterOrDigit.test(text[index])) {
      index++;
      continue;
    }
    const start = index;
    while (index < text.length && letterOrDigit.test(text[index])) index++;
    if (tokens.length >= tokenLimit || index - start > 256) throw new Error("token-limit");
    const word = text.slice(start, index);
    tokens.push({ start, length: index - start, word, lower: invariantLower(word) });
  }
  return tokens;
}

/** Classify a token with the same letter and Unicode case categories used by MicroPersonModel. */
function shape(word) {
  let letters = true;
  let allUpper = true;
  let allLower = true;
  for (const character of word) {
    letters = letters && letter.test(character);
    allUpper = allUpper && upper.test(character);
    allLower = allLower && lower.test(character);
  }
  if (!letters) return "mixed";
  if (allUpper) return "upper";
  if (allLower) return "lower";
  return upper.test(word[0]) ? "title" : "mixed";
}

/** Hash UTF-16 code units using the core model's unchecked FNV-1a mapping. */
function hash(value, buckets) {
  let result = 2166136261;
  for (let index = 0; index < value.length; index++) {
    result = Math.imul(result ^ value.charCodeAt(index), 16777619) >>> 0;
  }
  return result & (buckets - 1);
}

/** Produce the exact twelve features for a token and one preceding BIO label. */
export function features(tokens, index, previous, buckets) {
  const token = tokens[index];
  const word = token.lower;
  const before = index > 0 ? tokens[index - 1].lower : "<start>";
  const after = index + 1 < tokens.length ? tokens[index + 1].lower : "<end>";
  const tokenShape = shape(token.word);
  const beforeShape = index > 0 ? shape(tokens[index - 1].word) : "start";
  const afterShape = index + 1 < tokens.length ? shape(tokens[index + 1].word) : "end";
  const values = [
    "bias", "w=" + word, "shape=" + tokenShape,
    "prev=" + before, "next=" + after, "label=" + previous,
    "prefix=" + word.slice(0, 2), "suffix=" + word.slice(-3),
    "before-shape=" + beforeShape, "after-shape=" + afterShape,
    "shape-prev=" + tokenShape + ":" + before, "shape-label=" + tokenShape + ":" + previous
  ];
  return values.map(value => hash(value, buckets));
}

/** Sum signed weights and preserve the first label when scores tie. */
export function chooseLabel(weights, indices) {
  const scores = [0, 0, 0];
  for (const feature of indices) {
    for (let label = 0; label < 3; label++) scores[label] += weights[feature * 3 + label];
  }
  return bestLabel(scores, 0);
}

/** Select the first maximum from one three-label score row. */
export function bestLabel(scores, offset) {
  let best = 0;
  for (let label = 1; label < 3; label++) {
    if (scores[offset + label] > scores[offset + best]) best = label;
  }
  return best;
}

/** Decode BIO labels with the core model's handling of an orphan continuation. */
export function decode(tokens, labels) {
  const spans = [];
  let start = -1;
  let end = 0;
  for (let index = 0; index < tokens.length; index++) {
    const label = labels[index];
    if (label === 1 || (label === 2 && start < 0)) {
      if (start >= 0) spans.push({ start, length: end - start, type: "PERSON" });
      start = tokens[index].start;
    }
    if (label === 0 && start >= 0) {
      spans.push({ start, length: end - start, type: "PERSON" });
      start = -1;
    }
    if (label !== 0) end = tokens[index].start + tokens[index].length;
  }
  if (start >= 0) spans.push({ start, length: end - start, type: "PERSON" });
  return spans;
}

/** Run the portable JavaScript scorer with greedy previous-label feedback. */
export function predictJavaScript(model, tokens) {
  const labels = [];
  let previous = 0;
  for (let index = 0; index < tokens.length; index++) {
    previous = chooseLabel(model.weights, features(tokens, index, previous, model.buckets));
    labels.push(previous);
  }
  return decode(tokens, labels);
}
