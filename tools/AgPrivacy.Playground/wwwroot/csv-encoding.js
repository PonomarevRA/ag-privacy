const utf8 = new TextDecoder("utf-8", { fatal: true });
const windows1251 = new TextDecoder("windows-1251", { fatal: true });
const utf8Bom = [0xef, 0xbb, 0xbf];
const windows1251Bytes = new Map();

// A single-byte decoder also provides the reverse lookup for writing the file.
const singleByteLookup = new TextDecoder("windows-1251");
for (let byte = 128; byte < 256; byte++) {
  const character = singleByteLookup.decode(Uint8Array.of(byte));
  if (character !== "\ufffd") windows1251Bytes.set(character, byte);
}

/** Prefer valid UTF-8 and remember its BOM. Otherwise decode as Windows-1251. */
export function decodeCsv(bytes) {
  const hasBom = utf8Bom.every((byte, index) => bytes[index] === byte);
  const encoding = hasBom ? "utf-8-bom" : "utf-8";
  let text;
  try {
    text = utf8.decode(bytes);
  } catch (error) {
    if (hasBom || bytes.includes(0)) throw error;
    return { text: windows1251.decode(bytes), encoding: "windows-1251" };
  }
  if (text.includes("\0")) throw new TypeError("unsupported-csv-encoding");
  return { text, encoding };
}

/** Build Blob parts in the source encoding, rejecting characters it cannot represent. */
export function encodeDownload(text, encoding) {
  if (encoding === "utf-8-bom") return [Uint8Array.from(utf8Bom), text];
  if (encoding !== "windows-1251") return [text];

  const bytes = new Uint8Array(text.length);
  for (let index = 0; index < text.length; index++) {
    const code = text.charCodeAt(index);
    const byte = code < 128 ? code : windows1251Bytes.get(text[index]);
    if (byte === undefined) throw new RangeError("unrepresentable-windows-1251-character");
    bytes[index] = byte;
  }
  return [bytes];
}
