/** RFC 4648 section 5, without padding. Works with browser and Node globals. */
export function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export function decodeBase64Url(value: string): Uint8Array {
  // Match Node: ignore non-alphabet characters, stop at padding, and discard
  // a lone final sextet because it cannot form a byte.
  const alphabet = value
    .split("=", 1)[0]!
    .replace(/[^A-Za-z0-9+/_-]/g, "")
    .replace(/-/g, "+")
    .replace(/_/g, "/");
  const base64 = alphabet.length % 4 === 1 ? alphabet.slice(0, -1) : alphabet;
  const padded = base64.padEnd(
    base64.length + ((4 - (base64.length % 4)) % 4),
    "=",
  );
  return Uint8Array.from(atob(padded), (char) => char.charCodeAt(0));
}

export function encodeBase64UrlUtf8(value: string): string {
  return encodeBase64Url(new TextEncoder().encode(value));
}

export function decodeBase64UrlUtf8(value: string): string {
  return new TextDecoder("utf-8", { ignoreBOM: true }).decode(
    decodeBase64Url(value),
  );
}
