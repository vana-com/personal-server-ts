export interface EnvelopePreview {
  text: string;
  truncated: boolean;
}

const DEFAULT_PREVIEW_NODE_BUDGET = 15_000;
const textEncoder = new TextEncoder();

interface PreviewState {
  bytes: number;
  truncated: boolean;
}

function utf8Length(text: string): number {
  return textEncoder.encode(text).byteLength;
}

function clipToUtf8Bytes(text: string, maxBytes: number): string {
  if (maxBytes <= 0) return "";
  if (utf8Length(text) <= maxBytes) return text;

  let low = 0;
  let high = text.length;
  while (low < high) {
    const mid = Math.ceil((low + high) / 2);
    if (utf8Length(text.slice(0, mid)) <= maxBytes) {
      low = mid;
    } else {
      high = mid - 1;
    }
  }

  let clipped = text.slice(0, low);
  const last = clipped.charCodeAt(clipped.length - 1);
  if (last >= 0xd800 && last <= 0xdbff) {
    clipped = clipped.slice(0, -1);
  }
  return clipped;
}

function appendPreviewToken(
  chunks: string[],
  token: string,
  maxBytes: number,
  state: PreviewState,
): boolean {
  if (!token) return true;

  const text = chunks.length > 0 ? `\n${token}` : token;
  const remaining = maxBytes - state.bytes;
  if (remaining <= 0) {
    state.truncated = true;
    return false;
  }

  const encodedBytes = utf8Length(text);
  if (encodedBytes <= remaining) {
    chunks.push(text);
    state.bytes += encodedBytes;
    return true;
  }

  const clipped = clipToUtf8Bytes(text, remaining);
  if (clipped) {
    chunks.push(clipped);
    state.bytes += utf8Length(clipped);
  }
  state.truncated = true;
  return false;
}

export function previewEnvelopeValue(
  envelope: unknown,
  maxBytes: number,
  options: { nodeBudget?: number } = {},
): EnvelopePreview {
  const chunks: string[] = [];
  const stack: unknown[] = [envelope];
  const state: PreviewState = { bytes: 0, truncated: false };
  const seen = new WeakSet<object>();
  const nodeBudget = options.nodeBudget ?? DEFAULT_PREVIEW_NODE_BUDGET;
  let nodes = 0;

  while (stack.length > 0) {
    if (nodes >= nodeBudget) {
      state.truncated = true;
      break;
    }

    const current = stack.pop();
    nodes += 1;

    if (typeof current === "string") {
      if (!appendPreviewToken(chunks, current, maxBytes, state)) break;
      continue;
    }

    if (
      typeof current === "number" ||
      typeof current === "boolean" ||
      typeof current === "bigint"
    ) {
      if (!appendPreviewToken(chunks, String(current), maxBytes, state)) break;
      continue;
    }

    if (Array.isArray(current)) {
      if (seen.has(current)) continue;
      seen.add(current);
      for (let index = current.length - 1; index >= 0; index -= 1) {
        stack.push(current[index]);
      }
      continue;
    }

    if (typeof current === "object" && current !== null) {
      if (seen.has(current)) continue;
      seen.add(current);
      const entries = Object.entries(current as Record<string, unknown>);
      for (let index = entries.length - 1; index >= 0; index -= 1) {
        const [key, value] = entries[index]!;
        stack.push(value);
        stack.push(key);
      }
    }
  }

  return {
    text: chunks.join(""),
    truncated: state.truncated,
  };
}

export function previewJsonEnvelopePrefix(
  jsonText: string,
  maxBytes: number,
  options: { sourceTruncated?: boolean; nodeBudget?: number } = {},
): EnvelopePreview {
  const chunks: string[] = [];
  const state: PreviewState = {
    bytes: 0,
    truncated: options.sourceTruncated ?? false,
  };
  const nodeBudget = options.nodeBudget ?? DEFAULT_PREVIEW_NODE_BUDGET;
  let nodes = 0;
  let index = 0;

  while (index < jsonText.length) {
    if (nodes >= nodeBudget) {
      state.truncated = true;
      break;
    }

    const char = jsonText[index];
    if (char === '"') {
      const token = readJsonStringToken(jsonText, index + 1);
      nodes += 1;
      if (!appendPreviewToken(chunks, token.value, maxBytes, state)) break;
      state.truncated = state.truncated || token.truncated;
      index = token.nextIndex;
      continue;
    }

    if (char && /[-0-9]/u.test(char)) {
      const token = readJsonNumberToken(jsonText, index);
      nodes += 1;
      if (!appendPreviewToken(chunks, token.value, maxBytes, state)) break;
      index = token.nextIndex;
      continue;
    }

    const literal = readJsonLiteralToken(jsonText, index);
    if (literal) {
      nodes += 1;
      if (!appendPreviewToken(chunks, literal.value, maxBytes, state)) break;
      index = literal.nextIndex;
      continue;
    }

    index += 1;
  }

  return {
    text: chunks.join(""),
    truncated: state.truncated,
  };
}

function readJsonStringToken(
  text: string,
  startIndex: number,
): { value: string; nextIndex: number; truncated: boolean } {
  let value = "";
  let index = startIndex;
  let truncated = true;

  while (index < text.length) {
    const char = text[index]!;
    if (char === '"') {
      truncated = false;
      index += 1;
      break;
    }

    if (char !== "\\") {
      value += char;
      index += 1;
      continue;
    }

    const escaped = text[index + 1];
    if (!escaped) {
      index = text.length;
      break;
    }

    switch (escaped) {
      case '"':
      case "\\":
      case "/":
        value += escaped;
        index += 2;
        break;
      case "b":
        value += "\b";
        index += 2;
        break;
      case "f":
        value += "\f";
        index += 2;
        break;
      case "n":
        value += "\n";
        index += 2;
        break;
      case "r":
        value += "\r";
        index += 2;
        break;
      case "t":
        value += "\t";
        index += 2;
        break;
      case "u": {
        const hex = text.slice(index + 2, index + 6);
        if (!/^[0-9a-fA-F]{4}$/u.test(hex)) {
          index = text.length;
          break;
        }
        value += String.fromCharCode(Number.parseInt(hex, 16));
        index += 6;
        break;
      }
      default:
        value += escaped;
        index += 2;
        break;
    }
  }

  return { value, nextIndex: index, truncated };
}

function readJsonNumberToken(
  text: string,
  startIndex: number,
): { value: string; nextIndex: number } {
  let index = startIndex;
  while (index < text.length && /[-+0-9.eE]/u.test(text[index]!)) {
    index += 1;
  }
  return {
    value: text.slice(startIndex, index),
    nextIndex: index,
  };
}

function readJsonLiteralToken(
  text: string,
  startIndex: number,
): { value: string; nextIndex: number } | null {
  if (text.startsWith("true", startIndex)) {
    return { value: "true", nextIndex: startIndex + 4 };
  }
  if (text.startsWith("false", startIndex)) {
    return { value: "false", nextIndex: startIndex + 5 };
  }
  if (text.startsWith("null", startIndex)) {
    return { value: "null", nextIndex: startIndex + 4 };
  }
  return null;
}
