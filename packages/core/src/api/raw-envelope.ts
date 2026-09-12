import { DataFileEnvelopeSchema } from "@opendatalabs/vana-sdk/browser";

const decoder = new TextDecoder();
const encoder = new TextEncoder();
const OBJECT_START = 0x7b;
const OBJECT_END = 0x7d;
const ARRAY_START = 0x5b;
const ARRAY_END = 0x5d;
const QUOTE = 0x22;
const BACKSLASH = 0x5c;
const COLON = 0x3a;
const COMMA = 0x2c;

interface PropertySpan {
  key: string;
  keyStart: number;
  keyEnd: number;
  valueStart: number;
  valueEnd: number;
}

/** Build the grantee JSON view without materializing the record as objects. */
export function redactJsonEnvelopeBytesForGrantee(
  bytes: Uint8Array,
): Uint8Array {
  const metadata: Record<string, unknown> = {};
  let dataStart = -1;
  let dataEnd = -1;
  visitObject(bytes, 0, bytes.length, (property) => {
    if (property.key === "data") {
      dataStart = property.valueStart;
      dataEnd = property.valueEnd;
      return;
    }
    metadata[property.key] = JSON.parse(
      decoder.decode(bytes.subarray(property.valueStart, property.valueEnd)),
    ) as unknown;
  });
  if (dataStart < 0 || bytes[dataStart] !== OBJECT_START) {
    throw new Error("Stored data envelope is missing its data object");
  }

  const envelope = DataFileEnvelopeSchema.parse({ ...metadata, data: {} });
  const { data: _data, ...header } = envelope;
  const headerJson = JSON.stringify(header);
  const prefix = encoder.encode(`${headerJson.slice(0, -1)},"data":`);
  if (prefix.length > dataStart) {
    throw new Error("Stored data envelope header cannot be rewritten in place");
  }
  bytes.set(prefix, 0);

  const flags = dataFlags(bytes, dataStart, dataEnd);
  let output = writeDataObject(bytes, dataStart, dataEnd, prefix.length, flags);
  bytes[output] = OBJECT_END;
  output += 1;
  return bytes.subarray(0, output);
}

function dataFlags(bytes: Uint8Array, start: number, end: number) {
  let storedLineage = false;
  let binary = false;
  visitObject(bytes, start, end, (property) => {
    if (property.key === "$lineage") storedLineage = true;
    if (
      property.key === "$binary" &&
      decoder.decode(bytes.subarray(property.valueStart, property.valueEnd)) ===
        "true"
    ) {
      binary = true;
    }
  });
  return { storedLineage, binary };
}

function writeDataObject(
  bytes: Uint8Array,
  start: number,
  end: number,
  outputStart: number,
  flags: { storedLineage: boolean; binary: boolean },
): number {
  let output = outputStart;
  let wroteProperty = false;
  bytes[output++] = OBJECT_START;
  visitObject(bytes, start, end, (property) => {
    const redactMetadata =
      flags.storedLineage &&
      flags.binary &&
      property.key === "metadata" &&
      bytes[property.valueStart] === OBJECT_START;
    const omit =
      property.key === "$writtenBy" ||
      property.key === "$lineage" ||
      (flags.storedLineage && !flags.binary && property.key === "lineage") ||
      (redactMetadata &&
        !hasKeptProperty(bytes, property.valueStart, property.valueEnd));
    if (omit) return;

    if (wroteProperty) bytes[output++] = COMMA;
    output = copyRange(bytes, property.keyStart, property.keyEnd, output);
    bytes[output++] = COLON;
    output = redactMetadata
      ? writeFilteredObject(
          bytes,
          property.valueStart,
          property.valueEnd,
          output,
        )
      : copyMinified(bytes, property.valueStart, property.valueEnd, output);
    wroteProperty = true;
  });
  bytes[output++] = OBJECT_END;
  return output;
}

function hasKeptProperty(bytes: Uint8Array, start: number, end: number) {
  let kept = false;
  visitObject(bytes, start, end, ({ key }) => {
    if (key !== "lineage") kept = true;
  });
  return kept;
}

function writeFilteredObject(
  bytes: Uint8Array,
  start: number,
  end: number,
  outputStart: number,
): number {
  let output = outputStart;
  let wroteProperty = false;
  bytes[output++] = OBJECT_START;
  visitObject(bytes, start, end, (property) => {
    if (property.key === "lineage") return;
    if (wroteProperty) bytes[output++] = COMMA;
    output = copyRange(bytes, property.keyStart, property.keyEnd, output);
    bytes[output++] = COLON;
    output = copyMinified(
      bytes,
      property.valueStart,
      property.valueEnd,
      output,
    );
    wroteProperty = true;
  });
  bytes[output++] = OBJECT_END;
  return output;
}

function visitObject(
  bytes: Uint8Array,
  start: number,
  end: number,
  visit: (property: PropertySpan) => void,
): void {
  let index = skipWhitespace(bytes, start);
  if (bytes[index++] !== OBJECT_START) throw new Error("Expected JSON object");
  index = skipWhitespace(bytes, index);
  while (index < end && bytes[index] !== OBJECT_END) {
    const keyStart = index;
    const keyEnd = stringEnd(bytes, keyStart, end);
    const key = JSON.parse(
      decoder.decode(bytes.subarray(keyStart, keyEnd)),
    ) as string;
    index = skipWhitespace(bytes, keyEnd);
    if (bytes[index++] !== COLON) throw new Error("Expected JSON colon");
    const valueStart = skipWhitespace(bytes, index);
    const valueEnd = valueBoundary(bytes, valueStart, end);
    visit({ key, keyStart, keyEnd, valueStart, valueEnd });
    index = skipWhitespace(bytes, valueEnd);
    if (bytes[index] === COMMA) {
      index = skipWhitespace(bytes, index + 1);
    } else if (bytes[index] !== OBJECT_END) {
      throw new Error("Expected JSON object delimiter");
    }
  }
  if (bytes[index] !== OBJECT_END) throw new Error("Unterminated JSON object");
}

function valueBoundary(bytes: Uint8Array, start: number, end: number): number {
  if (bytes[start] === QUOTE) return stringEnd(bytes, start, end);
  if (bytes[start] === OBJECT_START || bytes[start] === ARRAY_START) {
    let depth = 0;
    let index = start;
    while (index < end) {
      const byte = bytes[index];
      if (byte === QUOTE) {
        index = stringEnd(bytes, index, end);
        continue;
      }
      if (byte === OBJECT_START || byte === ARRAY_START) depth += 1;
      if (byte === OBJECT_END || byte === ARRAY_END) depth -= 1;
      index += 1;
      if (depth === 0) return index;
    }
    throw new Error("Unterminated JSON value");
  }
  let index = start;
  while (
    index < end &&
    bytes[index] !== COMMA &&
    bytes[index] !== OBJECT_END &&
    bytes[index] !== ARRAY_END &&
    !isWhitespace(bytes[index])
  ) {
    index += 1;
  }
  return index;
}

function stringEnd(bytes: Uint8Array, start: number, end: number): number {
  if (bytes[start] !== QUOTE) throw new Error("Expected JSON string");
  let index = start + 1;
  while (index < end) {
    if (bytes[index] === BACKSLASH) {
      index += 2;
    } else if (bytes[index] === QUOTE) {
      return index + 1;
    } else {
      index += 1;
    }
  }
  throw new Error("Unterminated JSON string");
}

function copyMinified(
  bytes: Uint8Array,
  start: number,
  end: number,
  outputStart: number,
): number {
  let output = outputStart;
  let index = start;
  while (index < end) {
    if (bytes[index] === QUOTE) {
      const next = stringEnd(bytes, index, end);
      output = copyRange(bytes, index, next, output);
      index = next;
    } else if (isWhitespace(bytes[index])) {
      index += 1;
    } else {
      bytes[output++] = bytes[index++];
    }
  }
  return output;
}

function copyRange(
  bytes: Uint8Array,
  start: number,
  end: number,
  output: number,
): number {
  bytes.copyWithin(output, start, end);
  return output + end - start;
}

function skipWhitespace(bytes: Uint8Array, start: number): number {
  let index = start;
  while (isWhitespace(bytes[index])) index += 1;
  return index;
}

function isWhitespace(byte: number | undefined): boolean {
  return byte === 0x20 || byte === 0x09 || byte === 0x0a || byte === 0x0d;
}
