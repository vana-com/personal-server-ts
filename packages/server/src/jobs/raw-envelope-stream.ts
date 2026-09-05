import { Readable, Transform, type TransformCallback } from "node:stream";
import { DataFileEnvelopeSchema } from "@opendatalabs/vana-sdk/browser";

const decoder = new TextDecoder();
const encoder = new TextEncoder();
const QUOTE = 0x22;
const BACKSLASH = 0x5c;
const MAX_METADATA_TOKEN_BYTES = 64 * 1024;
const OUTPUT_CHUNK_BYTES = 64 * 1024;

interface ObjectFrame {
  type: "object";
  path: "root" | "data" | "metadata" | "other";
  suppress: boolean;
  expectKey: boolean;
  currentKey?: string;
  keepCurrent: boolean;
  wroteProperty: boolean;
}

interface ArrayFrame {
  type: "array";
  path: "other";
  suppress: boolean;
}

type Frame = ObjectFrame | ArrayFrame;

interface EnvelopePlan {
  prefix: Uint8Array;
  storedLineage: boolean;
  binary: boolean;
  metadataHasKeptProperty: boolean;
}

/** Open twice: once for bounded metadata inspection, then for streamed output. */
export async function openRedactedEnvelopeStream(
  open: () => Promise<ReadableStream<Uint8Array>>,
): Promise<ReadableStream<Uint8Array>> {
  const plan = await scanEnvelope(await open());
  const input = Readable.fromWeb((await open()) as never);
  const redactor = new EnvelopeRedactor(plan);
  input.on("error", (error) => redactor.destroy(error));
  redactor.on("close", () => input.destroy());
  input.pipe(redactor);
  return Readable.toWeb(redactor) as unknown as ReadableStream<Uint8Array>;
}

async function scanEnvelope(
  stream: ReadableStream<Uint8Array>,
): Promise<EnvelopePlan> {
  const scanner = new EnvelopeScanner();
  for await (const chunk of Readable.fromWeb(stream as never)) {
    scanner.write(chunk as Uint8Array);
  }
  return scanner.finish();
}

class EnvelopeScanner {
  private readonly stack: Frame[] = [];
  private inString = false;
  private escaped = false;
  private stringIsKey = false;
  private readonly stringBytes: number[] = [];
  private captureHeaderValue = false;
  private readonly headerValueBytes: number[] = [];
  private readonly metadata: Record<string, unknown> = {};
  private sawData = false;
  private storedLineage = false;
  private binary = false;
  private metadataHasKeptProperty = false;

  write(chunk: Uint8Array): void {
    for (const byte of chunk) this.writeByte(byte);
  }

  finish(): EnvelopePlan {
    if (this.inString || this.stack.length !== 0 || !this.sawData) {
      throw new Error("Stored data envelope is not complete JSON");
    }
    const envelope = DataFileEnvelopeSchema.parse({
      ...this.metadata,
      data: {},
    });
    const { data: _data, ...header } = envelope;
    const headerJson = JSON.stringify(header);
    return {
      prefix: encoder.encode(`${headerJson.slice(0, -1)},"data":`),
      storedLineage: this.storedLineage,
      binary: this.binary,
      metadataHasKeptProperty: this.metadataHasKeptProperty,
    };
  }

  private writeByte(byte: number): void {
    if (this.inString) {
      if (this.stringIsKey || this.captureHeaderValue) {
        const target = this.stringIsKey
          ? this.stringBytes
          : this.headerValueBytes;
        target.push(byte);
        if (target.length > MAX_METADATA_TOKEN_BYTES) {
          throw new Error("Stored data envelope metadata token is too large");
        }
      }
      if (this.escaped) {
        this.escaped = false;
      } else if (byte === BACKSLASH) {
        this.escaped = true;
      } else if (byte === QUOTE) {
        this.endString();
      }
      return;
    }
    if (isWhitespace(byte)) return;
    const frame = this.stack.at(-1);
    if (byte === QUOTE) {
      this.inString = true;
      this.stringIsKey = frame?.type === "object" && frame.expectKey;
      this.stringBytes.length = 0;
      this.headerValueBytes.length = 0;
      if (this.stringIsKey) this.stringBytes.push(byte);
      this.captureHeaderValue =
        !this.stringIsKey &&
        frame?.type === "object" &&
        frame.path === "root" &&
        isHeaderKey(frame.currentKey);
      if (this.captureHeaderValue) this.headerValueBytes.push(byte);
      return;
    }
    if (byte === 0x7b) {
      const path = childObjectPath(frame);
      if (path === "data") this.sawData = true;
      this.stack.push({
        type: "object",
        path,
        suppress: false,
        expectKey: true,
        keepCurrent: true,
        wroteProperty: false,
      });
      return;
    }
    if (byte === 0x5b) {
      this.stack.push({ type: "array", path: "other", suppress: false });
      return;
    }
    if (byte === 0x7d || byte === 0x5d) {
      this.stack.pop();
      return;
    }
    if (byte === 0x2c) {
      if (frame?.type === "object") {
        frame.expectKey = true;
        frame.currentKey = undefined;
      }
      return;
    }
    if (
      frame?.type === "object" &&
      frame.path === "data" &&
      frame.currentKey === "$binary" &&
      byte === 0x74
    ) {
      this.binary = true;
    }
  }

  private endString(): void {
    const frame = this.stack.at(-1);
    if (this.stringIsKey && frame?.type === "object") {
      const key = JSON.parse(
        decoder.decode(Uint8Array.from(this.stringBytes)),
      ) as string;
      frame.currentKey = key;
      frame.expectKey = false;
      if (frame.path === "data" && key === "$lineage")
        this.storedLineage = true;
      if (frame.path === "metadata" && key !== "lineage") {
        this.metadataHasKeptProperty = true;
      }
    } else if (
      this.captureHeaderValue &&
      frame?.type === "object" &&
      frame.currentKey
    ) {
      this.metadata[frame.currentKey] = JSON.parse(
        decoder.decode(Uint8Array.from(this.headerValueBytes)),
      ) as unknown;
    }
    this.inString = false;
    this.stringIsKey = false;
    this.captureHeaderValue = false;
  }
}

class EnvelopeRedactor extends Transform {
  private readonly stack: Frame[] = [];
  private inString = false;
  private escaped = false;
  private stringIsKey = false;
  private stringSuppressed = false;
  private readonly stringBytes: number[] = [];
  private readonly pending: number[] = [];

  constructor(private readonly plan: EnvelopePlan) {
    super();
  }

  override _transform(
    chunk: Buffer,
    _encoding: BufferEncoding,
    callback: TransformCallback,
  ): void {
    try {
      for (const byte of chunk) this.writeByte(byte);
      this.flushPending();
      callback();
    } catch (error) {
      callback(error as Error);
    }
  }

  private writeByte(byte: number): void {
    if (this.inString) {
      if (this.stringIsKey) {
        this.stringBytes.push(byte);
        if (this.stringBytes.length > MAX_METADATA_TOKEN_BYTES) {
          throw new Error("Stored data envelope property name is too large");
        }
      }
      if (!this.stringSuppressed && !this.stringIsKey) this.pushByte(byte);
      if (this.escaped) {
        this.escaped = false;
      } else if (byte === BACKSLASH) {
        this.escaped = true;
      } else if (byte === QUOTE) {
        if (this.stringIsKey) this.endKey();
        this.inString = false;
      }
      return;
    }
    if (isWhitespace(byte)) return;
    const frame = this.stack.at(-1);
    if (byte === QUOTE) {
      this.inString = true;
      this.stringIsKey = frame?.type === "object" && frame.expectKey;
      this.stringBytes.length = 0;
      if (this.stringIsKey) this.stringBytes.push(byte);
      this.stringSuppressed = this.stringIsKey || isSuppressed(frame);
      if (!this.stringSuppressed) this.pushByte(byte);
      return;
    }
    if (byte === 0x7b) {
      const path = childObjectPath(frame);
      const suppress = isSuppressed(frame);
      if (path === "root") {
        // The validated canonical prefix is emitted when the data value starts.
      } else if (path === "data") {
        this.pushBytes(this.plan.prefix);
        this.pushByte(byte);
      } else if (!suppress) {
        this.pushByte(byte);
      }
      this.stack.push({
        type: "object",
        path,
        suppress,
        expectKey: true,
        keepCurrent: true,
        wroteProperty: false,
      });
      return;
    }
    if (byte === 0x5b) {
      const suppress = isSuppressed(frame);
      if (!suppress) this.pushByte(byte);
      this.stack.push({ type: "array", path: "other", suppress });
      return;
    }
    if (byte === 0x7d || byte === 0x5d) {
      const closing = this.stack.pop();
      if (closing?.type === "object" && closing.path === "root") {
        this.pushByte(byte);
      } else if (closing && !closing.suppress) {
        this.pushByte(byte);
      }
      return;
    }
    if (byte === 0x2c) {
      if (frame?.type === "object") {
        frame.expectKey = true;
        frame.currentKey = undefined;
        frame.keepCurrent = true;
      } else if (!isSuppressed(frame)) {
        this.pushByte(byte);
      }
      return;
    }
    if (byte === 0x3a) {
      if (
        frame?.type === "object" &&
        frame.path !== "root" &&
        frame.keepCurrent &&
        !frame.suppress
      ) {
        this.pushByte(byte);
      }
      return;
    }
    if (!isSuppressed(frame)) this.pushByte(byte);
  }

  private endKey(): void {
    const frame = this.stack.at(-1);
    if (frame?.type !== "object") return;
    const keyBytes = Uint8Array.from(this.stringBytes);
    const key = JSON.parse(decoder.decode(keyBytes)) as string;
    frame.currentKey = key;
    frame.expectKey = false;
    frame.keepCurrent = shouldKeepProperty(frame.path, key, this.plan);
    if (frame.path === "root") return;
    if (frame.keepCurrent && !frame.suppress) {
      if (frame.wroteProperty) this.pushByte(0x2c);
      this.pushBytes(keyBytes);
      frame.wroteProperty = true;
    }
  }

  private pushByte(byte: number): void {
    this.pending.push(byte);
    if (this.pending.length === OUTPUT_CHUNK_BYTES) this.flushPending();
  }

  private pushBytes(bytes: Uint8Array): void {
    for (const byte of bytes) this.pushByte(byte);
  }

  private flushPending(): void {
    if (this.pending.length === 0) return;
    this.push(Buffer.from(this.pending));
    this.pending.length = 0;
  }
}

function childObjectPath(frame: Frame | undefined): ObjectFrame["path"] {
  if (!frame) return "root";
  if (frame.type !== "object") return "other";
  if (frame.path === "root" && frame.currentKey === "data") return "data";
  if (frame.path === "data" && frame.currentKey === "metadata") {
    return "metadata";
  }
  return "other";
}

function shouldKeepProperty(
  path: ObjectFrame["path"],
  key: string,
  plan: EnvelopePlan,
): boolean {
  if (path === "root") return key === "data";
  if (path === "metadata") return !(plan.storedLineage && key === "lineage");
  if (path !== "data") return true;
  if (key === "$writtenBy" || key === "$lineage") return false;
  if (plan.storedLineage && !plan.binary && key === "lineage") return false;
  if (
    plan.storedLineage &&
    plan.binary &&
    key === "metadata" &&
    !plan.metadataHasKeptProperty
  ) {
    return false;
  }
  return true;
}

function isSuppressed(frame: Frame | undefined): boolean {
  if (!frame) return false;
  if (frame.suppress) return true;
  return frame.type === "object" && !frame.keepCurrent;
}

function isHeaderKey(key: string | undefined): boolean {
  return (
    key === "$schema" ||
    key === "version" ||
    key === "scope" ||
    key === "schemaId" ||
    key === "collectedAt"
  );
}

function isWhitespace(byte: number): boolean {
  return byte === 0x20 || byte === 0x09 || byte === 0x0a || byte === 0x0d;
}
