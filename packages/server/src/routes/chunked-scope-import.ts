import { createHash, randomUUID } from "node:crypto";
import { createReadStream } from "node:fs";
import {
  mkdir,
  open,
  readFile,
  readdir,
  rename,
  rm,
  stat,
  unlink,
} from "node:fs/promises";
import { dirname, join, relative } from "node:path";
import type { IndexManager } from "@opendatalabs/personal-server-ts-core/storage/index";
import type { HierarchyManagerOptions } from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import { buildDataFilePath } from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import { cacheRequestBodyBytes } from "@opendatalabs/personal-server-ts-core/auth";
import { publishStagedDataFile } from "../storage/hierarchy.js";

export const SCOPE_IMPORT_CHUNK_BYTES = 8 * 1024 * 1024;
export const SCOPE_IMPORT_MAX_BYTES = 256 * 1024 * 1024;
export const SCOPE_IMPORT_MAX_CHUNKS = 32;
export const SCOPE_IMPORT_TTL_MS = 24 * 60 * 60 * 1000;
const IMPORT_DIR = ".scope-imports";
const RECEIPT_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const MAX_DURABLE_RECEIPTS = 10_000;
const SHA256 = /^[a-f0-9]{64}$/i;
const openingScopes = new Set<string>();
let beginReservationActive = false;
const activeChunkIndexes = new Set<string>();
const finalizingImports = new Set<string>();
const abortingImports = new Set<string>();
let activeChunkWrites = 0;

type Frame = { kind: "object" | "array"; state: string };

/** Validates JSON incrementally without retaining property names or string values. */
class JsonObjectStreamValidator {
  // Preserve a leading BOM so the JSON grammar rejects it. The input bytes are
  // embedded inside an envelope, where silently stripping a BOM would make the
  // stored payload invalid JSON.
  private readonly decoder = new TextDecoder("utf-8", {
    fatal: true,
    ignoreBOM: true,
  });
  private readonly frames: Frame[] = [];
  private rootState: "value" | "done" = "value";
  private stringState: "normal" | "escape" | "unicode" | undefined;
  private unicodeRemaining = 0;
  private unicodeDigits = "";
  private capturingRootKey = false;
  private rootKey = "";
  private primitive: { word: string; offset: number } | undefined;
  private numberState: string | undefined;

  write(bytes: Uint8Array): void {
    this.consume(this.decoder.decode(bytes, { stream: true }));
  }

  end(): void {
    this.consume(this.decoder.decode());
    if (
      this.stringState ||
      this.primitive ||
      this.numberState ||
      this.frames.length ||
      this.rootState !== "done"
    ) {
      throw new Error("Incomplete JSON value");
    }
  }

  private current(): Frame | undefined {
    return this.frames.at(-1);
  }

  private isSpace(char: string): boolean {
    return char === " " || char === "\n" || char === "\r" || char === "\t";
  }

  private canEndPrimitive(char: string): boolean {
    return this.isSpace(char) || char === "," || char === "]" || char === "}";
  }

  private beginValue(char: string): void {
    const frame = this.current();
    if (frame) {
      if (frame.kind === "object" && frame.state !== "value")
        throw new Error("Unexpected JSON value");
      if (
        frame.kind === "array" &&
        frame.state !== "valueOrEnd" &&
        frame.state !== "value"
      )
        throw new Error("Unexpected JSON value");
      frame.state = "commaOrEnd";
    } else {
      if (this.rootState !== "value" || char !== "{")
        throw new Error("Top-level scope data must be an object");
      this.rootState = "done";
    }
    if (char === "{") {
      if (this.frames.length >= 256)
        throw new Error("JSON nesting is too deep");
      this.frames.push({ kind: "object", state: "keyOrEnd" });
    } else if (char === "[") {
      if (this.frames.length >= 256)
        throw new Error("JSON nesting is too deep");
      this.frames.push({ kind: "array", state: "valueOrEnd" });
    } else if (char === '"') {
      this.stringState = "normal";
      this.capturingRootKey = false;
    } else if (char === "t") this.primitive = { word: "true", offset: 1 };
    else if (char === "f") this.primitive = { word: "false", offset: 1 };
    else if (char === "n") this.primitive = { word: "null", offset: 1 };
    else if (char === "-") this.numberState = "minus";
    else if (char === "0") this.numberState = "zero";
    else if (/[1-9]/.test(char)) this.numberState = "integer";
    else throw new Error("Invalid JSON value");
  }

  private consume(text: string): void {
    for (let index = 0; index < text.length; index++) {
      const char = text[index]!;
      if (this.stringState) {
        if (this.stringState === "unicode") {
          if (!/[0-9a-f]/i.test(char)) throw new Error("Invalid JSON escape");
          this.unicodeDigits += char;
          this.unicodeRemaining--;
          if (this.unicodeRemaining === 0) {
            this.appendRootKey(
              String.fromCharCode(Number.parseInt(this.unicodeDigits, 16)),
            );
            this.unicodeDigits = "";
            this.stringState = "normal";
          }
        } else if (this.stringState === "escape") {
          if (char === "u") {
            this.stringState = "unicode";
            this.unicodeRemaining = 4;
          } else if ('"\\/bfnrt'.includes(char)) {
            const escaped: Record<string, string> = {
              '"': '"',
              "\\": "\\",
              "/": "/",
              b: "\b",
              f: "\f",
              n: "\n",
              r: "\r",
              t: "\t",
            };
            this.appendRootKey(escaped[char]!);
            this.stringState = "normal";
          } else throw new Error("Invalid JSON escape");
        } else if (char === "\\") this.stringState = "escape";
        else if (char === '"') {
          this.stringState = undefined;
          const frame = this.current();
          if (frame?.kind === "object" && frame.state === "key") {
            frame.state = "colon";
            if (this.capturingRootKey) {
              if (
                this.rootKey === "$writtenBy" ||
                this.rootKey === "$lineage" ||
                this.rootKey === "$pdpp"
              ) {
                throw new Error("Reserved root property");
              }
              this.capturingRootKey = false;
            }
          }
        } else if (char.charCodeAt(0) < 0x20)
          throw new Error("Invalid control character in JSON string");
        else this.appendRootKey(char);
        continue;
      }

      if (this.primitive) {
        if (this.primitive.offset < this.primitive.word.length) {
          if (char !== this.primitive.word[this.primitive.offset])
            throw new Error("Invalid JSON literal");
          this.primitive.offset++;
          continue;
        }
        if (!this.canEndPrimitive(char))
          throw new Error("Invalid JSON literal ending");
        this.primitive = undefined;
        index--;
        continue;
      }

      if (this.numberState) {
        const state = this.numberState;
        const digit = char >= "0" && char <= "9";
        if (state === "minus") {
          if (char === "0") this.numberState = "zero";
          else if (char >= "1" && char <= "9") this.numberState = "integer";
          else throw new Error("Invalid JSON number");
        } else if (state === "zero") {
          if (char === ".") this.numberState = "fractionStart";
          else if (char === "e" || char === "E")
            this.numberState = "exponentStart";
          else if (this.canEndPrimitive(char)) {
            this.numberState = undefined;
            index--;
          } else throw new Error("Invalid JSON number");
        } else if (
          state === "integer" ||
          state === "fraction" ||
          state === "exponent"
        ) {
          if (digit) continue;
          if (state === "integer" && char === ".")
            this.numberState = "fractionStart";
          else if (
            (state === "integer" || state === "fraction") &&
            (char === "e" || char === "E")
          )
            this.numberState = "exponentStart";
          else if (this.canEndPrimitive(char)) {
            this.numberState = undefined;
            index--;
          } else throw new Error("Invalid JSON number");
        } else if (state === "fractionStart") {
          if (!digit) throw new Error("Invalid JSON number");
          this.numberState = "fraction";
        } else if (state === "exponentStart") {
          if (char === "+" || char === "-") this.numberState = "exponentSign";
          else if (digit) this.numberState = "exponent";
          else throw new Error("Invalid JSON number");
        } else if (state === "exponentSign") {
          if (!digit) throw new Error("Invalid JSON number");
          this.numberState = "exponent";
        }
        continue;
      }

      if (this.isSpace(char)) continue;
      const frame = this.current();
      if (frame?.kind === "object") {
        if (frame.state === "keyOrEnd" && char === "}") this.frames.pop();
        else if (frame.state === "keyOrEnd" && char === '"') {
          frame.state = "key";
          this.stringState = "normal";
          this.beginRootKey();
        } else if (frame.state === "key" && char === '"') {
          this.stringState = "normal";
          this.beginRootKey();
        } else if (frame.state === "colon" && char === ":")
          frame.state = "value";
        else if (frame.state === "commaOrEnd" && char === ",")
          frame.state = "key";
        else if (frame.state === "commaOrEnd" && char === "}")
          this.frames.pop();
        else if (frame.state === "value") this.beginValue(char);
        else throw new Error("Invalid JSON object structure");
      } else if (frame?.kind === "array") {
        if (frame.state === "valueOrEnd" && char === "]") this.frames.pop();
        else if (frame.state === "commaOrEnd" && char === ",")
          frame.state = "value";
        else if (frame.state === "commaOrEnd" && char === "]")
          this.frames.pop();
        else if (frame.state === "valueOrEnd" || frame.state === "value")
          this.beginValue(char);
        else throw new Error("Invalid JSON array structure");
      } else if (this.rootState === "value") this.beginValue(char);
      else throw new Error("Unexpected content after JSON value");
    }
  }

  private beginRootKey(): void {
    this.capturingRootKey = this.frames.length === 1;
    this.rootKey = "";
  }

  private appendRootKey(char: string): void {
    if (this.capturingRootKey && this.rootKey.length <= 32)
      this.rootKey += char;
  }
}

interface ImportMetadata {
  id: string;
  owner: string;
  scope: string;
  totalBytes: number;
  totalChunks: number;
  sha256: string;
  collectedAt: string;
  createdAt: number;
  chunks: Record<string, { bytes: number; sha256: string }>;
}

export interface ScopeImportDeps {
  hierarchyOptions: HierarchyManagerOptions;
  indexManager: IndexManager;
  serverOwner?: string;
  authorizeOwner(request: Request, scope: string): Promise<void>;
  afterTombstoneVersion?(scope: string): Promise<number | null>;
  onDataWritten?(event: { scope: string; collectedAt: string }): void;
  syncManager?: { notifyNewData?(): void; trigger?(): Promise<void> } | null;
}

export class ScopeImportError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

function notifyCommittedScope(
  deps: ScopeImportDeps,
  scope: string,
  collectedAt: string,
): void {
  try {
    deps.syncManager?.notifyNewData?.();
    if (deps.syncManager && !deps.syncManager.notifyNewData) {
      void deps.syncManager.trigger?.().catch(() => undefined);
    }
  } catch {
    // The scope is committed. Notification hooks cannot roll it back.
  }
  try {
    deps.onDataWritten?.({ scope, collectedAt });
  } catch {
    // The scope is committed. Notification hooks cannot roll it back.
  }
}

function importsDir(deps: Pick<ScopeImportDeps, "hierarchyOptions">): string {
  return join(deps.hierarchyOptions.dataDir, IMPORT_DIR);
}

function importPath(
  deps: Pick<ScopeImportDeps, "hierarchyOptions">,
  id: string,
): string {
  return join(importsDir(deps), id);
}

function receiptPath(
  deps: Pick<ScopeImportDeps, "hierarchyOptions">,
  id: string,
): string {
  if (!/^[0-9a-f-]{36}$/i.test(id)) {
    throw new ScopeImportError(404, "IMPORT_NOT_FOUND", "Import not found");
  }
  return join(importsDir(deps), "receipts", `${id}.json`);
}

async function loadMetadata(
  deps: ScopeImportDeps,
  id: string,
  allowExpired = false,
): Promise<ImportMetadata> {
  if (!/^[0-9a-f-]{36}$/i.test(id)) {
    throw new ScopeImportError(404, "IMPORT_NOT_FOUND", "Import not found");
  }
  try {
    const metadata = JSON.parse(
      await readFile(join(importPath(deps, id), "metadata.json"), "utf8"),
    ) as ImportMetadata;
    if (
      !allowExpired &&
      Date.now() - metadata.createdAt > SCOPE_IMPORT_TTL_MS
    ) {
      throw new ScopeImportError(410, "IMPORT_EXPIRED", "Import has expired");
    }
    return metadata;
  } catch (error) {
    if (error instanceof ScopeImportError) throw error;
    throw new ScopeImportError(404, "IMPORT_NOT_FOUND", "Import not found");
  }
}

async function saveMetadata(
  deps: ScopeImportDeps,
  metadata: ImportMetadata,
): Promise<void> {
  const directory = importPath(deps, metadata.id);
  const tempPath = join(directory, `metadata.${randomUUID()}.tmp`);
  await writeAtomic(
    tempPath,
    join(directory, "metadata.json"),
    Buffer.from(JSON.stringify(metadata)),
  );
}

async function writeAtomic(
  tempPath: string,
  finalPath: string,
  bytes: Uint8Array,
): Promise<void> {
  await mkdir(dirname(finalPath), { recursive: true });
  await (await open(tempPath, "wx")).close();
  const handle = await open(tempPath, "w");
  try {
    await handle.writeFile(bytes);
    await handle.sync();
  } finally {
    await handle.close();
  }
  await rename(tempPath, finalPath);
  const directory = await open(dirname(finalPath), "r");
  try {
    await directory.sync();
  } finally {
    await directory.close();
  }
}

async function pathExists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

async function removeImportArtifacts(
  deps: Pick<ScopeImportDeps, "hierarchyOptions" | "indexManager">,
  metadata: ImportMetadata,
): Promise<void> {
  const finalPath = buildDataFilePath(
    deps.hierarchyOptions.dataDir,
    metadata.scope,
    metadata.collectedAt,
  );
  await unlink(`${finalPath}.pending.${metadata.id}`).catch(() => undefined);
  const relativePath = relative(deps.hierarchyOptions.dataDir, finalPath);
  if (!deps.indexManager.findByPath(relativePath)) {
    await unlink(finalPath).catch(() => undefined);
  }
}

export async function cleanupExpiredScopeImports(
  deps: Pick<ScopeImportDeps, "hierarchyOptions" | "indexManager">,
  now = Date.now(),
  removeTemps = false,
): Promise<void> {
  const root = importsDir(deps);
  await mkdir(root, { recursive: true });
  for (const entry of await readdir(root, { withFileTypes: true })) {
    if (!entry.isDirectory() || entry.name === "receipts") continue;
    const directory = join(root, entry.name);
    try {
      const metadata = JSON.parse(
        await readFile(join(directory, "metadata.json"), "utf8"),
      ) as ImportMetadata;
      if (now - metadata.createdAt > SCOPE_IMPORT_TTL_MS) {
        await removeImportArtifacts(deps, metadata);
        await rm(directory, { recursive: true, force: true });
        continue;
      }
      if (removeTemps) {
        for (const item of await readdir(directory, { withFileTypes: true })) {
          if (item.isFile() && item.name.endsWith(".tmp")) {
            await unlink(join(directory, item.name));
          }
        }
      }
    } catch {
      await rm(directory, { recursive: true, force: true });
    }
  }
  const receipts = join(root, "receipts");
  await mkdir(receipts, { recursive: true });
  for (const name of await readdir(receipts)) {
    const path = join(receipts, name);
    try {
      const receipt = JSON.parse(await readFile(path, "utf8")) as {
        completedAt: string;
      };
      if (now - Date.parse(receipt.completedAt) > RECEIPT_TTL_MS) {
        await unlink(path);
      }
    } catch {
      await unlink(path).catch(() => undefined);
    }
  }
}

export async function beginScopeImport(
  deps: ScopeImportDeps,
  request: Request,
  scope: string,
  body: unknown,
): Promise<{ importId: string; chunkBytes: number; expiresAt: string }> {
  await deps.authorizeOwner(request, scope);
  if (!deps.serverOwner) {
    throw new ScopeImportError(
      500,
      "SERVER_NOT_CONFIGURED",
      "Server owner is not configured",
    );
  }
  const scopeKey = `${deps.serverOwner.toLowerCase()}:${scope}`;
  if (openingScopes.has(scopeKey)) {
    throw new ScopeImportError(
      409,
      "IMPORT_IN_PROGRESS",
      "An import for this scope is already being started",
    );
  }
  openingScopes.add(scopeKey);
  if (beginReservationActive) {
    openingScopes.delete(scopeKey);
    throw new ScopeImportError(
      429,
      "IMPORT_CAPACITY",
      "Another import is being reserved; retry shortly",
    );
  }
  beginReservationActive = true;
  try {
    await cleanupExpiredScopeImports(deps);
    const input =
      body !== null && typeof body === "object" && !Array.isArray(body)
        ? (body as Partial<{
            totalBytes: number;
            totalChunks: number;
            sha256: string;
          }>)
        : {};
    if (
      !Number.isSafeInteger(input.totalBytes) ||
      input.totalBytes! <= 0 ||
      input.totalBytes! > SCOPE_IMPORT_MAX_BYTES ||
      !Number.isSafeInteger(input.totalChunks) ||
      input.totalChunks! <= 0 ||
      input.totalChunks! > SCOPE_IMPORT_MAX_CHUNKS ||
      input.totalChunks! !==
        Math.ceil(input.totalBytes! / SCOPE_IMPORT_CHUNK_BYTES) ||
      typeof input.sha256 !== "string" ||
      !SHA256.test(input.sha256)
    ) {
      throw new ScopeImportError(
        400,
        "INVALID_IMPORT",
        "Import size, chunk count, or SHA-256 is invalid",
      );
    }
    const receiptCount = (await readdir(join(importsDir(deps), "receipts")))
      .length;
    const active = (
      await readdir(importsDir(deps), { withFileTypes: true })
    ).filter((item) => item.isDirectory() && item.name !== "receipts");
    let activeBytes = 0;
    let activeForScope = false;
    for (const item of active) {
      try {
        const metadata = JSON.parse(
          await readFile(
            join(importsDir(deps), item.name, "metadata.json"),
            "utf8",
          ),
        ) as ImportMetadata;
        activeBytes += metadata.totalBytes;
        activeForScope ||= metadata.scope === scope;
      } catch {
        // Invalid entries are removed by cleanup on the next request.
      }
    }
    if (receiptCount + active.length >= MAX_DURABLE_RECEIPTS) {
      throw new ScopeImportError(
        429,
        "RECEIPT_CAPACITY",
        "Import receipt storage is full",
      );
    }
    if (
      activeForScope ||
      active.length >= 4 ||
      activeBytes + input.totalBytes! > SCOPE_IMPORT_MAX_BYTES * 2
    ) {
      throw new ScopeImportError(
        429,
        "IMPORT_CAPACITY",
        "Import storage capacity is full",
      );
    }
    const id = randomUUID();
    let collectedAt = new Date().toISOString();
    while (
      await pathExists(
        buildDataFilePath(deps.hierarchyOptions.dataDir, scope, collectedAt),
      )
    ) {
      collectedAt = new Date(Date.parse(collectedAt) + 1).toISOString();
    }
    const metadata: ImportMetadata = {
      id,
      owner: deps.serverOwner.toLowerCase(),
      scope,
      totalBytes: input.totalBytes!,
      totalChunks: input.totalChunks!,
      sha256: input.sha256.toLowerCase(),
      collectedAt,
      createdAt: Date.now(),
      chunks: {},
    };
    await mkdir(importPath(deps, id), { recursive: true });
    await saveMetadata(deps, metadata);
    return {
      importId: id,
      chunkBytes: SCOPE_IMPORT_CHUNK_BYTES,
      expiresAt: new Date(
        metadata.createdAt + SCOPE_IMPORT_TTL_MS,
      ).toISOString(),
    };
  } finally {
    beginReservationActive = false;
    openingScopes.delete(scopeKey);
  }
}

async function writeChunkToFile(
  bytes: Uint8Array,
  path: string,
): Promise<{ bytes: number; sha256: string }> {
  if (bytes.byteLength === 0)
    throw new ScopeImportError(400, "EMPTY_CHUNK", "Chunk body is required");
  const handle = await open(path, "wx");
  const hash = createHash("sha256");
  try {
    if (bytes.byteLength > SCOPE_IMPORT_CHUNK_BYTES) {
      throw new ScopeImportError(413, "CHUNK_TOO_LARGE", "Chunk exceeds 8 MiB");
    }
    hash.update(bytes);
    await handle.writeFile(bytes);
    await handle.sync();
  } catch (error) {
    await unlink(path).catch(() => undefined);
    throw error;
  } finally {
    await handle.close();
  }
  return { bytes: bytes.byteLength, sha256: hash.digest("hex") };
}

export async function putScopeImportChunk(
  deps: ScopeImportDeps,
  request: Request,
  scope: string,
  id: string,
  index: number,
): Promise<{ accepted: true; index: number; bytes: number; sha256: string }> {
  await deps.authorizeOwner(request, scope);
  const bodyBytes = await cacheRequestBodyBytes(
    request,
    SCOPE_IMPORT_CHUNK_BYTES,
  );
  if (!bodyBytes) {
    throw new ScopeImportError(400, "EMPTY_CHUNK", "Chunk body is required");
  }
  if (abortingImports.has(id)) {
    throw new ScopeImportError(
      409,
      "IMPORT_ABORTING",
      "Import is being aborted",
    );
  }
  const metadata = await loadMetadata(deps, id);
  if (
    metadata.owner !== deps.serverOwner?.toLowerCase() ||
    metadata.scope !== scope
  ) {
    throw new ScopeImportError(404, "IMPORT_NOT_FOUND", "Import not found");
  }
  if (
    !Number.isSafeInteger(index) ||
    index < 0 ||
    index >= metadata.totalChunks
  ) {
    throw new ScopeImportError(
      400,
      "INVALID_CHUNK_INDEX",
      "Chunk index is out of range",
    );
  }
  if (
    request.headers.get("content-type")?.split(";", 1)[0] !==
    "application/octet-stream"
  ) {
    throw new ScopeImportError(
      415,
      "INVALID_CHUNK_TYPE",
      "Chunk must use application/octet-stream",
    );
  }
  if (abortingImports.has(id)) {
    throw new ScopeImportError(
      409,
      "IMPORT_ABORTING",
      "Import is being aborted",
    );
  }
  const chunkKey = `${id}:${index}`;
  if (activeChunkIndexes.has(chunkKey)) {
    throw new ScopeImportError(
      409,
      "CHUNK_IN_PROGRESS",
      "This chunk is already being uploaded",
    );
  }
  const present = new Set(Object.keys(metadata.chunks).map(Number));
  let firstMissing = 0;
  while (present.has(firstMissing)) firstMissing++;
  if (index > firstMissing) {
    throw new ScopeImportError(
      409,
      "CHUNK_GAP",
      `Expected chunk ${firstMissing}`,
    );
  }
  const expectedBytes =
    index === metadata.totalChunks - 1
      ? metadata.totalBytes - SCOPE_IMPORT_CHUNK_BYTES * index
      : SCOPE_IMPORT_CHUNK_BYTES;
  const expectedHash = request.headers.get("x-chunk-sha256")?.toLowerCase();
  if (!expectedHash || !SHA256.test(expectedHash)) {
    throw new ScopeImportError(
      400,
      "INVALID_CHUNK_HASH",
      "X-Chunk-SHA256 must be a SHA-256 hex digest",
    );
  }
  const directory = importPath(deps, id);
  const target = join(directory, `chunk-${index}.bin`);
  const temp = join(directory, `chunk-${index}.${randomUUID()}.tmp`);
  if (activeChunkWrites >= 4) {
    throw new ScopeImportError(
      429,
      "UPLOAD_CAPACITY",
      "Too many chunks are being uploaded",
    );
  }
  activeChunkWrites++;
  activeChunkIndexes.add(chunkKey);
  try {
    const received = await writeChunkToFile(bodyBytes, temp);
    if (received.bytes !== expectedBytes || received.sha256 !== expectedHash) {
      await unlink(temp).catch(() => undefined);
      throw new ScopeImportError(
        422,
        "CHUNK_HASH_MISMATCH",
        "Chunk size or SHA-256 does not match",
      );
    }
    const existing = metadata.chunks[String(index)];
    if (existing) {
      await unlink(temp);
      if (
        existing.bytes !== received.bytes ||
        existing.sha256 !== received.sha256
      ) {
        throw new ScopeImportError(
          409,
          "CHUNK_CONFLICT",
          "Chunk index already has different content",
        );
      }
      return { accepted: true, index, ...existing };
    }
    await rename(temp, target);
    const directoryHandle = await open(directory, "r");
    try {
      await directoryHandle.sync();
    } finally {
      await directoryHandle.close();
    }
    metadata.chunks[String(index)] = received;
    await saveMetadata(deps, metadata);
    return { accepted: true, index, ...received };
  } finally {
    activeChunkWrites--;
    activeChunkIndexes.delete(chunkKey);
  }
}

export async function finalizeScopeImport(
  deps: ScopeImportDeps,
  request: Request,
  scope: string,
  id: string,
): Promise<Record<string, unknown>> {
  await deps.authorizeOwner(request, scope);
  if (abortingImports.has(id)) {
    throw new ScopeImportError(
      409,
      "IMPORT_ABORTING",
      "Import is being aborted",
    );
  }
  if (finalizingImports.has(id)) {
    throw new ScopeImportError(
      409,
      "IMPORT_FINALIZING",
      "Import is already being finalized",
    );
  }
  finalizingImports.add(id);
  try {
    return await finalizeScopeImportAuthorized(deps, scope, id);
  } finally {
    finalizingImports.delete(id);
  }
}

export async function abortScopeImport(
  deps: ScopeImportDeps,
  request: Request,
  scope: string,
  id: string,
): Promise<Record<string, unknown>> {
  await deps.authorizeOwner(request, scope);
  if (finalizingImports.has(id)) {
    throw new ScopeImportError(
      409,
      "IMPORT_FINALIZING",
      "Import is already being finalized",
    );
  }
  if (abortingImports.has(id)) {
    throw new ScopeImportError(
      409,
      "IMPORT_ABORTING",
      "Import is already being aborted",
    );
  }
  abortingImports.add(id);
  try {
    if ([...activeChunkIndexes].some((key) => key.startsWith(`${id}:`))) {
      throw new ScopeImportError(
        409,
        "CHUNK_IN_PROGRESS",
        "A chunk for this import is still being uploaded",
      );
    }
    const receiptFile = receiptPath(deps, id);
    let prior: Record<string, unknown> | undefined;
    try {
      prior = JSON.parse(await readFile(receiptFile, "utf8")) as Record<
        string,
        unknown
      >;
    } catch {
      // No terminal receipt exists yet.
    }
    if (prior) {
      if (
        prior.owner !== deps.serverOwner?.toLowerCase() ||
        prior.scope !== scope
      ) {
        throw new ScopeImportError(404, "IMPORT_NOT_FOUND", "Import not found");
      }
      if (prior.status !== "aborted") {
        throw new ScopeImportError(
          409,
          "IMPORT_FINALIZED",
          "A finalized import cannot be aborted",
        );
      }
      try {
        const metadata = await loadMetadata(deps, id, true);
        if (metadata.owner === prior.owner && metadata.scope === prior.scope) {
          await removeImportArtifacts(deps, metadata);
          await rm(importPath(deps, id), { recursive: true, force: true });
        }
      } catch (error) {
        if (!(error instanceof ScopeImportError) || error.status !== 404) {
          throw error;
        }
      }
      return prior;
    }

    const metadata = await loadMetadata(deps, id, true);
    if (
      metadata.owner !== deps.serverOwner?.toLowerCase() ||
      metadata.scope !== scope
    ) {
      throw new ScopeImportError(404, "IMPORT_NOT_FOUND", "Import not found");
    }
    const abortedAt = new Date().toISOString();
    const receipt = {
      importId: id,
      owner: metadata.owner,
      scope,
      status: "aborted",
      abortedAt,
      completedAt: abortedAt,
    };
    await writeAtomic(
      `${receiptFile}.${randomUUID()}.tmp`,
      receiptFile,
      Buffer.from(JSON.stringify(receipt)),
    );
    await removeImportArtifacts(deps, metadata);
    await rm(importPath(deps, id), { recursive: true, force: true });
    return receipt;
  } finally {
    abortingImports.delete(id);
  }
}

async function finalizeScopeImportAuthorized(
  deps: ScopeImportDeps,
  scope: string,
  id: string,
): Promise<Record<string, unknown>> {
  try {
    const prior = JSON.parse(
      await readFile(receiptPath(deps, id), "utf8"),
    ) as Record<string, unknown>;
    if (
      prior.scope === scope &&
      prior.owner === deps.serverOwner?.toLowerCase()
    ) {
      if (prior.status === "aborted") {
        throw new ScopeImportError(410, "IMPORT_ABORTED", "Import was aborted");
      }
      return prior;
    }
  } catch (error) {
    if (error instanceof ScopeImportError) throw error;
    // No prior receipt.
  }
  const metadata = await loadMetadata(deps, id);
  if (
    metadata.owner !== deps.serverOwner?.toLowerCase() ||
    metadata.scope !== scope
  ) {
    throw new ScopeImportError(404, "IMPORT_NOT_FOUND", "Import not found");
  }
  if (Object.keys(metadata.chunks).length !== metadata.totalChunks) {
    throw new ScopeImportError(
      409,
      "IMPORT_INCOMPLETE",
      "Not all declared chunks have been uploaded",
    );
  }

  let finalPath = buildDataFilePath(
    deps.hierarchyOptions.dataDir,
    scope,
    metadata.collectedAt,
  );
  let stagePath = `${finalPath}.pending.${id}`;
  let relativePath = relative(deps.hierarchyOptions.dataDir, finalPath);
  const committedEntry = deps.indexManager.findByPath(relativePath);
  if (
    committedEntry?.scope === scope &&
    committedEntry.collectedAt === metadata.collectedAt
  ) {
    if (!(await pathExists(finalPath)) && (await pathExists(stagePath))) {
      await publishStagedDataFile(stagePath, finalPath);
    }
    if (await pathExists(finalPath)) {
      const receipt = {
        importId: id,
        owner: metadata.owner,
        scope,
        sha256: metadata.sha256,
        totalBytes: metadata.totalBytes,
        collectedAt: metadata.collectedAt,
        completedAt: new Date().toISOString(),
      };
      const receiptFile = receiptPath(deps, id);
      await writeAtomic(
        `${receiptFile}.${randomUUID()}.tmp`,
        receiptFile,
        Buffer.from(JSON.stringify(receipt)),
      );
      await rm(importPath(deps, id), { recursive: true, force: true });
      notifyCommittedScope(deps, scope, metadata.collectedAt);
      return receipt;
    }
  }
  // A crash can publish the fully validated envelope but stop before its
  // index transaction. Remove that unindexed publication before retrying with
  // a fresh timestamp so repeated retries cannot leave visible orphan files.
  if (!committedEntry && (await pathExists(finalPath))) {
    await unlink(finalPath);
  }
  const latestBeforeStage = deps.indexManager.findLatestByScope(scope);
  const latestTime = latestBeforeStage
    ? Date.parse(latestBeforeStage.collectedAt)
    : Number.NEGATIVE_INFINITY;
  let collectedAt = new Date(
    Math.max(Date.now(), latestTime + 1),
  ).toISOString();
  while (
    await pathExists(
      buildDataFilePath(deps.hierarchyOptions.dataDir, scope, collectedAt),
    )
  ) {
    collectedAt = new Date(Date.parse(collectedAt) + 1).toISOString();
  }
  metadata.collectedAt = collectedAt;
  await saveMetadata(deps, metadata);
  finalPath = buildDataFilePath(
    deps.hierarchyOptions.dataDir,
    scope,
    metadata.collectedAt,
  );
  stagePath = `${finalPath}.pending.${id}`;
  relativePath = relative(deps.hierarchyOptions.dataDir, finalPath);
  await mkdir(dirname(finalPath), { recursive: true });
  const file = await open(stagePath, "wx");
  const hash = createHash("sha256");
  const validator = new JsonObjectStreamValidator();
  let total = 0;
  const write = async (bytes: Uint8Array) => {
    await file.writeFile(bytes);
  };
  try {
    await write(
      Buffer.from(
        `{"version":"1.0","scope":${JSON.stringify(scope)},"collectedAt":${JSON.stringify(metadata.collectedAt)},"data":`,
      ),
    );
    for (let index = 0; index < metadata.totalChunks; index++) {
      const chunkPath = join(importPath(deps, id), `chunk-${index}.bin`);
      const chunkHash = createHash("sha256");
      let chunkBytes = 0;
      for await (const chunk of createReadStream(chunkPath)) {
        const bytes = chunk as Buffer;
        chunkBytes += bytes.byteLength;
        total += bytes.byteLength;
        chunkHash.update(bytes);
        hash.update(bytes);
        try {
          validator.write(bytes);
        } catch {
          throw new ScopeImportError(
            400,
            "INVALID_SCOPE_JSON",
            "Scope data is not valid JSON",
          );
        }
        await write(bytes);
      }
      const declared = metadata.chunks[String(index)];
      if (
        chunkBytes !== declared.bytes ||
        chunkHash.digest("hex") !== declared.sha256
      ) {
        throw new ScopeImportError(
          422,
          "CHUNK_CORRUPT",
          `Stored chunk ${index} failed its hash check`,
        );
      }
    }
    try {
      validator.end();
    } catch {
      throw new ScopeImportError(
        400,
        "INVALID_SCOPE_JSON",
        "Scope data is not valid JSON",
      );
    }
    const digest = hash.digest("hex");
    if (total !== metadata.totalBytes || digest !== metadata.sha256) {
      throw new ScopeImportError(
        422,
        "IMPORT_HASH_MISMATCH",
        "Imported scope size or SHA-256 does not match",
      );
    }
    await write(Buffer.from("}"));
    await file.sync();
  } catch (error) {
    await unlink(stagePath).catch(() => undefined);
    if (error instanceof ScopeImportError) throw error;
    throw error;
  } finally {
    await file.close();
  }

  try {
    const sizeBytes = (await stat(stagePath)).size;
    const afterTombstoneVersion =
      (await deps.afterTombstoneVersion?.(scope)) ?? null;
    const latestAtCommit = deps.indexManager.findLatestByScope(scope);
    if (
      latestAtCommit &&
      Date.parse(latestAtCommit.collectedAt) >= Date.parse(metadata.collectedAt)
    ) {
      await unlink(stagePath).catch(() => undefined);
      metadata.collectedAt = new Date(
        Date.parse(latestAtCommit.collectedAt) + 1,
      ).toISOString();
      await saveMetadata(deps, metadata);
      throw new ScopeImportError(
        409,
        "SCOPE_CHANGED",
        "Scope changed while the import was in progress; retry finalize",
      );
    }
    // Publish the complete, fsynced envelope before swapping the SQLite index.
    // Readers continue to resolve the old entry until the new file is ready.
    await publishStagedDataFile(stagePath, finalPath);
    let indexed: ReturnType<typeof deps.indexManager.insertIfCurrent>;
    try {
      indexed = deps.indexManager.insertIfCurrent(
        {
          fileId: null,
          schemaId: null,
          path: relativePath,
          scope,
          collectedAt: metadata.collectedAt,
          sizeBytes,
          dataPointId: null,
          afterTombstoneVersion,
          producer: null,
          producerProvenance: null,
        },
        latestAtCommit
          ? {
              kind: "match",
              version: latestAtCommit.casRevision ?? latestAtCommit.version,
            }
          : { kind: "none" },
      );
    } catch (error) {
      // The synchronous index API can throw. Keep the data file only if the
      // transaction committed before the error became observable.
      if (!deps.indexManager.findByPath(relativePath)) {
        await unlink(finalPath).catch(() => undefined);
      }
      throw error;
    }
    if (!indexed.ok) {
      await unlink(finalPath).catch(() => undefined);
      const latest = deps.indexManager.findLatestByScope(scope);
      if (latest) {
        metadata.collectedAt = new Date(
          Date.parse(latest.collectedAt) + 1,
        ).toISOString();
        await saveMetadata(deps, metadata);
      }
      throw new ScopeImportError(
        409,
        "SCOPE_CHANGED",
        "Scope changed while the import was in progress",
      );
    }
    const receipt = {
      importId: id,
      owner: metadata.owner,
      scope,
      sha256: metadata.sha256,
      totalBytes: metadata.totalBytes,
      collectedAt: metadata.collectedAt,
      completedAt: new Date().toISOString(),
    };
    const receiptFile = receiptPath(deps, id);
    const receiptTemp = `${receiptFile}.${randomUUID()}.tmp`;
    await writeAtomic(
      receiptTemp,
      receiptFile,
      Buffer.from(JSON.stringify(receipt)),
    );
    await rm(importPath(deps, id), { recursive: true, force: true });
    notifyCommittedScope(deps, scope, metadata.collectedAt);
    return receipt;
  } catch (error) {
    await removeImportArtifacts(deps, metadata);
    throw error;
  }
}
