/**
 * Streamed scope writes ("uploads"): one new version of a scope, written as a
 * sequence of record batches instead of one JSON body.
 *
 *   POST   /v1/data/:scope/uploads                     begin
 *   PUT    /v1/data/:scope/uploads/:id/batches/:seq    append one batch
 *   POST   /v1/data/:scope/uploads/:id/commit          make it the newest version
 *   DELETE /v1/data/:scope/uploads/:id                 discard it
 *
 * A JSON write holds the whole document several times over while it parses,
 * stamps, stores and indexes it, so its memory grows with the scope. Here the
 * server holds one batch at a time: each batch is parsed, serialized into the
 * envelope text and handed to `DataStoragePort.openVersionWriter`, which keeps
 * no copy. The stored envelope is the same JSON a single write of
 * `{...data, [arrayKey]: [...all items], ...commitData}` would store.
 *
 * Atomicity comes from the storage writer: nothing is indexed before
 * `commit`, so until then (and after an abort, an idle timeout or a crash)
 * readers and sync see the previous version and no partial one.
 *
 * Batches are numbered from 0 and must arrive in order. Only the latest batch
 * can be replayed: the server keeps the digest of that one batch, not of every
 * batch, so memory does not grow with the batch count. Sending the latest
 * number again with the same body is answered as a replay and stores nothing,
 * so a caller that lost a response can retry it. A different body under that
 * number is refused (BATCH_CONFLICT), and any older number is refused
 * (BATCH_OUT_OF_ORDER). The SDK only ever resends the batch it just sent, so
 * that is enough.
 *
 * One upload is open per registry at a time, because the storage writer may
 * hold the only file-write slot (PS-Lite's native host has one). A new begin
 * aborts the open upload, so an abandoned upload cannot block writes for
 * longer than the idle timeout or until the next begin.
 */

import type { DataStoragePort, DataVersionWriter } from "../ports/index.js";
import type { WriteResult } from "../storage/hierarchy/index.js";
import { sha256Hex } from "../contracts/binary.js";
import { hasReservedLineageKey } from "../lineage/lineage.js";
import { hasReservedWriterKey } from "../write/attribution.js";

/**
 * Largest batch body accepted, in UTF-8 bytes. Callers send far smaller
 * batches; the limit only has to admit the largest single record.
 */
export const SCOPE_UPLOAD_MAX_BATCH_BYTES = 16 * 1024 * 1024;
/** An upload with no request for this long is aborted. */
export const SCOPE_UPLOAD_IDLE_TIMEOUT_MS = 2 * 60 * 1000;
/** Largest `data` object a begin or commit may carry, serialized. */
const MAX_FRAME_BYTES = 64 * 1024;
/** Ended upload ids remembered so a late call learns why, not just 404. */
const ENDED_MEMORY = 16;
const DEFAULT_ARRAY_KEY = "records";
/** Keys the plain JSON write gives meaning to; an upload cannot use them. */
const SPECIAL_KEYS = new Set(["lineage", "$binary"]);
const textEncoder = new TextEncoder();

export class ScopeUploadError extends Error {
  constructor(
    readonly status: 400 | 404 | 409 | 410 | 413 | 501,
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "ScopeUploadError";
  }
}

export interface ScopeUploadBegin {
  storage: DataStoragePort;
  scope: string;
  /** Reserved by the caller; must not name an existing version. */
  collectedAt: string;
  /** Called once the upload ends, however it ends, to free `collectedAt`. */
  release(): void;
  /** Parsed begin body: `{ data?: object, arrayKey?: string }`. */
  body: unknown;
}

export interface ScopeUploadCommitted {
  scope: string;
  collectedAt: string;
  records: number;
  writeResult: WriteResult;
}

export interface ScopeUploadRegistry {
  readonly maxBatchBytes: number;
  begin(input: ScopeUploadBegin): Promise<{
    uploadId: string;
    collectedAt: string;
  }>;
  append(input: {
    scope: string;
    uploadId: string;
    seq: number;
    /** The raw batch body: `{"items":[...]}`. */
    text: string;
  }): Promise<{ seq: number; items: number; replay: boolean }>;
  commit(input: {
    scope: string;
    uploadId: string;
    /** Parsed commit body: `{ data?: object }`. */
    body: unknown;
    afterTombstoneVersion: number | null;
  }): Promise<ScopeUploadCommitted>;
  abort(input: { scope: string; uploadId: string }): Promise<void>;
}

export interface ScopeUploadRegistryOptions {
  idleTimeoutMs?: number;
  maxBatchBytes?: number;
  createId?: () => string;
}

interface OpenUpload {
  id: string;
  scope: string;
  collectedAt: string;
  storage: DataStoragePort;
  writer: DataVersionWriter;
  release(): void;
  arrayKey: string;
  headKeys: Set<string>;
  /** Batches accepted so far; the next batch number. */
  batches: number;
  /** Digest of the latest batch only. Older digests are not kept. */
  latestDigest: string | null;
  items: number;
  timer: ReturnType<typeof setTimeout> | undefined;
}

export function createScopeUploadRegistry(
  options: ScopeUploadRegistryOptions = {},
): ScopeUploadRegistry {
  const idleTimeoutMs = options.idleTimeoutMs ?? SCOPE_UPLOAD_IDLE_TIMEOUT_MS;
  const maxBatchBytes = options.maxBatchBytes ?? SCOPE_UPLOAD_MAX_BATCH_BYTES;
  const createId = options.createId ?? (() => crypto.randomUUID());
  let open: OpenUpload | null = null;
  const ended = new Map<string, "committed" | "aborted" | "expired">();

  function remember(id: string, why: "committed" | "aborted" | "expired") {
    ended.set(id, why);
    if (ended.size > ENDED_MEMORY) ended.delete(ended.keys().next().value!);
  }

  /** Close the open upload. The writer is aborted unless it committed. */
  async function end(
    upload: OpenUpload,
    why: "committed" | "aborted" | "expired",
  ): Promise<void> {
    if (open !== upload) return;
    open = null;
    if (upload.timer !== undefined) clearTimeout(upload.timer);
    remember(upload.id, why);
    try {
      if (why !== "committed") await upload.writer.abort();
    } finally {
      upload.release();
    }
  }

  /**
   * Every begin, request and expiry runs here, one at a time. The writer
   * takes one call at a time, and an upload cannot end, or give way to a new
   * one, while one of its requests is still writing.
   */
  let queue: Promise<unknown> = Promise.resolve();
  function exclusive<T>(step: () => Promise<T>): Promise<T> {
    const run = queue.then(step);
    queue = run.catch(() => undefined);
    return run;
  }

  /** Expire the upload after it has been idle, between requests only. */
  function armTimer(upload: OpenUpload): void {
    if (open !== upload) return;
    const timer = setTimeout(() => {
      void exclusive(() => end(upload, "expired")).catch(() => undefined);
    }, idleTimeoutMs);
    // Node: an idle upload must not keep the process alive.
    (timer as { unref?: () => void }).unref?.();
    upload.timer = timer;
  }

  function find(scope: string, uploadId: string): OpenUpload {
    if (open && open.id === uploadId && open.scope === scope) return open;
    const why = ended.get(uploadId);
    if (why === "committed") {
      throw new ScopeUploadError(
        409,
        "UPLOAD_COMMITTED",
        "Upload is already committed",
      );
    }
    if (why) {
      throw new ScopeUploadError(
        410,
        why === "expired" ? "UPLOAD_EXPIRED" : "UPLOAD_ABORTED",
        why === "expired" ? "Upload expired while idle" : "Upload was aborted",
      );
    }
    throw new ScopeUploadError(404, "UPLOAD_NOT_FOUND", "Upload not found");
  }

  /** Run `step` as the upload's next request; a storage failure aborts it. */
  function serialized<T>(
    upload: OpenUpload,
    step: () => Promise<T>,
  ): Promise<T> {
    return exclusive(async () => {
      // An earlier request or expiry may have ended it while this one waited.
      find(upload.scope, upload.id);
      if (upload.timer !== undefined) clearTimeout(upload.timer);
      upload.timer = undefined;
      try {
        return await step();
      } catch (err) {
        // A refused request leaves the upload usable; a storage failure
        // does not, because the writer may hold half a batch.
        if (!(err instanceof ScopeUploadError)) {
          await end(upload, "aborted").catch(() => undefined);
        }
        throw err;
      } finally {
        armTimer(upload);
      }
    });
  }

  return {
    maxBatchBytes,

    async begin(input) {
      let started = false;
      try {
        const body = objectBody(input.body, "begin");
        const unknown = Object.keys(body).filter(
          (key) => key !== "data" && key !== "arrayKey",
        );
        if (unknown.length > 0) {
          throw invalid(`Unknown begin field: ${unknown[0]}`);
        }
        const arrayKey = body.arrayKey ?? DEFAULT_ARRAY_KEY;
        if (typeof arrayKey !== "string" || arrayKey.length === 0) {
          throw invalid("arrayKey must be a non-empty string");
        }
        assertUsableKey(arrayKey);
        const head = frameData(body.data, "data");
        if (Object.prototype.hasOwnProperty.call(head, arrayKey)) {
          throw invalid(`data must not contain the array key "${arrayKey}"`);
        }
        if (!input.storage.openVersionWriter) {
          throw new ScopeUploadError(
            501,
            "UPLOAD_UNSUPPORTED",
            "This storage backend cannot stream a version",
          );
        }

        const openVersionWriter = input.storage.openVersionWriter;
        const upload = await exclusive(async () => {
          // One file-write slot: the open upload gives way to the new one.
          if (open) await end(open, "aborted").catch(() => undefined);
          const writer = await openVersionWriter(
            input.scope,
            input.collectedAt,
          );
          started = true;
          const created: OpenUpload = {
            id: createId(),
            scope: input.scope,
            collectedAt: input.collectedAt,
            storage: input.storage,
            writer,
            release: input.release,
            arrayKey,
            headKeys: new Set(Object.keys(head)),
            batches: 0,
            latestDigest: null,
            items: 0,
            timer: undefined,
          };
          open = created;
          try {
            await writer.write(
              `{"version":"1.0","scope":${JSON.stringify(input.scope)},` +
                `"collectedAt":${JSON.stringify(input.collectedAt)},"data":{` +
                Object.entries(head)
                  .map(
                    ([key, value]) =>
                      `${JSON.stringify(key)}:${JSON.stringify(value)},`,
                  )
                  .join("") +
                `${JSON.stringify(arrayKey)}:[`,
            );
          } catch (err) {
            await end(created, "aborted").catch(() => undefined);
            throw err;
          }
          armTimer(created);
          return created;
        });
        return { uploadId: upload.id, collectedAt: upload.collectedAt };
      } finally {
        if (!started) input.release();
      }
    },

    async append(input) {
      const upload = find(input.scope, input.uploadId);
      return serialized(upload, async () => {
        if (!Number.isSafeInteger(input.seq) || input.seq < 0) {
          throw invalid("Batch number must be a non-negative integer");
        }
        if (textEncoder.encode(input.text).byteLength > maxBatchBytes) {
          throw new ScopeUploadError(
            413,
            "BATCH_TOO_LARGE",
            `Batch exceeds ${maxBatchBytes} bytes`,
          );
        }
        const digest = await sha256Hex(textEncoder.encode(input.text));
        const latest = upload.batches - 1;
        if (input.seq === latest && upload.latestDigest !== null) {
          if (upload.latestDigest !== digest) {
            throw new ScopeUploadError(
              409,
              "BATCH_CONFLICT",
              `Batch ${input.seq} was already received with a different body`,
            );
          }
          return { seq: input.seq, items: 0, replay: true };
        }
        if (input.seq < latest) {
          throw new ScopeUploadError(
            409,
            "BATCH_OUT_OF_ORDER",
            `Batch ${input.seq} is older than batch ${latest}, the only one that can be replayed`,
          );
        }
        if (input.seq !== upload.batches) {
          throw new ScopeUploadError(
            409,
            "BATCH_OUT_OF_ORDER",
            `Expected batch ${upload.batches}, got ${input.seq}`,
          );
        }
        let parsed: unknown;
        try {
          parsed = JSON.parse(input.text);
        } catch {
          throw invalid("Batch body must be valid JSON");
        }
        const batch = objectBody(parsed, "batch");
        if (
          Object.keys(batch).length !== 1 ||
          !Array.isArray(batch.items) ||
          batch.items.length === 0
        ) {
          throw invalid(
            'Batch body must be {"items": [...]} with at least one item',
          );
        }
        const items = batch.items as unknown[];
        // One copy of the batch as text, then nothing retained.
        const text =
          (upload.items > 0 ? "," : "") +
          items.map((item) => JSON.stringify(item)).join(",");
        await upload.writer.write(text);
        upload.batches += 1;
        upload.latestDigest = digest;
        upload.items += items.length;
        return { seq: input.seq, items: items.length, replay: false };
      });
    },

    async commit(input) {
      const upload = find(input.scope, input.uploadId);
      return serialized(upload, async () => {
        const body = objectBody(input.body ?? {}, "commit");
        const unknown = Object.keys(body).filter((key) => key !== "data");
        if (unknown.length > 0) {
          throw invalid(`Unknown commit field: ${unknown[0]}`);
        }
        const tail = frameData(body.data, "data");
        for (const key of Object.keys(tail)) {
          if (key === upload.arrayKey || upload.headKeys.has(key)) {
            throw invalid(`data key "${key}" is already in the envelope`);
          }
        }
        // A version committed since begin is newer than this one: becoming
        // visible now would not make this upload the scope's latest.
        const latest = upload.storage.findEntry({ scope: upload.scope });
        if (
          latest &&
          Date.parse(latest.collectedAt) > Date.parse(upload.collectedAt)
        ) {
          await end(upload, "aborted");
          throw new ScopeUploadError(
            409,
            "UPLOAD_SUPERSEDED",
            "A newer version of this scope was written during the upload",
          );
        }
        await upload.writer.write(
          "]" +
            Object.entries(tail)
              .map(
                ([key, value]) =>
                  `,${JSON.stringify(key)}:${JSON.stringify(value)}`,
              )
              .join("") +
            "}}",
        );
        const writeResult = await upload.writer.commit({
          fileId: null,
          schemaId: null,
          afterTombstoneVersion: input.afterTombstoneVersion,
        });
        await end(upload, "committed");
        return {
          scope: upload.scope,
          collectedAt: upload.collectedAt,
          records: upload.items,
          writeResult,
        };
      });
    },

    async abort(input) {
      const upload = find(input.scope, input.uploadId);
      await serialized(upload, () => end(upload, "aborted"));
    },
  };
}

function invalid(message: string): ScopeUploadError {
  return new ScopeUploadError(400, "INVALID_UPLOAD", message);
}

function objectBody(value: unknown, what: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw invalid(`The ${what} body must be a JSON object`);
  }
  return value as Record<string, unknown>;
}

/** A begin or commit `data` object: small, and free of server-owned keys. */
function frameData(value: unknown, what: string): Record<string, unknown> {
  if (value === undefined) return {};
  const data = objectBody(value, what);
  for (const key of Object.keys(data)) assertUsableKey(key);
  if (textEncoder.encode(JSON.stringify(data)).byteLength > MAX_FRAME_BYTES) {
    throw new ScopeUploadError(
      413,
      "FRAME_TOO_LARGE",
      `${what} exceeds ${MAX_FRAME_BYTES} bytes; send records as batches`,
    );
  }
  return data;
}

function assertUsableKey(key: string): void {
  const probe = { [key]: true };
  if (
    SPECIAL_KEYS.has(key) ||
    hasReservedWriterKey(probe) ||
    hasReservedLineageKey(probe)
  ) {
    throw invalid(`"${key}" cannot be written by an upload`);
  }
}
