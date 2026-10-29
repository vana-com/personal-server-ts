/**
 * Import jobs over the Lite canonical store (docs/261028-pdpp-import-job.md,
 * "Native staged copy"). The host stages the entries this module encodes and
 * later copies them into its canonical tables in one native transaction, so
 * Dart never re-implements record encoding.
 *
 * The encoder runs the real `commitLocal` write path against a read view and
 * captures its writes instead of committing them. The entries are therefore
 * the exact keys and values Lite would write for the same batch, by
 * construction.
 */

import {
  canonicalJson,
  type DeclarationBinding,
} from "@opendatalabs/personal-server-ts-core/replication/envelope";
import type { MergeContext } from "@opendatalabs/personal-server-ts-core/replication/merge-plan";
import {
  ImportJobError,
  type ImportCanonicalEntry,
  type ImportCanonicalFence,
  type ImportJobRecord,
  type ImportStagedOperation,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-import-job";
import {
  createLiteCanonicalStore,
  type LiteCommitReceipt,
  type LiteOperationDraft,
} from "./canonical-store.js";
import {
  LITE_CANONICAL_BATCH_BYTES,
  LITE_CANONICAL_MAX_OPERATION_BYTES,
  LITE_CANONICAL_MAX_VALUE_BYTES,
  type LiteBlobDescriptor,
  type LiteCanonicalTransaction,
  type LiteStorageEntry,
  type LiteStoragePage,
} from "./canonical-persistence.js";

export * from "@opendatalabs/personal-server-ts-core/storage/pdpp-import-job";

/** One canonical KV write. `value: null` deletes the key. */
export type LiteCanonicalEntry = ImportCanonicalEntry;

/**
 * What the encoder reads. For a job, the host answers from the job's staged
 * entries over its committed canonical entries, so each batch sees the clock,
 * rows and receipts the earlier batches of the same job wrote.
 *
 * `getMany` and `scanMany` are optional batched reads: item `i` is what
 * `get`/`scan` would return for request `i`, all items of one call from one
 * snapshot. A host may answer a leading part of the list (at least one item);
 * the encoder asks again for the rest. The encoder sends at most
 * `LITE_IMPORT_READ_MANY_MAX` items per call.
 */
export interface LiteCanonicalReadView {
  get(key: string): Promise<string | undefined>;
  /** Same contract as `LiteCanonicalTransaction.scan`. */
  scan(prefix: string, after?: string): Promise<LiteStoragePage>;
  getMany?(keys: string[]): Promise<(string | undefined)[]>;
  scanMany?(
    scans: { prefix: string; after?: string }[],
  ): Promise<LiteStoragePage[]>;
  blob?(blobId: string): Promise<LiteBlobDescriptor | undefined>;
}

export interface LiteCanonicalEncodedBatch {
  /** Sorted by key; the final value of every key the batch wrote. */
  entries: LiteCanonicalEntry[];
  /** The clock the entries were encoded against (`ImportCanonicalFence`). */
  fence: ImportCanonicalFence;
  /** One `commitLocal` receipt per part, in order. */
  parts: { id: string; receipt: LiteCommitReceipt }[];
}

/** Items per `getMany`/`scanMany` call (the native store's read bound). */
export const LITE_IMPORT_READ_MANY_MAX = 500;
/** The native store's page bounds; a page always holds its first entry. */
const PAGE_ENTRIES = 100;
const PAGE_BYTES = 512 * 1024;
/** Passes over guessed answers before the last pass reads directly. */
const GUESSED_PASSES = 3;
const utf8 = new TextEncoder();
/** Every record-writing canonical commit advances it (`canonical-store.ts`). */
const CLOCK_KEY = "clock";

/** Keys hold no NUL, so this names one `scan(prefix, after)` request. */
const scanId = (prefix: string, after?: string) =>
  after === undefined ? prefix : `${prefix}\0${after}`;

/** A batch's writes: the final value per key (`null` deletes), in key order. */
class Overlay {
  readonly values = new Map<string, string | null>();
  private readonly keys: string[] = [];
  /** Index of the first key not below `key`. */
  private seek(key: string) {
    let low = 0;
    let high = this.keys.length;
    while (low < high) {
      const mid = (low + high) >>> 1;
      if (this.keys[mid]! < key) low = mid + 1;
      else high = mid;
    }
    return low;
  }
  set(key: string, value: string | null) {
    if (!this.values.has(key)) this.keys.splice(this.seek(key), 0, key);
    this.values.set(key, value);
  }
  /** Live keys under `prefix` after `cursor`, up to `bound` inclusive. */
  *range(prefix: string, cursor: string | undefined, bound?: string) {
    let index = this.seek(cursor ?? prefix);
    if (cursor !== undefined && this.keys[index] === cursor) index++;
    for (; index < this.keys.length; index++) {
      const key = this.keys[index]!;
      if (!key.startsWith(prefix) || (bound !== undefined && key > bound))
        return;
      const value = this.values.get(key)!;
      if (value !== null) yield { key, value };
    }
  }
  entries(): LiteCanonicalEntry[] {
    return this.keys.map((key) => ({ key, value: this.values.get(key)! }));
  }
}

/** Reads of the base under the overlay, async as the store expects. */
interface BaseReads {
  get(key: string): Promise<string | undefined>;
  scan(prefix: string, after?: string): Promise<LiteStoragePage>;
}

/**
 * One page of `base` with `overlay` written over it. A base continuation
 * bounds the overlay keys too, so nothing past it can be skipped on the next
 * page.
 */
async function mergedPage(
  base: BaseReads,
  overlay: Overlay,
  prefix: string,
  after?: string,
): Promise<LiteStoragePage> {
  let cursor = after;
  for (;;) {
    const page = await base.scan(prefix, cursor);
    const bound = page.after;
    const own = overlay.range(prefix, cursor, bound);
    // One entry past a full page is enough to know the page is cut.
    const merged: LiteStorageEntry[] = [];
    const full = () => merged.length > PAGE_ENTRIES;
    let next = own.next();
    for (const entry of page.entries) {
      for (; !next.done && next.value.key < entry.key; next = own.next()) {
        if (full()) break;
        merged.push(next.value);
      }
      if (full()) break;
      if (!overlay.values.has(entry.key)) merged.push(entry);
    }
    for (; !next.done && !full(); next = own.next()) merged.push(next.value);
    const entries: LiteStorageEntry[] = [];
    let bytes = 0;
    for (const entry of merged) {
      const size = utf8.encode(entry.value).byteLength;
      if (
        entries.length === PAGE_ENTRIES ||
        (entries.length && bytes + size > PAGE_BYTES)
      )
        break;
      entries.push(entry);
      bytes += size;
    }
    if (entries.length < merged.length)
      return { entries, after: entries.at(-1)!.key };
    if (entries.length || bound === undefined)
      return bound === undefined ? { entries } : { entries, after: bound };
    cursor = bound;
  }
}

/** A transaction over `base` that keeps its writes in `overlay`. */
function captureTransaction(
  base: BaseReads,
  overlay: Overlay,
  blob: LiteCanonicalReadView["blob"],
): LiteCanonicalTransaction {
  return {
    async get(key) {
      if (overlay.values.has(key)) return overlay.values.get(key) ?? undefined;
      return base.get(key);
    },
    async put(key, value) {
      if (utf8.encode(value).byteLength > LITE_CANONICAL_MAX_VALUE_BYTES)
        throw new RangeError("canonical value exceeds 18 MiB");
      overlay.set(key, value);
    },
    async delete(key) {
      overlay.set(key, null);
    },
    scan: (prefix, after) => mergedPage(base, overlay, prefix, after),
    attachBlob() {
      return Promise.reject(new Error("import encoding does not attach blobs"));
    },
    async blob(blobId) {
      return blob?.(blobId);
    },
  };
}

/** True base answers, and the reads a pass answered from a guess. */
interface Reads {
  values: Map<string, string | undefined>;
  pages: Map<string, LiteStoragePage>;
}
const noReads = (): Reads => ({ values: new Map(), pages: new Map() });

const samePage = (a: LiteStoragePage, b: LiteStoragePage) =>
  a.after === b.after &&
  a.entries.length === b.entries.length &&
  a.entries.every(
    (entry, i) =>
      entry.key === b.entries[i]!.key && entry.value === b.entries[i]!.value,
  );

/** Every item of `requests`, asked in bounded calls that may answer a part. */
async function readAll<Q, A>(
  requests: Q[],
  read: (requests: Q[]) => Promise<A[]>,
): Promise<A[]> {
  const answers: A[] = [];
  while (answers.length < requests.length) {
    const asked = requests.slice(
      answers.length,
      answers.length + LITE_IMPORT_READ_MANY_MAX,
    );
    const answered = await read(asked);
    if (answered.length < 1 || answered.length > asked.length)
      throw new Error("batched canonical read answered no items");
    answers.push(...answered);
  }
  return answers;
}

export interface LiteCanonicalImportEncoderOptions {
  context: () => MergeContext;
  /** Operation ids; the host must persist what it staged, so replay reuses them. */
  newId?: () => string;
}

export function createLiteCanonicalImportEncoder(
  options: LiteCanonicalImportEncoderOptions,
) {
  const newId = options.newId ?? (() => globalThis.crypto.randomUUID());
  // One Lite store for every batch; each pass points it at its own capture.
  let capture: LiteCanonicalTransaction | undefined;
  let tape: string[] = [];
  let used = 0;
  const store = createLiteCanonicalStore({
    persistence: {
      transaction: (run) => run(capture!),
      stageBlob: () =>
        Promise.reject(new Error("import encoding does not stage blobs")),
      readBlob: () => {
        throw new Error("import encoding does not read blobs");
      },
    },
    context: options.context,
    authenticateReplica: () => undefined,
    enabled: true,
    // Every pass replays the same ids, so a rerun encodes the same entries.
    newId: () => {
      if (used === tape.length) tape.push(newId());
      return tape[used++]!;
    },
  });
  // What the last batch read and wrote: the guesses for the next batch.
  let carried = { reads: noReads(), overlay: new Overlay() };
  let queue = Promise.resolve();

  /** Guessed answers: the last batch's reads and writes, else absent. */
  function guesses(): BaseReads {
    const { reads, overlay } = carried;
    const before: BaseReads = {
      get: async (key) => reads.values.get(key),
      scan: async (prefix, after) =>
        reads.pages.get(scanId(prefix, after)) ?? { entries: [] },
    };
    return {
      get: async (key) =>
        overlay.values.has(key)
          ? (overlay.values.get(key) ?? undefined)
          : reads.values.get(key),
      scan: (prefix, after) => mergedPage(before, overlay, prefix, after),
    };
  }

  async function run(
    view: LiteCanonicalReadView,
    parts: { id: string; operations: LiteOperationDraft[] }[],
  ): Promise<LiteCanonicalEncodedBatch> {
    const batched = view.getMany !== undefined && view.scanMany !== undefined;
    const known = noReads();
    const guess = guesses();
    for (let pass = 0; ; pass++) {
      // The last pass, and every pass on a host without batched reads, asks
      // the view for anything not known; the others answer from a guess.
      const direct = !batched || pass === GUESSED_PASSES;
      const guessed: Reads = noReads();
      const scans = new Map<string, { prefix: string; after?: string }>();
      const base: BaseReads = {
        async get(key) {
          if (known.values.has(key)) return known.values.get(key);
          if (direct) {
            const value = await view.get(key);
            known.values.set(key, value);
            return value;
          }
          const value = await guess.get(key);
          guessed.values.set(key, value);
          return value;
        },
        async scan(prefix, after) {
          const id = scanId(prefix, after);
          const page = known.pages.get(id);
          if (page) return page;
          if (direct) {
            const read = await view.scan(prefix, after);
            known.pages.set(id, read);
            return read;
          }
          const value = await guess.scan(prefix, after);
          guessed.pages.set(id, value);
          scans.set(id, after === undefined ? { prefix } : { prefix, after });
          return value;
        },
      };
      const overlay = new Overlay();
      capture = captureTransaction(base, overlay, view.blob?.bind(view));
      used = 0;
      let outcome:
        | { ok: true; batch: LiteCanonicalEncodedBatch }
        | { ok: false; error: unknown };
      try {
        const fence = {
          key: CLOCK_KEY,
          value: (await base.get(CLOCK_KEY)) ?? null,
        };
        const receipts: LiteCanonicalEncodedBatch["parts"] = [];
        for (const part of parts)
          receipts.push({
            id: part.id,
            receipt: await store.commitLocal(part.id, part.operations),
          });
        outcome = {
          ok: true,
          batch: { entries: overlay.entries(), fence, parts: receipts },
        };
      } catch (error) {
        outcome = { ok: false, error };
      } finally {
        capture = undefined;
      }
      // Check every guess against the view in a few batched calls.
      const keys = [...guessed.values.keys()];
      const values = await readAll(keys, (asked) => view.getMany!(asked));
      const ids = [...scans.keys()];
      const pages = await readAll(
        ids.map((id) => scans.get(id)!),
        (asked) => view.scanMany!(asked),
      );
      let held = true;
      keys.forEach((key, i) => {
        known.values.set(key, values[i]);
        held &&= values[i] === guessed.values.get(key);
      });
      ids.forEach((id, i) => {
        known.pages.set(id, pages[i]!);
        held &&= samePage(pages[i]!, guessed.pages.get(id)!);
      });
      if (!held) continue;
      // Ids the accepted pass did not use start the next batch's tape.
      tape = tape.slice(used);
      if (!outcome.ok) throw outcome.error;
      carried = { reads: known, overlay };
      return outcome.batch;
    }
  }

  /**
   * Encodes `commitLocal` calls in order, each part seeing the parts before it.
   * Nothing is committed; a refused part throws and returns no entries. The
   * output does not depend on the guesses: a pass is kept only when every
   * read it guessed matches the view.
   */
  function encode(
    view: LiteCanonicalReadView,
    parts: { id: string; operations: LiteOperationDraft[] }[],
  ): Promise<LiteCanonicalEncodedBatch> {
    const result = queue.then(() => run(view, parts));
    queue = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }

  /**
   * One import batch as `commitLocal` parts of at most 192 KiB, with ids
   * `import:<jobId>:<seq>:<part>`. A larger operation is a part alone, up to
   * 17 MiB. Every operation needs its stream's retained declaration binding.
   */
  function importBatchParts(input: {
    job: Pick<ImportJobRecord, "jobId" | "binding">;
    seq: number;
    operations: readonly ImportStagedOperation[];
    bindingFor: (stream: string) => DeclarationBinding | undefined;
  }): { id: string; operations: LiteOperationDraft[] }[] {
    const { job } = input;
    const parts: { id: string; operations: LiteOperationDraft[] }[] = [];
    let current: LiteOperationDraft[] = [];
    let bytes = 2;
    const flush = () => {
      if (!current.length) return;
      parts.push({
        id: `import:${job.jobId}:${input.seq}:${parts.length}`,
        operations: current,
      });
      current = [];
      bytes = 2;
    };
    for (const operation of input.operations) {
      const declaration = input.bindingFor(operation.stream);
      if (!declaration)
        throw new ImportJobError(
          "stream_not_declared",
          `stream '${operation.stream}' has no retained declaration binding`,
        );
      const base = {
        owner: job.binding.owner,
        sourceId: job.binding.sourceId,
        connectionId: job.binding.instance,
        methodId: job.binding.method,
        generation: job.binding.generation,
        declaration,
        recordKey: operation.recordKey,
        emittedAt: operation.emittedAt,
      };
      const draft = (
        operation.op === "upsert"
          ? {
              ...base,
              kind: "upsert",
              data: JSON.parse(operation.dataJson!) as Record<string, unknown>,
              blobs: [],
            }
          : { ...base, kind: "delete", deletedAt: operation.emittedAt }
      ) as LiteOperationDraft;
      const size = utf8.encode(canonicalJson(draft)).byteLength + 1;
      if (size + 1 > LITE_CANONICAL_MAX_OPERATION_BYTES)
        throw new ImportJobError(
          "record_too_large",
          `one operation is ${size + 1} bytes; a canonical part holds ${LITE_CANONICAL_MAX_OPERATION_BYTES}`,
        );
      if (bytes + size > LITE_CANONICAL_BATCH_BYTES) flush();
      current.push(draft);
      bytes += size;
    }
    flush();
    return parts;
  }

  return { encode, importBatchParts };
}
