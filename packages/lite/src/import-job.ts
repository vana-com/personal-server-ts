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
  type ImportJobRecord,
  type ImportStagedOperation,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-import-job";
import {
  createLiteCanonicalStore,
  type LiteCommitReceipt,
  type LiteOperationDraft,
} from "./canonical-store.js";
import type {
  LiteBlobDescriptor,
  LiteCanonicalPersistence,
  LiteCanonicalTransaction,
  LiteStorageEntry,
  LiteStoragePage,
} from "./canonical-persistence.js";

export * from "@opendatalabs/personal-server-ts-core/storage/pdpp-import-job";

/** One canonical KV write. `value: null` deletes the key. */
export type LiteCanonicalEntry = ImportCanonicalEntry;

/**
 * What the encoder reads. For a job, the host answers from the job's staged
 * entries over its committed canonical entries, so each batch sees the clock,
 * rows and receipts the earlier batches of the same job wrote.
 */
export interface LiteCanonicalReadView {
  get(key: string): Promise<string | undefined>;
  /** Same contract as `LiteCanonicalTransaction.scan`. */
  scan(prefix: string, after?: string): Promise<LiteStoragePage>;
  blob?(blobId: string): Promise<LiteBlobDescriptor | undefined>;
}

export interface LiteCanonicalEncodedBatch {
  /** Sorted by key; the final value of every key the batch wrote. */
  entries: LiteCanonicalEntry[];
  /** One `commitLocal` receipt per part, in order. */
  parts: { id: string; receipt: LiteCommitReceipt }[];
}

/** The same limits the native bridge applies to values and commit batches. */
const VALUE_BYTES = 256 * 1024;
const PART_BYTES = 192 * 1024;
const PAGE_ENTRIES = 100;
const PAGE_BYTES = 512 * 1024;
const utf8 = new TextEncoder();

/** A transaction over `view` that keeps its writes in `overlay`. */
function captureTransaction(
  view: LiteCanonicalReadView,
  overlay: Map<string, string | null>,
): LiteCanonicalTransaction {
  return {
    async get(key) {
      if (overlay.has(key)) return overlay.get(key) ?? undefined;
      return view.get(key);
    },
    async put(key, value) {
      if (utf8.encode(value).byteLength > VALUE_BYTES)
        throw new RangeError("canonical value exceeds 256 KiB");
      overlay.set(key, value);
    },
    async delete(key) {
      overlay.set(key, null);
    },
    async scan(prefix, after) {
      // Merge one base page with the overlay. A base continuation bounds the
      // overlay keys too, so nothing past it can be skipped on the next page.
      let cursor = after;
      for (;;) {
        const base = await view.scan(prefix, cursor);
        const bound = base.after;
        const merged = new Map<string, string>();
        for (const entry of base.entries)
          if (!overlay.has(entry.key)) merged.set(entry.key, entry.value);
        for (const [key, value] of overlay)
          if (
            value !== null &&
            key.startsWith(prefix) &&
            (cursor === undefined || key > cursor) &&
            (bound === undefined || key <= bound)
          )
            merged.set(key, value);
        const sorted = [...merged.entries()].sort(([a], [b]) =>
          a < b ? -1 : a > b ? 1 : 0,
        );
        const entries: LiteStorageEntry[] = [];
        let bytes = 0;
        for (const [key, value] of sorted) {
          const size = utf8.encode(value).byteLength;
          if (entries.length === PAGE_ENTRIES || bytes + size > PAGE_BYTES)
            break;
          entries.push({ key, value });
          bytes += size;
        }
        if (entries.length < sorted.length)
          return { entries, after: entries.at(-1)!.key };
        if (entries.length || bound === undefined)
          return bound === undefined ? { entries } : { entries, after: bound };
        cursor = bound;
      }
    },
    attachBlob() {
      return Promise.reject(new Error("import encoding does not attach blobs"));
    },
    async blob(blobId) {
      return view.blob?.(blobId);
    },
  };
}

export interface LiteCanonicalImportEncoderOptions {
  context: () => MergeContext;
  /** Operation ids; the host must persist what it staged, so replay reuses them. */
  newId?: () => string;
}

export function createLiteCanonicalImportEncoder(
  options: LiteCanonicalImportEncoderOptions,
) {
  /**
   * Encodes `commitLocal` calls in order, each part seeing the parts before it.
   * Nothing is committed; a refused part throws and returns no entries.
   */
  async function encode(
    view: LiteCanonicalReadView,
    parts: { id: string; operations: LiteOperationDraft[] }[],
  ): Promise<LiteCanonicalEncodedBatch> {
    const overlay = new Map<string, string | null>();
    const persistence: LiteCanonicalPersistence = {
      transaction: (run) => run(captureTransaction(view, overlay)),
      stageBlob: () =>
        Promise.reject(new Error("import encoding does not stage blobs")),
      readBlob: () => {
        throw new Error("import encoding does not read blobs");
      },
    };
    const store = createLiteCanonicalStore({
      persistence,
      context: options.context,
      authenticateReplica: () => undefined,
      enabled: true,
      ...(options.newId ? { newId: options.newId } : {}),
    });
    const receipts: LiteCanonicalEncodedBatch["parts"] = [];
    for (const part of parts)
      receipts.push({
        id: part.id,
        receipt: await store.commitLocal(part.id, part.operations),
      });
    return {
      entries: [...overlay.entries()]
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([key, value]) => ({ key, value })),
      parts: receipts,
    };
  }

  /**
   * One import batch as `commitLocal` parts of at most 192 KiB, with ids
   * `import:<jobId>:<seq>:<part>`. Every operation needs its stream's
   * retained declaration binding.
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
      if (size + 2 > PART_BYTES)
        throw new ImportJobError(
          "record_too_large",
          `one operation is ${size} bytes; a canonical part holds ${PART_BYTES}`,
        );
      if (bytes + size > PART_BYTES) flush();
      current.push(draft);
      bytes += size;
    }
    flush();
    return parts;
  }

  return { encode, importBatchParts };
}
