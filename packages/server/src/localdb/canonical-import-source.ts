import type { DeclarationSnapshot } from "@opendatalabs/personal-server-ts-core/pdpp";
import type { ImportInventoryEntry } from "@opendatalabs/personal-server-ts-core/localdb";

/** F.2/F.4: bounded page port implemented privately by legacy-access; no store opened here. */
export interface CanonicalImportPageReader {
  /** Declarations retained and verified by the existing authority, not caller manifests. */
  readonly declarations: readonly DeclarationSnapshot[];
  /** Complete stored inventory independent of declarations, keyset paged by the
   * implementation. Includes unknown source ids, unbound instances and streams.
   * Bound to options.revision; mutation/incomplete inventory must throw. */
  inventory(revision: string): AsyncIterable<{
    readonly sourceId: string | null;
    readonly instance: string;
    readonly stream: string;
    readonly rows: number;
  }>;
  /** Check the entire snapshot, not just one stream; call before/after each
   * inventory and records pass. Source quiescence is owned by legacy-access. */
  assertRevision(revision: string): Promise<void>;
  connections(
    sourceId: string,
  ): Promise<readonly { instance: string; deleted: boolean }[]>;
  page(
    instance: string,
    stream: string,
    after: string | null,
    limit: number,
    /** <=4 MiB including serialized response envelope; enforced before retaining
     * a full page. An oversize single record refuses, never truncates/skips. */
    maxBytes: number,
    revision: string,
  ): Promise<{
    readonly rows: readonly Record<string, unknown>[];
    readonly next: string | null;
  }>;
}

/**
 * F.2/F.3: adapt canonical pdpp_records via verified declarations and LIMIT
 * pages (byte bound too). Immutable revision, explicit exclusions; ambiguous
 * instances or missing declarations are held, never silently selected. Derive
 * connector/stream/key from declarations, never connector-id literals. Do not
 * invert legacy projected JSON or add transition tables. Oversized record
 * refuses, never skips silently. Factory returns descriptors lazily.
 * incremental defaults true as in IntakeStreamDeclaration; it is not inferred
 * from semantics or a new declaration field. Multiple live instances hold all.
 * Unknown inventory yields ImportExclusion; never invent declaration/key/target.
 */
export function createCanonicalImportSource(_options: {
  readonly owner: string;
  readonly network: string;
  readonly revision: string;
  readonly reader: CanonicalImportPageReader;
  /** Same authenticated connection authority as host uploads; null holds.
   * Never turn a legacy instance/install id into a new sync namespace. */
  readonly resolveTarget: (
    sourceId: string,
    instance: string,
    stream: string,
  ) => Promise<
    import("@opendatalabs/personal-server-ts-core/localdb").ImportTarget | null
  >;
}): AsyncIterable<ImportInventoryEntry> {
  throw new Error("PS-3: not built");
}
