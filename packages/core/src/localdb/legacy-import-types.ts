/** PS-3 source and proof contracts. Spec: F.2-F.5; r5.2 §1.2. */
export interface ImportTarget {
  readonly connectionId: string;
  readonly connector: string;
  readonly stream: string;
  /** Verified declaration fields; no manifest schema extension. */
  readonly primaryKey: readonly string[];
  readonly semantics: "mutable_state" | "append_only";
  readonly incremental: boolean;
}

/** Immutable device-local source revision, bound to one owner/network. F.2. */
export interface ImportSource {
  readonly source: string;
  readonly owner: string;
  readonly network: string;
  readonly revision: string;
  readonly target: ImportTarget;
  /** Exclusions are counted and not imported; they never delay removal. */
  readonly exclusions: readonly { reason: string; rows: number }[];
  /** Replayable data objects, NOT PDPP envelopes. Use computeRecordKeyFromData
   * (storage/pdpp-records) for record_key, stream-sync pkHash for typed pk_hash,
   * and SHA-256(UTF-8 canonicalJson(record)) for body_sha256. Never stringify
   * key values before pkHash. Invalid/missing keys refuse, not skip.
   * Each pass validates the sealed revision before its first and after its last
   * row; mutation throws source_changed, including an empty pass. */
  records(): AsyncIterable<Record<string, unknown>>;
}

/** Count and SHA-256 over unique rows in binary pk_hash order. Each pair is
 * lowercase hex ASCII pk_hash then body_sha256, each framed with its UTF-8
 * byte length as unsigned 4-byte big-endian. Empty hashes empty bytes.
 * importFingerprint is the single implementation for import and read-back. */
export interface ImportFingerprint {
  readonly rows: number;
  readonly fingerprint: string;
}

/** Durable receipt; migration 2 owns nullable revision/generation/highest_seq.
 * NULL is unknown, never a synthesized receipt. reason is opaque free text. */
export interface ImportReceipt extends ImportFingerprint {
  readonly source: string;
  readonly revision: string;
  readonly connectionId: string;
  readonly stream: string;
  readonly generation: 1;
  /** Highest committed record_changes.seq attributable to this import; 0 if empty. */
  readonly highestSeq: number;
  readonly state: "imported" | "verified" | "retired" | "excluded";
  readonly reason: string | null;
  readonly at: number;
}

/** Exact local copy; erase compares id/path/hash under its storage lock. F.2. */
export interface LegacyCopy {
  readonly id: string;
  readonly path: string;
  /** Lowercase SHA-256 of exact file bytes; erase fence only, not content proof. */
  readonly contentHash: string;
  readonly revision: string;
  readonly dataSet: string;
  readonly sources: readonly {
    source: string;
    connectionId: string;
    stream: string;
  }[];
}

/** The host supplies the frozen compatibility catalogue. Database modules
 * treat names as opaque and never discover or import connector projections. */
export interface ImportProjectionBinding {
  readonly connector: string;
  readonly streams: readonly string[];
}
export interface ImportProjectionPort {
  readonly bindings: ReadonlyMap<string, ImportProjectionBinding>;
}

/** Diagnostic read-back of an imported source revision. F.2. */
export interface ImportReadback {
  readonly receipt: ImportReceipt | null;
  readonly actual: ImportFingerprint;
  readonly pass: boolean;
  readonly reason: string | null;
}

/** Per-copy report contains opaque ids and reasons, never paths or bodies. F.2/F.4. */
export interface LegacyRetireFileReport {
  readonly file: string;
  readonly decision: "skipped" | "ready" | "retired" | "changed";
  readonly reason: string | null;
}

/** Stream reports instead of retaining an unbounded file inventory. F.2. */
export interface LegacyRetireReport {
  readonly mode: "readback-only" | "dry-run" | "delete";
  readonly files: number;
  readonly ready: number;
  readonly deleted: number;
  /** Copies without an importable source. */
  readonly unimported: number;
  readonly readbackFailures: number;
  readonly missing: number;
}

/** Undeclared/unbound inventory cannot invent an ImportTarget. Never import it;
 * removal still includes these old stores. Counts are inventory counts, not proof. */
export interface ImportExclusion {
  readonly kind: "excluded";
  readonly source: string;
  readonly revision: string;
  readonly reason: string;
  readonly rows: number;
}
export type ImportInventoryEntry = ImportSource | ImportExclusion;
