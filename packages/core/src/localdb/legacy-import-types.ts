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
  /** Any exclusion holds all dependent legacy copies; never silently discard. */
  readonly exclusions: readonly { reason: string; rows: number }[];
  /** Replayable, bounded iterator; never a whole-source array. */
  records(): AsyncIterable<Record<string, unknown>>;
}

/** Count and SHA-256 over length-prefixed sorted (pk_hash, body_sha256). F.2. */
export interface ImportFingerprint {
  readonly rows: number;
  readonly fingerprint: string;
}

/** Durable receipt in import_ledger; reason carries versioned metadata. F.2. */
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

/** Exact local copy; erase must compare all fields under its storage lock. F.2. */
export interface LegacyCopy {
  readonly id: string;
  readonly path: string;
  readonly contentHash: string;
  readonly revision: string;
  readonly dataSet: string;
  readonly sources: readonly {
    source: string;
    connectionId: string;
    stream: string;
  }[];
}

/** F.2: compare every frozen bindings.ts data-set name, using a fixed projection time. */
export interface ProjectionProof {
  readonly dataSet: string;
  readonly expectedHash: string;
  readonly actualHash: string | null;
  readonly pass: boolean;
}

/** Fresh read-back of a source revision and optionally one exact local copy. F.2. */
export interface ImportReadback {
  readonly receipt: ImportReceipt;
  readonly actual: ImportFingerprint;
  readonly projections: readonly ProjectionProof[];
  readonly copy: LegacyCopy | null;
  readonly pass: boolean;
  readonly reason: string | null;
}

/** Per-copy report contains opaque ids and reasons, never paths or bodies. F.2/F.4. */
export interface LegacyRetireFileReport {
  readonly file: string;
  readonly decision: "held" | "ready" | "retired" | "changed";
  readonly reason: string | null;
}

/** Stream reports instead of retaining an unbounded file inventory. F.2. */
export interface LegacyRetireReport {
  readonly mode: "readback-only" | "dry-run" | "delete";
  readonly files: number;
  readonly ready: number;
  readonly deleted: number;
}
