/** Protocol limits shared by replication senders, admission, and stream readers. */
export const REPLICA_MAX_FRAGMENTS = 100_000;
/** vana-storage DEFAULT_MAX_BLOB_SIZE. Compare the actual encrypted request. */
export const REPLICA_MAX_BLOB_BYTES = 100 * 1024 * 1024;
/** Per-fragment framing allowance used by the #500 aggregate ciphertext check. */
export const REPLICA_FRAGMENT_OVERHEAD_BYTES = 4096;

/**
 * The source write APIs cap an ingest body and a blob at 512 MiB. Four times
 * that source cap covers an ingest body plus one base64-encoded maximum blob
 * with room for the rest of the payload; sender preparation enforces this cap.
 */
export const REPLICA_MAX_TOTAL_BYTES = 4 * 512 * 1024 * 1024;
/** Node capture already limits a batch to 10,000 operations. */
export const REPLICA_MAX_OPERATIONS = 10_000;
/** An operation cannot exceed its enclosing admitted payload. */
export const REPLICA_MAX_OPERATION_BYTES = REPLICA_MAX_TOTAL_BYTES;
/** Base64 uses at least as many bytes as decoded blobs; both fit totalBytes. */
export const REPLICA_MAX_BLOB_TOTAL_BYTES = REPLICA_MAX_TOTAL_BYTES;
/** Derived from totalBytes for the same reason as the aggregate blob bound. */
export const REPLICA_MAX_SINGLE_BLOB_BYTES = REPLICA_MAX_TOTAL_BYTES;
/** One retained evidence row is created for each manifest fragment. */
export const REPLICA_MAX_EVIDENCE_ROWS = REPLICA_MAX_FRAGMENTS;
export const REPLICA_LIMITS_VERSION = 1;

/**
 * The maximum encrypted fragment bytes for a payload of `totalBytes` and
 * `count` fragments: base64 payload bytes plus #500's per-fragment framing.
 */
export function replicaFramedBytesBound(totalBytes: number, count: number) {
  return (
    4 * Math.ceil(totalBytes / 3) +
    count * (4 + REPLICA_FRAGMENT_OVERHEAD_BYTES)
  );
}

/**
 * A 512 MiB uploaded blob expands to about 683 MiB of base64; 1 GiB leaves
 * room for its envelope and fragment framing while bounding stored evidence.
 */
export const REPLICA_MAX_AGGREGATE_CIPHERTEXT_BYTES = 1024 * 1024 * 1024;

export interface DeclaredReplicaManifest {
  totalBytes: number;
  digest?: string;
  owner?: string;
  fragments: readonly { bytes: number }[];
}

export type ResourceRefusal =
  | { kind: "resource_unsupported"; limit: string; limitsVersion: number }
  | { kind: "resource_busy"; requestedBytes: number; availableBytes: number };

/** Reservation ledger shared by concurrently running replication steps. */
export class ReplicaByteBudget {
  private reservedBytes = 0;

  constructor(readonly maxBytes: number) {
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 0)
      throw new RangeError("invalid replication byte budget");
  }

  get reserved() {
    return this.reservedBytes;
  }

  reserve(bytes: number): (() => void) | ResourceRefusal {
    if (!Number.isSafeInteger(bytes) || bytes < 0)
      throw new RangeError("invalid replication reservation");
    const availableBytes = this.maxBytes - this.reservedBytes;
    if (bytes > availableBytes)
      return { kind: "resource_busy", requestedBytes: bytes, availableBytes };
    this.reservedBytes += bytes;
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.reservedBytes -= bytes;
    };
  }
}

// Ciphertext, plaintext, parsed JSON tree, and base64-decoded fragment bytes.
export const REPLICA_LIVE_COPY_FACTOR = 4;

const admissionBrand: unique symbol = Symbol("ReplicaAdmission");
export interface Admission {
  readonly [admissionBrand]: true;
  readonly admissionId: string;
  readonly repositoryId: string;
  readonly owner: string;
  readonly manifestDigest: string;
  readonly ciphertextBytes: number;
  readonly payloadBytes: number;
  readonly reservedBytes: number;
  readonly limitsVersion: number;
  release(): void;
}

export type AdmissionResult = Admission | ResourceRefusal;

export class ReplicaResourceLimitError extends Error {
  readonly code = "replica_resource_limit_exceeded";

  constructor(
    readonly limit: string,
    readonly actual: number,
    readonly maximum: number,
  ) {
    super("replica resource limit exceeded");
    this.name = "ReplicaResourceLimitError";
  }
}

/** Check manifest-declared totals only and reserve bounded live-copy capacity. */
export function admit(
  manifest: DeclaredReplicaManifest,
  budget: ReplicaByteBudget,
  identity: { repositoryId: string; owner: string; manifestDigest: string },
): AdmissionResult {
  if (manifest.fragments.length > REPLICA_MAX_EVIDENCE_ROWS)
    return unsupported("retained_evidence_rows");
  if (manifest.fragments.length > REPLICA_MAX_FRAGMENTS)
    return unsupported("fragment_count");
  if (
    manifest.fragments.some(
      (fragment) => fragment.bytes > REPLICA_MAX_BLOB_BYTES,
    )
  )
    return unsupported("fragment_ciphertext_bytes");
  const ciphertextBytes = manifest.fragments.reduce(
    (total, fragment) => total + fragment.bytes,
    0,
  );
  if (
    !Number.isSafeInteger(ciphertextBytes) ||
    ciphertextBytes > REPLICA_MAX_AGGREGATE_CIPHERTEXT_BYTES ||
    ciphertextBytes >
      replicaFramedBytesBound(manifest.totalBytes, manifest.fragments.length)
  )
    return unsupported("aggregate_ciphertext_bytes");
  if (
    !Number.isSafeInteger(manifest.totalBytes) ||
    manifest.totalBytes < 1 ||
    manifest.totalBytes > REPLICA_MAX_TOTAL_BYTES
  )
    return unsupported("total_bytes");

  const reservedBytes = ciphertextBytes * REPLICA_LIVE_COPY_FACTOR;
  const release = budget.reserve(reservedBytes);
  if (typeof release !== "function") return release;
  return Object.freeze({
    [admissionBrand]: true as const,
    admissionId: `${identity.repositoryId}:${identity.owner}:${identity.manifestDigest}`,
    ...identity,
    ciphertextBytes,
    payloadBytes: manifest.totalBytes,
    reservedBytes,
    limitsVersion: REPLICA_LIMITS_VERSION,
    release,
  });
}

function unsupported(limit: string): ResourceRefusal {
  return {
    kind: "resource_unsupported",
    limit,
    limitsVersion: REPLICA_LIMITS_VERSION,
  };
}
