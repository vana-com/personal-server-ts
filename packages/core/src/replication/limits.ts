/** Protocol limits shared by replication senders, admission, and stream readers. */
import { MAX_DECLARATION_BYTES } from "../pdpp/declaration-limits.js";

export const REPLICA_MAX_FRAGMENTS = 100_000;
/** vana-storage DEFAULT_MAX_BLOB_SIZE. Compare the actual encrypted request. */
export const REPLICA_MAX_BLOB_BYTES = 100 * 1024 * 1024;
/** Per-fragment framing allowance used by the #500 aggregate ciphertext check. */
export const REPLICA_FRAGMENT_OVERHEAD_BYTES = 4096;

/** Same source-write bounds used by the Node PDPP routes. */
export const REPLICA_SOURCE_MAX_BLOB_BYTES = 512 * 1024 * 1024;
export const REPLICA_SOURCE_MAX_RECORD_JSON_BYTES = 512 * 1024 * 1024;
/** Node capture's persisted batch target and operation count. */
export const REPLICA_BATCH_TARGET_BYTES = 32 * 1024 * 1024;
export const REPLICA_BATCH_OPERATION_LIMIT = 10_000;
/** Node prepares 4 MiB payload chunks before #500 encryption overhead. */
export const REPLICA_DEFAULT_FRAGMENT_BYTES = 4 * 1024 * 1024;
export const REPLICA_MAX_OPERATIONS = REPLICA_BATCH_OPERATION_LIMIT;
/** One retained evidence row is created for each manifest fragment. */
export const REPLICA_MAX_EVIDENCE_ROWS = REPLICA_MAX_FRAGMENTS;
export const REPLICA_LIMITS_VERSION = 3;

/**
 * Operation metadata can repeat the record key and carries declaration-bound
 * source/method identifiers. Bound that overhead by a second ingest body plus
 * the largest retained declaration and fixed replication fields.
 */
export const REPLICA_MAX_OPERATION_ENVELOPE_BYTES =
  REPLICA_SOURCE_MAX_RECORD_JSON_BYTES + MAX_DECLARATION_BYTES + 64 * 1024;
/** The payload-level header is fixed apart from its retained declaration IDs. */
export const REPLICA_MAX_PAYLOAD_ENVELOPE_BYTES =
  2 * MAX_DECLARATION_BYTES + 64 * 1024;
export const REPLICA_MAX_SINGLE_OPERATION_BYTES =
  4 * Math.ceil(REPLICA_SOURCE_MAX_BLOB_BYTES / 3) +
  REPLICA_SOURCE_MAX_RECORD_JSON_BYTES +
  REPLICA_MAX_OPERATION_ENVELOPE_BYTES;

/**
 * The first operation may exceed the target, then later operations may fill
 * the target; otherwise every operation fits the target and count is binding.
 */
export const REPLICA_MAX_TOTAL_BYTES =
  Math.max(
    REPLICA_BATCH_TARGET_BYTES + REPLICA_MAX_SINGLE_OPERATION_BYTES,
    REPLICA_BATCH_OPERATION_LIMIT * REPLICA_BATCH_TARGET_BYTES,
  ) + REPLICA_MAX_PAYLOAD_ENVELOPE_BYTES;
/** Each streamed operation is bounded by the admitted payload that contains it. */
export const REPLICA_MAX_OPERATION_BYTES = REPLICA_MAX_TOTAL_BYTES;
/** A blob cannot exceed the actual Node source write cap. */
export const REPLICA_MAX_SINGLE_BLOB_BYTES = REPLICA_SOURCE_MAX_BLOB_BYTES;
/** Base64 blob bytes are part of totalBytes, so their sum cannot exceed it. */
export const REPLICA_MAX_BLOB_TOTAL_BYTES = REPLICA_MAX_TOTAL_BYTES;

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

/** Maximum declared encrypted bytes for an honest payload and 100,000 fragments. */
export const REPLICA_MAX_AGGREGATE_CIPHERTEXT_BYTES =
  4 * Math.ceil(REPLICA_MAX_TOTAL_BYTES / 3) +
  REPLICA_MAX_FRAGMENTS * (4 + REPLICA_FRAGMENT_OVERHEAD_BYTES);
/** Four live representations: ciphertext, plaintext, parsed JSON and decoded bytes. */
export const REPLICA_LIVE_COPY_FACTOR = 4;
/** The retained JSON string plus its parsed operation tree. */
export const REPLICA_ENVELOPE_LIVE_COPY_FACTOR = 2;
/** 100 MiB #500 per-object cap × four copies = 400 MiB, below this budget. */
export const REPLICA_DEFAULT_BYTE_BUDGET_BYTES = 512 * 1024 * 1024;

export interface ReplicaResourceLimits {
  maxSourceBlobBytes: number;
  maxRecordJsonBytes: number;
  maxManifestCiphertextBytes: number;
  maxFragmentCiphertextBytes: number;
  maxAggregateCiphertextBytes: number;
  maxFragments: number;
  maxEvidenceRows: number;
  maxTotalBytes: number;
  maxOperations: number;
  maxOperationBytes: number;
  maxSingleBlobBytes: number;
  maxBlobTotalBytes: number;
}

export const REPLICA_DEFAULT_LIMITS: ReplicaResourceLimits = Object.freeze({
  maxSourceBlobBytes: REPLICA_SOURCE_MAX_BLOB_BYTES,
  maxRecordJsonBytes: REPLICA_SOURCE_MAX_RECORD_JSON_BYTES,
  maxManifestCiphertextBytes: REPLICA_MAX_BLOB_BYTES,
  maxFragmentCiphertextBytes: REPLICA_MAX_BLOB_BYTES,
  maxAggregateCiphertextBytes: REPLICA_MAX_AGGREGATE_CIPHERTEXT_BYTES,
  maxFragments: REPLICA_MAX_FRAGMENTS,
  maxEvidenceRows: REPLICA_MAX_EVIDENCE_ROWS,
  maxTotalBytes: REPLICA_MAX_TOTAL_BYTES,
  maxOperations: REPLICA_MAX_OPERATIONS,
  maxOperationBytes: REPLICA_MAX_OPERATION_BYTES,
  maxSingleBlobBytes: REPLICA_MAX_SINGLE_BLOB_BYTES,
  maxBlobTotalBytes: REPLICA_MAX_BLOB_TOTAL_BYTES,
});

export function replicaResourceLimits(
  overrides: Partial<ReplicaResourceLimits> = {},
): ReplicaResourceLimits {
  return Object.freeze({ ...REPLICA_DEFAULT_LIMITS, ...overrides });
}

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
  private readonly reservations = new Map<object, number>();

  constructor(readonly maxBytes: number) {
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 0)
      throw new RangeError("invalid replication byte budget");
  }

  get reserved() {
    return this.reservedBytes;
  }

  reserve(bytes: number, group: object = {}): (() => void) | ResourceRefusal {
    if (!Number.isSafeInteger(bytes) || bytes < 0)
      throw new RangeError("invalid replication reservation");
    const availableBytes = this.maxBytes - this.reservedBytes;
    const groupBytes = this.reservations.get(group) ?? 0;
    if (bytes > availableBytes && groupBytes !== this.reservedBytes)
      return { kind: "resource_busy", requestedBytes: bytes, availableBytes };
    const nextReservedBytes = this.reservedBytes + bytes;
    const nextGroupBytes = groupBytes + bytes;
    if (
      !Number.isSafeInteger(nextReservedBytes) ||
      !Number.isSafeInteger(nextGroupBytes)
    )
      throw new RangeError("replication reservation exhausted");
    this.reservedBytes = nextReservedBytes;
    this.reservations.set(group, nextGroupBytes);
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.reservedBytes -= bytes;
      const remaining = (this.reservations.get(group) ?? 0) - bytes;
      if (remaining === 0) this.reservations.delete(group);
      else this.reservations.set(group, remaining);
    };
  }
}

const admissionBrand: unique symbol = Symbol("ReplicaAdmission");
export interface Admission {
  readonly [admissionBrand]: true;
  readonly admissionId: string;
  readonly repositoryId: string;
  readonly owner: string;
  readonly manifestDigest: string;
  readonly payloadBytes: number;
  readonly limitsVersion: number;
  reserveObject(
    ciphertextBytes: number,
    reservationGroup?: object,
  ): (() => void) | ResourceRefusal;
  reserveEnvelope(
    jsonBytes: number,
    reservationGroup?: object,
  ): (() => void) | ResourceRefusal;
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

export class ReplicaResourceBusyError extends Error {
  readonly code = "resource_busy";

  constructor() {
    super("replica object reservation is busy");
    this.name = "ReplicaResourceBusyError";
  }
}

/** Check manifest-declared totals and issue an object-reservation capability. */
export function admit(
  manifest: DeclaredReplicaManifest,
  budget: ReplicaByteBudget,
  identity: { repositoryId: string; owner: string; manifestDigest: string },
  limits: ReplicaResourceLimits = REPLICA_DEFAULT_LIMITS,
): AdmissionResult {
  if (manifest.fragments.length > limits.maxEvidenceRows)
    return unsupported("retained_evidence_rows");
  if (manifest.fragments.length > limits.maxFragments)
    return unsupported("fragment_count");
  if (
    manifest.fragments.some(
      (fragment) => fragment.bytes > limits.maxFragmentCiphertextBytes,
    )
  )
    return unsupported("fragment_ciphertext_bytes");
  const ciphertextBytes = manifest.fragments.reduce(
    (total, fragment) => total + fragment.bytes,
    0,
  );
  if (
    !Number.isSafeInteger(ciphertextBytes) ||
    ciphertextBytes > limits.maxAggregateCiphertextBytes ||
    ciphertextBytes >
      replicaFramedBytesBound(manifest.totalBytes, manifest.fragments.length)
  )
    return unsupported("aggregate_ciphertext_bytes");
  if (
    !Number.isSafeInteger(manifest.totalBytes) ||
    manifest.totalBytes < 1 ||
    manifest.totalBytes > limits.maxTotalBytes
  )
    return unsupported("total_bytes");

  const reservationGroup = {};
  return Object.freeze({
    [admissionBrand]: true as const,
    admissionId: `${identity.repositoryId}:${identity.owner}:${identity.manifestDigest}`,
    ...identity,
    payloadBytes: manifest.totalBytes,
    limitsVersion: REPLICA_LIMITS_VERSION,
    reserveObject(ciphertextBytes: number, group = {}) {
      if (!Number.isSafeInteger(ciphertextBytes) || ciphertextBytes < 0)
        throw new RangeError("invalid replica object size");
      return budget.reserve(ciphertextBytes * REPLICA_LIVE_COPY_FACTOR, group);
    },
    reserveEnvelope(jsonBytes: number, group = reservationGroup) {
      if (!Number.isSafeInteger(jsonBytes) || jsonBytes < 0)
        throw new RangeError("invalid replica envelope size");
      return budget.reserve(
        jsonBytes * REPLICA_ENVELOPE_LIVE_COPY_FACTOR,
        group,
      );
    },
  });
}

function unsupported(limit: string): ResourceRefusal {
  return {
    kind: "resource_unsupported",
    limit,
    limitsVersion: REPLICA_LIMITS_VERSION,
  };
}
