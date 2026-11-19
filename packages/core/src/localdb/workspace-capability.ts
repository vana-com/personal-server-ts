/** Bounded storage capabilities, versioned independently of the SQL convenience API.
 * No host name implies support. Validate this capability before fetching input.
 * Implementations must keep staging in the canonical database's durable store.
 */
export interface WorkspaceBinding {
  /** Absent is allowed only while preparing the first control creation. */
  readonly controlState?: "active" | "absent";
  readonly owner: string;
  readonly databaseIncarnation: string;
  readonly connection: string;
  readonly generation: number;
  readonly keyCheck: string;
  readonly operation: string;
  readonly expectedHead: string;
  readonly codecVersion: number;
}

/** Runtime-wide admission, initially one heavy job. Queued jobs retain only durable IDs.
 * Reserve BEFORE allocation; capacity includes encoded frames, decoded values and copies.
 * Release is idempotent. A lease cannot escape its operation or survive discard.
 */
export interface ByteLease {
  readonly operation: string;
  readonly capacityBytes: number;
  release(): Promise<void>;
}
export interface ByteAdmission {
  /** Refuse oversized units before any durable cursor advances. No captured body waiters. */
  acquire(
    operation: string,
    bytes: number,
    signal?: AbortSignal,
  ): Promise<ByteLease>;
}

/** Opaque durable value identity; never a SQL parameter or a materialized body.
 * Tokens are scoped to binding and invalid after discard/incarnation change.
 */
export interface ValueToken {
  readonly kind: "sealed-value";
  readonly encoding: "utf8" | "binary";
  readonly binding: WorkspaceBinding;
  readonly id: string;
  readonly bytes: number;
  readonly sha256: string;
}
export interface ValueWriterToken {
  readonly kind: "value-writer";
  readonly binding: WorkspaceBinding;
  readonly id: string;
}

/** One owned page/unit, including keys, schemas and envelope bytes.
 * Its actual encoded size and every resident representation must fit the lease.
 * Release before requesting another unit; no detached producer or prefetch queue.
 */
export interface OwnedUnit<T> {
  readonly value: T;
  readonly encodedBytes: number;
  release(): Promise<void>;
}
export interface BoundedCursor<T> {
  /** Stable indexed keyset order, never OFFSET or a materialized/sorted full result.
   * null means exhaustion. Reject while the preceding unit is unreleased.
   */
  next(lease: ByteLease): Promise<OwnedUnit<T> | null>;
  close(): Promise<void>;
}

/** Receipt and fold changes commit atomically. A duplicate identity/digest replays
 * the same receipt; a conflicting duplicate fails without advancing the cursor.
 */
export interface UnitReceipt {
  readonly binding: WorkspaceBinding;
  readonly unitId: string;
  readonly digest: string;
  readonly nextCursor: string;
  readonly phase: "input-folded" | "output-sealed" | "upload-confirmed";
}

/** Failure is durable and retryable where indicated; it never certifies progress. */
export interface WorkspaceFailure {
  readonly binding: WorkspaceBinding;
  readonly unitId: string;
  readonly reason:
    "admission" | "disk-full" | "stale-authority" | "corrupt-input";
  readonly retryable: boolean;
}

export interface BoundedValueStore {
  readonly version: 1;
  /** Explicit opt-in: seal(token, lease) verifies under the caller's existing
   * lease and rejects while another unit owns it. Older version-1 stores omit it. */
  readonly supportsBorrowedSeal?: true;
  /** Includes escaping/base64/envelope; only one frame may be in flight. */
  readonly frameCapacityBytes: number;
  readonly admission: ByteAdmission;
  /** At most one bounded chunk; never materialize the whole token. */
  read(
    token: ValueToken,
    offset: number,
    lease: ByteLease,
  ): Promise<OwnedUnit<Uint8Array>>;
  begin(
    binding: WorkspaceBinding,
    bytes: number,
    sha256: string,
    encoding: "utf8" | "binary",
  ): Promise<ValueWriterToken>;
  /** Ordered offsets. Identical retry is idempotent; conflicting/out-of-order append fails. */
  append(
    token: ValueWriterToken,
    offset: number,
    chunk: Uint8Array,
    lease: ByteLease,
  ): Promise<{ readonly nextOffset: number }>;
  /** Atomic immutable seal only after length, digest and declared encoding validation; no visible rows yet. */
  seal(token: ValueWriterToken, lease?: ByteLease): Promise<ValueToken>;
  /** Lost append/seal replies query durable status using a fixed-size response. */
  status(
    token: ValueWriterToken,
  ): Promise<{ readonly offset: number; readonly sealed: ValueToken | null }>;
  abort(token: ValueWriterToken): Promise<void>;
}

/** Measured host ledger, in bytes. Null coefficients mean unmeasured, not zero.
 * Mpeak <= Midle+Bdb+P+H0+bR*R+bC*C+bT*T+Bcrypto.
 * N, source bytes and historical versions must not occur in this expression.
 */
export interface WorkspaceResourceLedger {
  readonly host: "phone host" | "desktop host" | "browser host";
  readonly Bdb: number;
  readonly P: number;
  readonly H0: number;
  readonly R: number;
  readonly C: number;
  readonly T: number;
  readonly Bcrypto: number | null;
  readonly bR: number | null;
  readonly bC: number | null;
  readonly bT: number | null;
}

/** Stable persisted identity, independent of caller property insertion order. */
export const workspaceBindingIdentity = (b: WorkspaceBinding): string =>
  JSON.stringify([
    b.owner,
    b.databaseIncarnation,
    b.connection,
    b.generation,
    b.keyCheck,
    b.operation,
    b.expectedHead,
    b.codecVersion,
    ...(b.controlState === "absent" ? ["absent"] : []),
  ]);
