// What is left of a connection delete, in three parts. An app says "deleted"
// only when all three are `done`; until then it says what is left.
//
//   fence    the control tombstone: every surface sees the connection as gone.
//   legacy   the legacy copy: the gateway's legacy data points of the
//            connector's bound scopes, and their blobs in storage.
//   storage  the stream-sync objects: the connection log's segments, parts and
//            body pieces in storage.
//
// `pending` finishes by itself: this device or another one is on it. `blocked`
// does not: it says why, and what ends it is outside this device's retry loop
// (another device with the access, an operator, or work not built yet).

/** Why a part of a delete does not finish by retrying here. */
export type DeleteBlockReason =
  /** The account switched under cutover policy v1: the gateway refuses every legacy delete. */
  | "owner_stream_sync_required"
  /** The gateway refused this server's key: the owner revoked it. */
  | "server_revoked"
  /** The gateway refused this server's key: the owner never registered it. */
  | "server_unregistered"
  /**
   * This device cannot delete from the gateway or storage (no server key, or an
   * enclave). Any device of the account that can does it when it next runs.
   */
  | "needs_another_device"
  /** The control tombstone failed to settle: the connection is live again. */
  | "tombstone_rolled_back"
  /** The newest log segment does not open with this device's key. */
  | "log_unreadable"
  /**
   * Out-of-line body pieces stay in storage: their names are shared with a
   * later lifetime of the connection, so they are not deleted yet.
   */
  | "body_pieces_retained"
  /**
   * Another device erased the log. Storage no longer names the body pieces it
   * left, and only that device recorded them, so this device cannot say they
   * are gone.
   */
  | "erased_elsewhere"
  /**
   * The connection was added again before its log was erased, or while it was.
   * The old lifetime's objects share the log scope with the new one, so none
   * is deleted and none can be shown gone. A later delete of the connection
   * erases both lifetimes.
   */
  | "re_added";

export type DeletePart =
  | { readonly state: "done" }
  | { readonly state: "pending" }
  | { readonly state: "blocked"; readonly reason: DeleteBlockReason };

export interface ConnectionDeleteStatus {
  readonly fence: DeletePart;
  readonly legacy: DeletePart;
  readonly storage: DeletePart;
}

export const PART_DONE: DeletePart = { state: "done" };
export const PART_PENDING: DeletePart = { state: "pending" };
export const blocked = (reason: DeleteBlockReason): DeletePart => ({
  state: "blocked",
  reason,
});

/** The gateway's terminal refusal codes, which are also block reasons. */
export const LEGACY_REFUSALS = [
  "owner_stream_sync_required",
  "server_revoked",
  "server_unregistered",
] as const satisfies readonly DeleteBlockReason[];
export type LegacyRefusal = (typeof LEGACY_REFUSALS)[number];
