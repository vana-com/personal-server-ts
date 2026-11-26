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

import type { GatewayRefusalCode } from "../sync/gateway-refusal.js";

/** Why a part of a delete does not finish by retrying here. */
export type DeleteBlockReason =
  /**
   * The gateway's terminal refusals (`GATEWAY_REFUSAL_CODES`: the owner
   * switched under a policy that admits no legacy delete, or this server's
   * key is revoked or was never registered). One list, shared with the parser.
   */
  | GatewayRefusalCode
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
  | "re_added"
  /**
   * A standalone legacy retirement pinned the gateway head of a legacy scope.
   * The head is not that one now (a write moved it, or a scope that was
   * absent or deleted is live), so the retirement does not tombstone it. It
   * never widens to the head it finds.
   */
  | "legacy_head_changed"
  | "legacy_manifest_missing";

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
