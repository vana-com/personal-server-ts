/**
 * Durable retention for PDPP ↔ chain grant bindings (scope §6).
 *
 * The binding record is the only thing that crosses the gateway/chain
 * boundary on our side; record payloads stay in PS storage and never enter
 * this store. What is retained here is an identity join — PDPP grant id,
 * chain permission ref, owner, grantee — and nothing about the data itself.
 *
 * ## Append-only by construction
 *
 * The port exposes `put` and `get` but no `update` and no `delete`. That is
 * deliberate, and it is the mechanism that makes §6's revocation semantics
 * correct rather than merely intended:
 *
 *   - A binding asserts a *historical* fact ("this consent authorized this
 *     permission"), which does not stop being true when the grant is revoked.
 *   - Revocation is a *current* fact, and lives on the chain grant, read live
 *     at verification time.
 *
 * If revocation were mirrored into this store, the two would have to be kept
 * in sync, and every window where they disagreed would be a window where a
 * revoked grant still read as live. Not storing the status at all removes that
 * class of bug instead of managing it.
 *
 * `putBinding` rejects a conflicting rewrite for the same key rather than
 * overwriting, so a second binding cannot silently retarget an existing PDPP
 * grant at a different permission, owner, or app.
 */

import { InvalidSignatureError } from "../errors/catalog.js";

import {
  samePermission,
  type ChainPermissionRef,
  type PdppGrantBinding,
} from "./pdpp-binding.js";

/**
 * Durable storage for grant bindings.
 *
 * Implementations back this with the deployment's real store (SQLite on
 * desktop, the supplied runtime's durable state in Enclave). The interface is
 * intentionally tiny so both can implement it without sharing a schema.
 */
export interface PdppGrantBindingStore {
  /**
   * Retain a binding. Idempotent for an identical re-put; throws on a
   * conflicting one.
   */
  putBinding(binding: PdppGrantBinding): void;
  /** Look up by the PDPP grant id (the consent artifact). */
  getByPdppGrantId(pdppGrantId: string): PdppGrantBinding | null;
  /** Look up by chain permission identity. */
  getByPermission(permission: ChainPermissionRef): PdppGrantBinding | null;
}

/**
 * True when two bindings agree on every field that defines the binding.
 *
 * `granteeAddress` is compared, which makes grantee rotation an explicit
 * conflict rather than a silent follow. That is deliberate. Context Gateway
 * holds one Privy-custodied wallet per app, keyed `(ownerType, ownerId)` with
 * a DB unique index, and its schema *models* rotation (`isCurrent` plus a
 * partial unique index) although no code path performs one today — so the
 * address is currently immutable per app in practice but not by design.
 *
 * If rotation ever ships, a rotated wallet is a different grantee, and the
 * owner's existing consent must not transfer to it without a new decision.
 * Rejecting the rewrite surfaces that as a failure instead of quietly
 * repointing a retained grant at an address the owner never approved.
 */
export function bindingsAgree(
  a: PdppGrantBinding,
  b: PdppGrantBinding,
): boolean {
  return (
    a.pdppGrantId === b.pdppGrantId &&
    samePermission(a.permission, b.permission) &&
    a.ownerAddress.toLowerCase() === b.ownerAddress.toLowerCase() &&
    a.granteeAddress.toLowerCase() === b.granteeAddress.toLowerCase() &&
    a.pdppClientId === b.pdppClientId
  );
}

export function permissionKey(p: ChainPermissionRef): string {
  return `${p.chainId}:${p.contractAddress.toLowerCase()}:${p.permissionId}`;
}

/**
 * In-memory implementation, used by tests and by callers that have no durable
 * store yet.
 *
 * This is a real implementation of the port's semantics — including the
 * conflict rejection — not a stub that accepts everything. Tests exercising it
 * are therefore testing the actual binding rules; only the persistence medium
 * differs from a deployed store.
 */
export function createInMemoryPdppGrantBindingStore(): PdppGrantBindingStore {
  const byGrantId = new Map<string, PdppGrantBinding>();
  const byPermission = new Map<string, PdppGrantBinding>();

  return {
    putBinding(binding: PdppGrantBinding): void {
      const existingByGrant = byGrantId.get(binding.pdppGrantId);
      if (existingByGrant && !bindingsAgree(existingByGrant, binding)) {
        throw new InvalidSignatureError({
          reason: "A different binding already exists for this PDPP grant id",
          pdppGrantId: binding.pdppGrantId,
        });
      }

      const key = permissionKey(binding.permission);
      const existingByPermission = byPermission.get(key);
      if (
        existingByPermission &&
        !bindingsAgree(existingByPermission, binding)
      ) {
        throw new InvalidSignatureError({
          reason: "A different binding already exists for this permission",
          permission: key,
        });
      }

      byGrantId.set(binding.pdppGrantId, binding);
      byPermission.set(key, binding);
    },

    getByPdppGrantId(pdppGrantId: string): PdppGrantBinding | null {
      return byGrantId.get(pdppGrantId) ?? null;
    },

    getByPermission(permission: ChainPermissionRef): PdppGrantBinding | null {
      return byPermission.get(permissionKey(permission)) ?? null;
    },
  };
}
