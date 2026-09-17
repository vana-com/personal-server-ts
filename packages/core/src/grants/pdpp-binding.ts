/**
 * PDPP ↔ Vana chain grant binding (scope §6, "gateway binding" branch).
 *
 * ## What this is, and what it deliberately is not
 *
 * PDPP Core is chain-neutral. Vana is not: a data read is authorized by a
 * *chain* grant (a `DataPortabilityPermissions` permission, surfaced through
 * the Data Gateway as `GatewayGrantResponse`), while PDPP consent produces a
 * separate *PDPP* grant (an RFC 9396 artifact with a `grant_id`, resolved
 * streams, and frozen declaration facts). Those are two authorities over two
 * different objects, and §7 keeps them separate on purpose.
 *
 * Section 6 asks for the *smallest real binding* between them. This module is
 * that binding: a durable record asserting "PDPP grant X is the consent
 * artifact behind chain permission Y, for owner O and grantee app A".
 *
 * ### Why there is no new hash protocol here
 *
 * An earlier proposal derived a `keccak256` "binding key" over the permission
 * fields. That is rejected, for three reasons that matter:
 *
 *  1. **A sequential permission ID is not a content address.** The chain
 *     allocates `permissionId` as a counter. Hashing it produces a value that
 *     *looks* content-addressed while committing to nothing — a digest of an
 *     index is still an index.
 *  2. **Hashing a mutable grant URI does not bind grant bytes.** The on-chain
 *     `grant` field is a URI (IPFS or HTTPS). Hashing the *URI* binds the
 *     pointer, not the document; the document behind an HTTPS URI can change
 *     freely afterwards. Binding actual frozen bytes would require hashing the
 *     retrieved content, which is what the PDPP declaration digest already
 *     does — separately, and correctly.
 *  3. **`endBlock` is mutable, so it cannot be part of a stable identity.**
 *     Revocation *sets* `endBlock`. A "stable identity" that changes on
 *     revocation is not an identity; it is a status encoding wearing an
 *     identity's clothes, and it silently breaks any record keyed by it.
 *
 * The chain already provides an unambiguous, durable identity — the tuple
 * (chainId, contract address, permissionId) — and an unambiguous revocation
 * signal. A record keyed by that identity is sufficient, so per the scope's
 * own instruction ("do not invent a new hash protocol if a durable record
 * keyed by existing chain permission identity suffices") we key by it and
 * derive nothing.
 *
 * ### No signed struct changes
 *
 * Nothing here enters the EIP-712 `Grant`/`Permission` payload, so the
 * typehash is untouched and no coordinated signer/verifier/contract rollout is
 * triggered. That is what keeps this in the 1–2 day "gateway binding" branch
 * rather than the 6–8 day chain-migration branch.
 */

import {
  GrantOwnerMismatchError,
  GrantRevokedError,
  InvalidSignatureError,
  ScopeMismatchError,
} from "../errors/catalog.js";

import type { GatewayGrantResponse } from "@opendatalabs/vana-sdk/browser";

/**
 * The chain-side identity of a grant. This tuple — and not any derived digest
 * — is the binding key.
 *
 * `chainId` and `contractAddress` are both required because `permissionId` is
 * a per-deployment counter: permission 1 on Moksha and permission 1 on Vana
 * mainnet are unrelated grants. Keying on `permissionId` alone would let a
 * record from one network authorize a read on another.
 */
export interface ChainPermissionRef {
  /** EIP-155 chain ID of the deployment that allocated `permissionId`. */
  chainId: number;
  /** `DataPortabilityPermissions` proxy address on that chain. */
  contractAddress: `0x${string}`;
  /** The on-chain permission ID, as a decimal string (uint256). */
  permissionId: string;
}

/**
 * An immutable binding between one resolved PDPP grant and one chain
 * permission.
 *
 * Immutability is the point: this record is written once, at grant creation,
 * and is never mutated — not even on revocation. Revocation is a *live* fact
 * read from the chain grant (`revokedAt`), never a field edited here. Copying
 * a mutable status into an immutable record is how a stale "still valid" claim
 * survives a revocation, so the two are kept strictly apart.
 */
export interface PdppGrantBinding {
  /** `grant_id` of the resolved PDPP grant (the consent artifact). */
  pdppGrantId: string;
  /** Chain identity of the permission that authorizes reads for this grant. */
  permission: ChainPermissionRef;
  /**
   * The data owner. Must equal both the chain grant's `grantorAddress` and the
   * PS's configured `serverOwner` at read time.
   */
  ownerAddress: `0x${string}`;
  /**
   * The grantee app's wallet address — the app's *existing* identity, carried
   * through unchanged.
   *
   * §6 requires one grantee identity per Context Gateway builder/app: the
   * PDPP `client_id`, the issued grant, the ledger grant, and the access-history
   * grantee must all resolve to this one address. We record the address the app
   * already has; we do not allocate one.
   */
  granteeAddress: `0x${string}`;
  /** The PDPP OAuth `client_id` that the above address belongs to. */
  pdppClientId: string;
  /** The gateway's grantee ID for that address, as the chain grant reports it. */
  granteeId: string;
  /** When the binding was recorded (ISO 8601). Provenance, not status. */
  boundAt: string;
}

/** Normalizes an address for comparison. Addresses are case-insensitive. */
function sameAddress(a: string | null | undefined, b: string): boolean {
  return typeof a === "string" && a.toLowerCase() === b.toLowerCase();
}

/**
 * Compare two chain permission references. All three components must match —
 * see `ChainPermissionRef` for why the address and chain ID are load-bearing.
 */
export function samePermission(
  a: ChainPermissionRef,
  b: ChainPermissionRef,
): boolean {
  return (
    a.chainId === b.chainId &&
    a.contractAddress.toLowerCase() === b.contractAddress.toLowerCase() &&
    a.permissionId === b.permissionId
  );
}

export interface CreateBindingInput {
  pdppGrantId: string;
  permission: ChainPermissionRef;
  /** The PS's configured owner address. */
  serverOwner: `0x${string}`;
  /** The app's existing grantee wallet address. */
  granteeAddress: `0x${string}`;
  pdppClientId: string;
  /** The chain grant this PDPP grant is being bound to, as the gateway reports it. */
  chainGrant: GatewayGrantResponse;
  now?: Date;
}

/**
 * Create the binding at grant-creation time, refusing to record one that is
 * already inconsistent.
 *
 * This is the *creation* boundary check. It is deliberately strict: a binding
 * written now is trusted later, so anything we fail to verify here becomes an
 * unverifiable assertion at read time. Specifically it rejects:
 *
 *  - a chain grant whose `grantorAddress` is not this server's owner (binding
 *    another owner's grant to our PDPP consent),
 *  - a chain grant whose `granteeId` is not the app's (binding a grant issued
 *    to a *different* app),
 *  - a chain grant that is already revoked (never record a dead grant as live),
 *  - a chain grant whose id does not match the permission being bound.
 */
export function createPdppGrantBinding(
  input: CreateBindingInput,
): PdppGrantBinding {
  const { chainGrant, serverOwner, granteeAddress, permission } = input;

  if (chainGrant.id !== permission.permissionId) {
    throw new InvalidSignatureError({
      reason: "Chain grant id does not match the permission being bound",
      expected: permission.permissionId,
      actual: chainGrant.id,
    });
  }

  if (!sameAddress(chainGrant.grantorAddress, serverOwner)) {
    throw new GrantOwnerMismatchError({
      grantId: chainGrant.id,
      expected: serverOwner,
      actual: chainGrant.grantorAddress ?? null,
    });
  }

  // Bind to the app's EXISTING grantee identity. If the chain grant was issued
  // to a different grantee, this PDPP consent does not describe it.
  if (!sameAddress(chainGrant.granteeId, granteeAddress)) {
    throw new InvalidSignatureError({
      reason: "Chain grant grantee does not match the app's grantee address",
      expected: granteeAddress,
      actual: chainGrant.granteeId,
    });
  }

  if (chainGrant.revokedAt !== null && chainGrant.revokedAt !== undefined) {
    throw new GrantRevokedError({ grantId: chainGrant.id });
  }

  return Object.freeze({
    pdppGrantId: input.pdppGrantId,
    permission,
    ownerAddress: serverOwner,
    granteeAddress,
    pdppClientId: input.pdppClientId,
    granteeId: chainGrant.granteeId,
    boundAt: (input.now ?? new Date()).toISOString(),
  });
}

export interface VerifyBindingInput {
  /** The retained, immutable binding record. */
  binding: PdppGrantBinding;
  /** The PDPP grant id presented by the caller. */
  pdppGrantId: string;
  /** The PS's configured owner address, at read time. */
  serverOwner: `0x${string}`;
  /** The address that signed this request (the app's grantee wallet). */
  requestSigner: `0x${string}`;
  /**
   * The chain grant as read *now*. Revocation is read live from here; it is
   * never taken from the binding record.
   */
  chainGrant: GatewayGrantResponse | null;
  /** The deployment the PS is configured against, at read time. */
  deployment: { chainId: number; contractAddress: `0x${string}` };
}

/**
 * Verify a binding at read time.
 *
 * Every axis §6 names is checked against the *retained* binding, so a
 * mismatch on any one of owner, app, chain, contract, or record fails closed:
 *
 *  - **record**: the presented PDPP grant id must be the one bound,
 *  - **chain/contract**: the binding's deployment must be the one the PS is
 *    configured against (a Moksha binding cannot authorize a mainnet read),
 *  - **owner**: the binding's owner must still be this server's owner, and the
 *    live chain grant's grantor must agree,
 *  - **app**: the request signer must be the bound grantee address, and the
 *    live chain grant must still name that grantee,
 *  - **revocation**: the live chain grant must exist and be unrevoked.
 *
 * No chain I/O happens in this function — the caller supplies the already-read
 * `chainGrant`. That keeps this usable on the hot read path without adding a
 * network round trip per request.
 */
export function verifyPdppGrantBinding(input: VerifyBindingInput): void {
  const { binding, chainGrant, deployment } = input;

  // Record binding: the consent artifact presented must be the bound one.
  if (binding.pdppGrantId !== input.pdppGrantId) {
    throw new ScopeMismatchError({
      requestedScope: "pdpp:binding",
      reason: "PDPP grant id does not match the binding record",
      expected: binding.pdppGrantId,
      actual: input.pdppGrantId,
    });
  }

  // Chain/contract binding: a record from another deployment is not evidence
  // here, because permissionId is only unique within one deployment.
  if (
    binding.permission.chainId !== deployment.chainId ||
    binding.permission.contractAddress.toLowerCase() !==
      deployment.contractAddress.toLowerCase()
  ) {
    throw new ScopeMismatchError({
      requestedScope: "pdpp:binding",
      reason: "Binding is for a different chain deployment",
      expected: `${deployment.chainId}:${deployment.contractAddress}`,
      actual: `${binding.permission.chainId}:${binding.permission.contractAddress}`,
    });
  }

  // Owner binding, against the server's current configuration.
  if (!sameAddress(binding.ownerAddress, input.serverOwner)) {
    throw new GrantOwnerMismatchError({
      grantId: binding.permission.permissionId,
      expected: input.serverOwner,
      actual: binding.ownerAddress,
    });
  }

  // App binding: the caller must BE the bound grantee, not merely know its id.
  if (!sameAddress(input.requestSigner, binding.granteeAddress)) {
    throw new InvalidSignatureError({
      reason: "Request signer is not the bound grantee for this PDPP grant",
      expected: binding.granteeAddress,
      actual: input.requestSigner,
    });
  }

  // Revocation is read live. A missing chain grant is treated as revoked
  // rather than as "unknown": failing open here would let a deleted or
  // unreachable permission authorize reads.
  if (!chainGrant) {
    throw new GrantRevokedError({
      grantId: binding.permission.permissionId,
      reason: "Chain grant not found",
    });
  }

  if (chainGrant.id !== binding.permission.permissionId) {
    throw new ScopeMismatchError({
      requestedScope: "pdpp:binding",
      reason: "Chain grant id does not match the binding record",
      expected: binding.permission.permissionId,
      actual: chainGrant.id,
    });
  }

  if (chainGrant.revokedAt !== null && chainGrant.revokedAt !== undefined) {
    throw new GrantRevokedError({ grantId: chainGrant.id });
  }

  // The live chain grant must still agree with the binding on both parties.
  // These can diverge from the record only if the gateway is serving a
  // different grant under the same id, which we must not paper over.
  if (!sameAddress(chainGrant.grantorAddress, binding.ownerAddress)) {
    throw new GrantOwnerMismatchError({
      grantId: chainGrant.id,
      expected: binding.ownerAddress,
      actual: chainGrant.grantorAddress ?? null,
    });
  }

  if (!sameAddress(chainGrant.granteeId, binding.granteeAddress)) {
    throw new InvalidSignatureError({
      reason: "Chain grant grantee no longer matches the bound grantee",
      expected: binding.granteeAddress,
      actual: chainGrant.granteeId,
    });
  }
}
