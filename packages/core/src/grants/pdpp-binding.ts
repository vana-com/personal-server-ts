/**
 * Retains the identity join between a PDPP grant and a Vana gateway grant.
 * `permissionId` stores GatewayGrantResponse.id, including hex grant IDs.
 * Builder IDs and wallet addresses are distinct: creation requires a trusted
 * builder lookup, and verification compares each identity with its counterpart.
 * Deployment fields bind the record to the PS configuration; they are not
 * authenticated fields of the gateway response. Revocation is checked live.
 */

import {
  GrantOwnerMismatchError,
  GrantRevokedError,
  InvalidSignatureError,
  ScopeMismatchError,
} from "../errors/catalog.js";

import type {
  Builder,
  GatewayGrantResponse,
} from "@opendatalabs/vana-sdk/browser";

/**
 * The chain-side identity of a grant. This tuple — and not any derived digest
 * — is the binding key.
 *
 * `chainId` and `contractAddress` are the PS's own deployment configuration,
 * not fields the gateway returns; see the module doc for why they are kept.
 * `permissionId` is `GatewayGrantResponse.id` (see module doc) — keying on it
 * alone, without a deployment tag, would also let a record recorded under one
 * deployment configuration silently authorize a read under another.
 */
export interface ChainPermissionRef {
  /** EIP-155 chain ID of the deployment the PS was configured against when this was recorded. */
  chainId: number;
  /** The gateway/contract address the PS was configured against when this was recorded. */
  contractAddress: `0x${string}`;
  /** `GatewayGrantResponse.id` — the gateway's grant id (may be hex). */
  permissionId: string;
}

/** The builder evidence a caller must resolve before creating or checking a binding. */
export type ResolvedBuilder = Pick<Builder, "id" | "granteeAddress">;

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
  /**
   * The resolved builder's id (`Builder.id`), as the chain grant's
   * `granteeId` reports it. This is a distinct bytes32-shaped identifier,
   * NOT the wallet address above — see the module doc.
   */
  granteeId: string;
  /** When the binding was recorded (ISO 8601). Provenance, not status. */
  boundAt: string;
}

/** Case-insensitive comparison for hex-ish strings (addresses or bytes32 ids). */
function sameHex(a: string | null | undefined, b: string): boolean {
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
  /**
   * Trusted, already-resolved builder evidence for `granteeAddress` — e.g.
   * `await gateway.getBuilder(granteeAddress)`. This is what lets the binding
   * check the chain grant's `granteeId` (a builder id) against the right
   * counterpart instead of against the wallet address directly.
   */
  resolvedBuilder: ResolvedBuilder;
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
 *  - a `resolvedBuilder` whose wallet is not the app's requested address
 *    (the caller resolved the wrong builder),
 *  - a chain grant whose `granteeId` is not the resolved builder's id
 *    (binding a grant issued to a *different* app),
 *  - a chain grant that is already revoked (never record a dead grant as live),
 *  - a chain grant whose id does not match the permission being bound.
 */
export function createPdppGrantBinding(
  input: CreateBindingInput,
): PdppGrantBinding {
  const {
    chainGrant,
    serverOwner,
    granteeAddress,
    resolvedBuilder,
    permission,
  } = input;

  if (chainGrant.id !== permission.permissionId) {
    throw new InvalidSignatureError({
      reason: "Chain grant id does not match the permission being bound",
      expected: permission.permissionId,
      actual: chainGrant.id,
    });
  }

  if (!sameHex(chainGrant.grantorAddress, serverOwner)) {
    throw new GrantOwnerMismatchError({
      grantId: chainGrant.id,
      expected: serverOwner,
      actual: chainGrant.grantorAddress ?? null,
    });
  }

  // The caller's resolved builder must actually BE the requested app's
  // wallet — otherwise everything below verifies the wrong builder.
  if (!sameHex(resolvedBuilder.granteeAddress, granteeAddress)) {
    throw new InvalidSignatureError({
      reason:
        "Resolved builder wallet does not match the requested app address",
      expected: granteeAddress,
      actual: resolvedBuilder.granteeAddress,
    });
  }

  // Bind to the app's EXISTING grantee identity. If the chain grant was
  // issued to a different builder, this PDPP consent does not describe it.
  // `granteeId` is the builder's bytes32 id, NOT its wallet address — compare
  // against `resolvedBuilder.id`, never against `granteeAddress` directly.
  if (!sameHex(chainGrant.granteeId, resolvedBuilder.id)) {
    throw new InvalidSignatureError({
      reason: "Chain grant grantee does not match the app's builder id",
      expected: resolvedBuilder.id,
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
 * mismatch on any one of owner, app, chain/contract, or record fails closed:
 *
 *  - **record**: the presented PDPP grant id must be the one bound,
 *  - **chain/contract**: the binding must have been recorded under the same
 *    deployment configuration the PS is running under now (see module doc —
 *    this is an operator-misconfiguration guard, not gateway-supplied
 *    evidence, since the gateway response carries no chain/contract fields),
 *  - **owner**: the binding's owner must still be this server's owner, and the
 *    live chain grant's grantor must agree,
 *  - **app**: the request signer (a wallet) must be the bound grantee
 *    address, and the live chain grant's `granteeId` (a builder id) must
 *    still agree with the `granteeId` retained on the binding — these two
 *    checks are deliberately against different fields, because a wallet and
 *    a builder id are different values,
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

  // Deployment binding: a record from another PS deployment configuration is
  // not evidence here. See module doc — this cannot be checked against the
  // gateway response (it carries no chain/contract fields); it guards
  // against the PS itself being reconfigured to a different deployment
  // between when the binding was recorded and when it is read.
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
  if (!sameHex(binding.ownerAddress, input.serverOwner)) {
    throw new GrantOwnerMismatchError({
      grantId: binding.permission.permissionId,
      expected: input.serverOwner,
      actual: binding.ownerAddress,
    });
  }

  // App binding: the caller must BE the bound grantee wallet, not merely
  // know its grant id.
  if (!sameHex(input.requestSigner, binding.granteeAddress)) {
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
  if (!sameHex(chainGrant.grantorAddress, binding.ownerAddress)) {
    throw new GrantOwnerMismatchError({
      grantId: chainGrant.id,
      expected: binding.ownerAddress,
      actual: chainGrant.grantorAddress ?? null,
    });
  }

  // Compare the live grant's builder id (`granteeId`) against the builder id
  // retained on the binding (`binding.granteeId`) — NOT against
  // `binding.granteeAddress`, which is a wallet. The wallet is what
  // `requestSigner` proves above; this checks the separate, gateway-reported
  // builder-id axis has not drifted.
  if (!sameHex(chainGrant.granteeId, binding.granteeId)) {
    throw new InvalidSignatureError({
      reason: "Chain grant grantee no longer matches the bound grantee",
      expected: binding.granteeId,
      actual: chainGrant.granteeId,
    });
  }
}
