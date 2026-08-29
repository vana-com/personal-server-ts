/**
 * Delegated-write authorization, shared by every build.
 *
 * `authorizeWrite` / `authorizeWriteSession` are the two write-session halves
 * of `PersonalServerApiAuthPort`. They were originally written inside the Node
 * server's auth adapter (packages/server/src/api-auth.ts); the checks they run
 * are pure protocol — a token hash, a live grant re-check, an EIP-191 payload
 * proof and a replay reservation — with nothing Node-specific in them, so they
 * live here and BOTH the Node server adapter and the browser (PS-Lite)
 * adapters call the same code. There is exactly one implementation of the
 * write policy; a browser build cannot drift into a weaker one.
 *
 * The two entry points differ in what they are allowed to decide:
 *
 *   - `authorizeSessionWrite` authorizes a write to a NAMED scope. It
 *     re-runs `verifyDataWritePolicy` against the LIVE grant on every call,
 *     so revocation, expiry, grantee binding, owner binding and scope
 *     coverage stay authoritative per write rather than being frozen at
 *     handshake, and it verifies the builder's per-write payload proof.
 *   - `recognizeWriteSession` is identity only: the bearer must resolve to a
 *     live session and the request must carry that builder's valid proof, but
 *     NO grant policy runs (there is no scope to run one against). Callers use
 *     it only to choose between error shapes, never to release data.
 *
 * Both fail closed: an unknown bearer, an unknown session, a missing server
 * owner, or any failing proof check returns/raises rather than falling back to
 * a weaker credential. A request that is not a write-session request at all
 * returns `undefined`, and the caller applies its own owner gate.
 */

import { ProtocolError } from "../errors/catalog.js";
import {
  verifyDataWritePolicy,
  type DataWritePolicyPorts,
} from "../policy/data-write.js";
import type {
  PersonalServerWriteAuthInput,
  PersonalServerWriteAuthResult,
  PersonalServerWriteSessionResult,
} from "../api/index.js";
import { verifyWriterAttribution } from "./attribution.js";
import {
  hashWriteSessionToken,
  type WriteProofReplayStore,
  type WriteSessionStore,
} from "./session.js";

export interface WriteSessionAuthorizationDeps {
  /**
   * This server's origin. Every payload proof must name it as its audience,
   * so a proof signed for another Personal Server cannot be relayed here.
   */
  serverOrigin: string | (() => string);
  /**
   * The owner every grant must have been issued by. Absent = fail closed:
   * a delegated write cannot be bound to an owner we cannot name.
   */
  serverOwner?: `0x${string}`;
  /**
   * Live write sessions (minted by POST /v1/write/session). Absent = the host
   * does not support delegated writes and every request falls through to the
   * caller's owner gate.
   */
  sessionStore?: WriteSessionStore;
  /** Replay guard for the per-write `X-Vana-Write-Signature` proofs. */
  replayStore: WriteProofReplayStore;
  /** Live builder/grant verification, re-run on every delegated write. */
  policyPorts: DataWritePolicyPorts;
  now?: () => Date;
}

export interface WriteSessionAuthorization {
  /**
   * Authorize a delegated write to `input.scope`, or `undefined` when the
   * request carries no live write-session credential (the caller then applies
   * its owner gate, exactly as before write sessions existed).
   */
  authorizeSessionWrite(
    input: PersonalServerWriteAuthInput,
  ): Promise<PersonalServerWriteAuthResult | undefined>;
  /**
   * Identity-only recognition of a write-session caller. Never releases data.
   */
  recognizeWriteSession(
    request: Request,
  ): Promise<PersonalServerWriteSessionResult | undefined>;
}

/** The bearer credential a write session is presented under. */
export function writeSessionBearerToken(request: Request): string | null {
  const header = request.headers.get("authorization");
  if (!header?.startsWith("Bearer ")) return null;
  return header.slice(7);
}

/**
 * Same shape and message as the auth layer's own missing-owner failure, so a
 * host that never configured an owner reports one thing, not two.
 */
export function writeServerNotConfigured(): ProtocolError {
  return new ProtocolError(
    500,
    "SERVER_NOT_CONFIGURED",
    "Server owner address not configured. Set VANA_MASTER_KEY_SIGNATURE environment variable.",
  );
}

export function createWriteSessionAuthorization(
  deps: WriteSessionAuthorizationDeps,
): WriteSessionAuthorization {
  async function liveSession(request: Request) {
    const token = writeSessionBearerToken(request);
    if (!token || !deps.sessionStore) return null;
    return deps.sessionStore.getByTokenHash(await hashWriteSessionToken(token));
  }

  return {
    async authorizeSessionWrite(input) {
      const session = await liveSession(input.request);
      if (!session) return undefined;
      if (!deps.serverOwner) throw writeServerNotConfigured();
      // The grant is re-checked live on EVERY write: a session token minted
      // an hour ago against a grant that has since been revoked, narrowed or
      // expired authorizes nothing.
      const grant = await verifyDataWritePolicy(
        {
          signer: session.builderAddress,
          grantId: session.grantId,
          requestedScope: input.scope,
          serverOwner: deps.serverOwner,
        },
        deps.policyPorts,
      );
      // releaseProof is a rollback hook for the handler, never part of the
      // stored attribution record.
      const { releaseProof, ...attribution } = await verifyWriterAttribution({
        request: input.request,
        builderAddress: session.builderAddress,
        grantId: grant.id,
        serverOrigin: deps.serverOrigin,
        replayStore: deps.replayStore,
        now: deps.now,
      });
      return {
        builder: session.builderAddress,
        grantId: grant.id,
        grantScopes: grant.scopes ?? [],
        attribution,
        releaseProof,
      };
    },

    async recognizeWriteSession(request) {
      const session = await liveSession(request);
      if (!session) return undefined;
      const { releaseProof } = await verifyWriterAttribution({
        request,
        builderAddress: session.builderAddress,
        grantId: session.grantId,
        serverOrigin: deps.serverOrigin,
        replayStore: deps.replayStore,
        now: deps.now,
      });
      return {
        builder: session.builderAddress,
        grantId: session.grantId,
        releaseProof,
      };
    },
  };
}
