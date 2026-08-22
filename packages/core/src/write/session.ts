/**
 * Write API session (server-signed delegated writes, v1).
 *
 * A registered builder that holds its OWN key and a WRITE-grant proves control
 * of that key ONCE — a Web3Signed handshake to `POST /v1/write/session` — and
 * the PS mints a short-lived bearer token bound to `{ builderAddress, grantId }`
 * (the grant's `write:`-prefixed scope entries define what it may write).
 * Writes then present that token on the EXISTING ingest endpoint
 * (`POST /v1/data/:scope`); each write authorizes as the builder via
 * `verifyDataWritePolicy` and the PS ingests / encrypts / uploads / registers
 * through the normal owner path — the PS signs AddData as the owner exactly as
 * it does today, and the builder never holds the owner key.
 *
 * Deliberately the same handshake shape as the self-signing MCP session
 * (mcp/session.ts): prove key control once, short-lived bearer after. The
 * session token is authorization only; per-write builder ATTRIBUTION is a
 * separate signed proof (see ./attribution.ts).
 */

import { hashConnectionToken } from "../mcp/connection-api.js";
import {
  createInMemoryMcpProofReplayStore,
  type McpProofReplayStore,
} from "../mcp/session.js";
import { writeScopePatterns } from "../policy/data-write.js";
import type {
  AuthSessionVerifierPort,
  GrantVerifierPort,
} from "../ports/index.js";
import {
  GrantOwnerMismatchError,
  GrantRequiredError,
  GrantRevokedError,
  InvalidSignatureError,
  ProtocolError,
  ScopeMismatchError,
  UnregisteredBuilderError,
} from "../errors/catalog.js";

// The MCP session's proof-replay guard and token hashing are runtime-agnostic
// (Web Crypto + a Map); reuse them rather than duplicating. Re-exported under
// write-flavored names so callers don't couple to the MCP module.
export type WriteProofReplayStore = McpProofReplayStore;
export const createInMemoryWriteProofReplayStore =
  createInMemoryMcpProofReplayStore;
export const hashWriteSessionToken = hashConnectionToken;

export interface WriteSessionRecord {
  /** SHA-256 hex of the raw session token. Only the hash is stored. */
  tokenHash: string;
  /** The builder's address (recovered from the handshake proof). */
  builderAddress: `0x${string}`;
  /** The write-grant id the builder was issued (grantee == builder). */
  grantId: string;
  /** The grant's write patterns at handshake time (prefix stripped). */
  writeScopes: string[];
  createdAt: string;
  expiresAtMs: number;
}

export interface WriteSessionStore {
  create(record: WriteSessionRecord): Promise<void>;
  /** Returns a live (non-expired) session, or null. */
  getByTokenHash(tokenHash: string): Promise<WriteSessionRecord | null>;
}

/**
 * KNOWN LIMITATION: in-memory only, same trade-off as the MCP session store —
 * a process restart drops live tokens and the builder must re-handshake.
 * Acceptable for today's single-instance Personal Server; persist via the
 * host's state store before multi-instance.
 */
export function createInMemoryWriteSessionStore(): WriteSessionStore {
  const byHash = new Map<string, WriteSessionRecord>();
  return {
    async create(record) {
      byHash.set(record.tokenHash, record);
    },
    async getByTokenHash(tokenHash) {
      const record = byHash.get(tokenHash);
      if (!record) return null;
      if (record.expiresAtMs <= Date.now()) {
        byHash.delete(tokenHash);
        return null;
      }
      return record;
    },
  };
}

const DEFAULT_SESSION_TTL_MS = 60 * 60 * 1000;

export interface CreateWriteSessionInput {
  builderAddress: `0x${string}`;
  grantId: string;
  /**
   * Handshake-proof replay guard. When supplied together with a `replayStore`,
   * a proof id already seen (and still live) is rejected instead of minting a
   * fresh token. `expiresAtMs` bounds how long the id is remembered (the
   * proof's own expiry).
   */
  proof?: { id: string; expiresAtMs: number };
}

export interface CreateWriteSessionOptions {
  store: WriteSessionStore;
  authSessionVerifier: AuthSessionVerifierPort;
  grantVerifier: GrantVerifierPort;
  /**
   * This server's owner address. The grant's grantor MUST equal it — mirrors
   * `verifyDataWritePolicy`'s ownership binding, applied at handshake so a
   * wrong-owner grant fails with a clear error instead of minting a token
   * whose every write would 403.
   */
  serverOwner: `0x${string}`;
  randomToken: () => string;
  ttlMs?: number;
  now?: () => number;
  /** Optional replay guard for the handshake proof (see `input.proof`). */
  replayStore?: WriteProofReplayStore;
}

export interface CreateWriteSessionResult {
  accessToken: string;
  expiresInSeconds: number;
  grantId: string;
  /** Write patterns (prefix stripped) the session may write into. */
  writeScopes: string[];
}

/**
 * Validate the handshake identity and mint a write-session token. Same
 * division of labor as createMcpSession: the handshake does the minimal
 * checks that give a clear error (builder registered, grant exists + not
 * revoked + carries write scopes, grantee == builder, grantor == owner);
 * per-scope / expiry enforcement stays authoritative at write time, where
 * `verifyDataWritePolicy` runs against the live grant on every POST.
 */
export async function createWriteSession(
  input: CreateWriteSessionInput,
  options: CreateWriteSessionOptions,
): Promise<CreateWriteSessionResult> {
  const builder = await options.authSessionVerifier.getBuilder(
    input.builderAddress,
  );
  if (!builder) throw new UnregisteredBuilderError();

  const grant = await options.grantVerifier.getGrant(input.grantId);
  if (!grant) {
    throw new GrantRequiredError({
      reason: "Grant not found",
      grantId: input.grantId,
    });
  }
  if (grant.revokedAt !== null) {
    throw new GrantRevokedError({ grantId: grant.id });
  }
  const patterns = writeScopePatterns(grant.scopes ?? []);
  if (patterns.length === 0) {
    throw new ScopeMismatchError({
      reason:
        "Grant has no write scopes (write-grant entries use the write: prefix)",
      grantedScopes: grant.scopes ?? [],
    });
  }
  if (builder.id.toLowerCase() !== grant.granteeId.toLowerCase()) {
    throw new InvalidSignatureError({
      reason: "Handshake signer is not the grant builder",
      expected: grant.granteeId,
      actual: input.builderAddress,
    });
  }
  // Ownership binding — fail closed on a grantor-less grant: gateway
  // responses are untrusted runtime data, despite their type.
  if (
    !grant.grantorAddress ||
    grant.grantorAddress.toLowerCase() !== options.serverOwner.toLowerCase()
  ) {
    throw new GrantOwnerMismatchError({
      grantId: grant.id,
      expected: options.serverOwner,
      actual: grant.grantorAddress ?? null,
    });
  }

  // Prepare the token first (deterministic, can't meaningfully fail) so the
  // only fallible step after consuming the proof is persistence.
  const token = options.randomToken();
  const tokenHash = await hashWriteSessionToken(token);
  const ttlMs = options.ttlMs ?? DEFAULT_SESSION_TTL_MS;
  const nowMs = options.now?.() ?? Date.now();

  // Replay guard: a still-valid handshake proof must mint at most one token.
  // Same consume/rollback discipline as createMcpSession.
  const usingReplayGuard = Boolean(input.proof && options.replayStore);
  if (input.proof && options.replayStore) {
    const replayed = await options.replayStore.consume(
      input.proof.id,
      input.proof.expiresAtMs,
    );
    if (replayed) {
      throw new ProtocolError(
        401,
        "WRITE_SESSION_PROOF_REPLAY",
        "Handshake proof already used; sign a fresh proof",
      );
    }
  }

  try {
    await options.store.create({
      tokenHash,
      builderAddress: input.builderAddress,
      grantId: grant.id,
      writeScopes: patterns,
      createdAt: new Date(nowMs).toISOString(),
      expiresAtMs: nowMs + ttlMs,
    });
  } catch (err) {
    // Persistence failed — release the reservation so a legitimate retry with
    // the same still-valid proof isn't rejected as a replay.
    if (usingReplayGuard && input.proof && options.replayStore?.release) {
      await options.replayStore.release(input.proof.id);
    }
    throw err;
  }

  return {
    accessToken: token,
    expiresInSeconds: Math.floor(ttlMs / 1000),
    grantId: grant.id,
    writeScopes: patterns,
  };
}
