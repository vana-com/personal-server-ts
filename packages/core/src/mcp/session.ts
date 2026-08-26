/**
 * Self-signing MCP session (Option A / chatbot-first).
 *
 * A third-party app that holds its OWN key and a DCR grant proves control of
 * that key ONCE — a Web3Signed handshake to `POST /mcp/session` — and the PS
 * mints a short-lived bearer session token bound to `{ builderAddress, grantId }`.
 * MCP tool calls then present that token as `Authorization: Bearer …`; each read
 * authorizes as the builder via `verifyDataReadPolicy` (signer == grantee) with
 * NO per-read signature and NO PS-held key.
 *
 * Contrast with the owner's-Claude flow, where the PS generates and holds a
 * per-connection grantee key and signs reads itself. Here the app is
 * self-custody; the PS only ever recovered its address (at handshake).
 */

import { generateMcpGrantee } from "./grantee.js";
import { hashConnectionToken } from "./connection-api.js";
import type { McpConnectionRecord } from "./types.js";
import type { ServerAccount } from "../keys/server-account.js";
import { verifyDataReadPolicy } from "../policy/data-read.js";
import type {
  AuthSessionVerifierPort,
  GrantVerifierPort,
  RuntimeAvailabilityPort,
} from "../ports/index.js";
import { assertScopeNotDeleted, handleX402Cycle } from "../api/index.js";
import type {
  PersonalServerApiAuthPort,
  PersonalServerReadAuthInput,
  PersonalServerDataApiDeps,
} from "../api/index.js";
import {
  GrantOwnerMismatchError,
  GrantRequiredError,
  GrantRevokedError,
  InvalidSignatureError,
  ProtocolError,
  UnregisteredBuilderError,
} from "../errors/catalog.js";
import type {
  DataPortabilityGatewayConfig,
  GatewayClient,
} from "@opendatalabs/vana-sdk/browser";

export interface McpSessionRecord {
  /** SHA-256 hex of the raw session token. Only the hash is stored. */
  tokenHash: string;
  /** The self-custody app's address (recovered from the handshake proof). */
  builderAddress: `0x${string}`;
  /** DCR grant id the app was issued (grantee == builderAddress). */
  grantId: string;
  scopes: string[];
  createdAt: string;
  expiresAtMs: number;
}

export interface McpSessionStore {
  create(record: McpSessionRecord): Promise<void>;
  /** Returns a live (non-expired) session, or null. */
  getByTokenHash(tokenHash: string): Promise<McpSessionRecord | null>;
}

/**
 * KNOWN LIMITATION: in-memory only. A process restart (or a second instance)
 * starts with an empty store, so live session tokens die with the process and
 * the client must re-handshake. Acceptable for today's single-instance
 * Personal Server; persist via the host's state store before multi-instance.
 */
export function createInMemoryMcpSessionStore(): McpSessionStore {
  const byHash = new Map<string, McpSessionRecord>();
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

/**
 * Records consumed handshake-proof identifiers until they expire, so a still-
 * valid Web3Signed proof cannot be replayed to mint a second session token.
 */
export interface McpProofReplayStore {
  /**
   * Atomically record `proofId` (remembered until `expiresAtMs`) and report
   * whether it was ALREADY present and live — i.e. a replay. Returns `true`
   * on replay, `false` when the proof is fresh (and now recorded).
   */
  consume(proofId: string, expiresAtMs: number): Promise<boolean>;
  /**
   * Roll back a prior `consume` for `proofId` (e.g. when session persistence
   * failed after the reservation). Optional — stores that can't release safely
   * omit it and callers must tolerate its absence.
   */
  release?(proofId: string): Promise<void>;
}

/**
 * KNOWN LIMITATION: in-memory only. A process restart (or a second instance)
 * forgets consumed proof ids, so a still-valid handshake proof could be
 * replayed once against the fresh process. The blast radius is bounded by the
 * proof's own expiry, and today's Personal Server runs single-instance, so we
 * document rather than persist. Persist via the host's state store (do not
 * invent a new storage layer) before running multiple instances.
 */
export function createInMemoryMcpProofReplayStore(): McpProofReplayStore {
  const seen = new Map<string, number>();
  return {
    async consume(proofId, expiresAtMs) {
      const now = Date.now();
      for (const [id, exp] of seen) {
        if (exp <= now) seen.delete(id);
      }
      const existing = seen.get(proofId);
      if (existing !== undefined && existing > now) return true;
      seen.set(proofId, expiresAtMs);
      return false;
    },
    async release(proofId) {
      seen.delete(proofId);
    },
  };
}

const DEFAULT_SESSION_TTL_MS = 60 * 60 * 1000;

export interface CreateMcpSessionInput {
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

export interface CreateMcpSessionOptions {
  store: McpSessionStore;
  authSessionVerifier: AuthSessionVerifierPort;
  grantVerifier: GrantVerifierPort;
  /**
   * This server's owner address. The grant's grantor MUST equal it — mirrors
   * `verifyDataReadPolicy`'s ownership binding (see policy/data-read.ts).
   * Required (not optional) so TypeScript flags any caller that would mint a
   * session for a grant issued by a different owner.
   */
  serverOwner: `0x${string}`;
  randomToken: () => string;
  ttlMs?: number;
  now?: () => number;
  /** Optional replay guard for the handshake proof (see `input.proof`). */
  replayStore?: McpProofReplayStore;
}

export interface CreateMcpSessionResult {
  accessToken: string;
  expiresInSeconds: number;
  grantId: string;
  scopes: string[];
}

/**
 * Validate the handshake identity and mint a session token. Per-scope / expiry
 * enforcement is authoritative at read time (`verifyDataReadPolicy`), so this
 * does the minimal checks that give a clear handshake error: builder registered,
 * grant exists + not revoked, and grantee == builder.
 */
export async function createMcpSession(
  input: CreateMcpSessionInput,
  options: CreateMcpSessionOptions,
): Promise<CreateMcpSessionResult> {
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
  if (builder.id.toLowerCase() !== grant.granteeId.toLowerCase()) {
    throw new InvalidSignatureError({
      reason: "Handshake signer is not the grant builder",
      expected: grant.granteeId,
      actual: input.builderAddress,
    });
  }
  // Ownership binding — the grant MUST have been issued by THIS server's
  // owner (same check as `verifyDataReadPolicy`, which stays authoritative at
  // read time). A wrong-owner grant can never become valid for this server,
  // so reject at handshake with a clear error instead of minting a token
  // whose every read would 403. Fail closed on a grantor-less grant: gateway
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
  const tokenHash = await hashConnectionToken(token);
  const ttlMs = options.ttlMs ?? DEFAULT_SESSION_TTL_MS;
  const nowMs = options.now?.() ?? Date.now();

  // Replay guard: a still-valid handshake proof must mint at most one token.
  // Consume ONLY after identity validation, and roll the reservation back if
  // persistence fails — so a transient failure never burns a valid proof.
  // consume() is an atomic check-and-set, so concurrent duplicates still
  // resolve to exactly one winner.
  const usingReplayGuard = Boolean(input.proof && options.replayStore);
  if (input.proof && options.replayStore) {
    const replayed = await options.replayStore.consume(
      input.proof.id,
      input.proof.expiresAtMs,
    );
    if (replayed) {
      throw new ProtocolError(
        401,
        "MCP_SESSION_PROOF_REPLAY",
        "Handshake proof already used; sign a fresh proof",
      );
    }
  }

  try {
    await options.store.create({
      tokenHash,
      builderAddress: input.builderAddress,
      grantId: grant.id,
      scopes: grant.scopes ?? [],
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
    scopes: grant.scopes ?? [],
  };
}

/**
 * An auth port bound to one session's `{ builderAddress, grantId }`. Reads
 * authorize by running `verifyDataReadPolicy` with the builder address proven at
 * handshake — no signature needed. Owner ops are refused.
 */
/**
 * x402 payment binding for a paid (self-signing) session. When present, every
 * read runs the same challenge-or-settle cycle as an external builder's
 * `GET /v1/data/:scope`. Omit it (owner's-Claude path) to keep reads free.
 */
export interface McpSessionPaymentConfig {
  /** Payment-enabled data-API deps (storage, serverSigner, serverAddress, …). */
  dataApiDeps: PersonalServerDataApiDeps;
  gateway: Pick<GatewayClient, "getGrant">;
  gatewayConfig: DataPortabilityGatewayConfig;
  gatewayUrl: string;
}

export function createMcpSessionAuthPort(params: {
  builderAddress: `0x${string}`;
  grantId: string;
  authSessionVerifier: AuthSessionVerifierPort;
  grantVerifier: GrantVerifierPort;
  /**
   * This server's owner address, required by `verifyDataReadPolicy` to bind
   * every session read to a grant issued by THIS server's owner.
   */
  serverOwner: `0x${string}`;
  runtimeAvailability?: RuntimeAvailabilityPort;
  /** Present only for paid self-signing sessions; absent = free. */
  payment?: McpSessionPaymentConfig;
}): PersonalServerApiAuthPort {
  return {
    async authorizeOwner() {
      throw new InvalidSignatureError({
        reason: "MCP session cannot perform owner operations",
      });
    },
    async authorizeBuilderList() {
      // Allowed: the session builder may list its own granted scopes.
    },
    async authorizeBuilderRead(input: PersonalServerReadAuthInput) {
      const grant = await verifyDataReadPolicy(
        {
          signer: params.builderAddress,
          grantId: params.grantId,
          requestedScope: input.scope,
          fileId: input.fileId,
          serverOwner: params.serverOwner,
        },
        {
          authSessionVerifier: params.authSessionVerifier,
          grantVerifier: params.grantVerifier,
          runtimeAvailability: params.runtimeAvailability,
        },
      );

      // Paid session: enforce x402 per read (reuses the exact HTTP cycle). The
      // read client forwards the app's `X-PAYMENT` proof on `input.request`.
      if (params.payment) {
        // Settlement happens here, ahead of the HTTP handler's own deletion
        // gate, so the gate must run here too: never challenge or settle a
        // read of a scope the owner deleted.
        const deps = params.payment.dataApiDeps;
        await assertScopeNotDeleted(
          deps,
          input.scope,
          deps.storage.findEntry({
            scope: input.scope,
            fileId: input.fileId,
            at: input.at,
          }),
        );
        const cycle = await handleX402Cycle({
          deps: params.payment.dataApiDeps,
          request: input.request,
          scope: input.scope,
          fileIdParam: input.fileId,
          // Bind the payment to the exact data version being served (a
          // cursor-pinned or `at=`-pinned read may serve an older version
          // than the latest entry) — otherwise the challenge/accessRecord
          // would settle against different bytes than were returned.
          atParam: input.at,
          grantId: params.grantId,
          builder: params.builderAddress,
          gateway: params.payment.gateway,
          gatewayConfig: params.payment.gatewayConfig,
          gatewayUrl: params.payment.gatewayUrl,
        });
        if (cycle.kind === "challenge") {
          throw new ProtocolError(
            402,
            "PAYMENT_REQUIRED",
            "Payment required for this read",
            { challenge: cycle.body },
          );
        }
        if (cycle.kind === "gateway-error") {
          throw new ProtocolError(
            cycle.status,
            "PAYMENT_GATEWAY_ERROR",
            "Payment gateway rejected the payment",
            { body: cycle.body },
          );
        }
        // cycle.kind === "ok" — payment settled; proceed to read.
      }

      return { builder: params.builderAddress, grantId: grant.id };
    },
  };
}

export interface McpSessionConnection {
  connection: McpConnectionRecord;
  account: ServerAccount;
}

/**
 * Build a synthetic connection record + a throwaway signing account for the
 * streamable `/mcp` handler. The MCP read client still signs its in-process
 * request (the read path requires an account), but the session auth port
 * ignores that signature and authorizes as the real builder — so this key is
 * disposable and never leaves the process.
 */
export function buildMcpSessionConnection(
  session: Pick<McpSessionRecord, "builderAddress" | "grantId" | "scopes">,
  options: { id?: string; now?: () => number } = {},
): McpSessionConnection {
  const ephemeral = generateMcpGrantee();
  const nowIso = new Date(options.now?.() ?? Date.now()).toISOString();
  const connection: McpConnectionRecord = {
    id: options.id ?? `mcp-session-${session.grantId}`,
    displayName: "MCP session",
    granteeAddress: session.builderAddress,
    granteePublicKey: ephemeral.key.publicKey,
    encryptedGranteePrivateKey: ephemeral.key.encryptedPrivateKey,
    tokenHash: "",
    status: "approved",
    grants: [{ grantId: session.grantId, scopes: session.scopes }],
    createdAt: nowIso,
    approvedAt: nowIso,
  };
  return { connection, account: ephemeral.account };
}
