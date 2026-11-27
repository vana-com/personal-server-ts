/**
 * Design 2: chain-enforced PDPP grants (Vana-6.1, Vana-6.2).
 *
 * Each issued PDPP grant becomes one entry in the PermissionsV2 slot of
 * (owner, app builder): `pdpp:sha256:<salted fingerprint>` (core
 * `grants/pdpp-chain-entry.ts`). The wire contract is the data gateway's
 * (`lib/pdpp-grants.ts` header, `api/v1/grants/[grantId].ts` "Wire contract",
 * `db/migrations/README.md` 0077, branch `maciej/pdpp-design2`):
 *
 * - Issuance: `PUT /v1/pdpp/scope-bindings` for every label the grant can
 *   read, then `POST /v1/grants` with the slot's current entries plus the new
 *   one, signed as a GrantRegistration at `currentGrantVersion + 1`, with the
 *   grant document and salt attached (`pdppGrants`). The gateway returns the
 *   slot id (the chain permission id), which is stored as the binding.
 * - Grant end: a removal-only `POST /v1/grants` without the entry, or a V2
 *   revocation (`DELETE /v1/grants/:id`, past expiry) when no entry remains.
 *   The row stays `ending` until the gateway reports the upsert final; a
 *   `v2_reverted` or `superseded` revocation is signed again.
 * - Reads: the gate below checks `GET /v1/pdpp/chain-binding` for the grant:
 *   the entry must be listed at the gateway AND on chain at an active slot.
 *
 * Signing: the PS signs as the owner's registered server, which the gateway
 * accepts for registrations, revocations and the `/v1/pdpp/*` routes. That is
 * how MCP grant registrations are signed today (`mcp/connection-api.ts`).
 *
 * Fail closed: a grant whose registration did not reach the gateway stays
 * `pending` and is not readable. The gate retries the registration on the
 * next read and answers "retry" (500 + Retry-After) until it lands.
 *
 * Never logged: grant documents and salts.
 */

import { createHash } from "node:crypto";
import {
  computePdppGrantEntry,
  newPdppGrantSalt,
} from "@opendatalabs/personal-server-ts-core/grants";
import {
  grantUsesLockedRules,
  isV02Grant,
  type ChainRegistration,
  type Grant,
  type PdppAuthStore,
} from "@opendatalabs/personal-server-ts-core/pdpp";
import {
  buildWeb3SignedHeader,
  getChainConfig,
} from "@opendatalabs/vana-sdk/browser";
import {
  createPublicClient,
  encodeAbiParameters,
  http,
  keccak256,
  parseAbi,
} from "viem";
import type { Logger } from "pino";
import type {
  PdppChainDecision,
  PdppChainEnforcementPort,
} from "../routes/pdpp-records.js";

// ─── Gateway wire ─────────────────────────────────────────────────────────

/** `data.grants[i]` / `data` of the gateway grant routes (subset read here). */
export interface GatewaySlot {
  id: string;
  granteeId: string;
  scopes: string[];
  grantVersion: string;
  /** Sign strictly above this (highest version the gateway answered). */
  currentGrantVersion: string;
  expiresAtSeconds: string;
  expired: boolean;
  status: string;
  revokedAt: string | null;
  revocationKind: string | null;
  revocationFinalizedAt: string | null;
  revocationOutcome: string | null;
  /**
   * Outcome of the slot's LATEST registration or upsert (gateway b16e9d7):
   * 'pending' | 'sent' | 'confirmed' | 'finalized' | 'reverted' | 'failed' |
   * 'not_sent'. Absent on older gateways.
   */
  registrationOutcome?: string | null;
}

/** One element of `GET /v1/pdpp/chain-binding` `data.bindings`. */
export interface GatewayChainBinding {
  chainId: string;
  contractAddress: string;
  permissionId: string;
  entry: string;
  pdppGrantId: string;
  pdppExpired: boolean;
  gateway: { entryListed: boolean; slotRevoked: boolean; slotExpired: boolean };
  onChain: { entryPresent: boolean; slotActive: boolean };
  active: boolean;
}

export interface GatewayAnswer {
  status: number;
  body: Record<string, unknown>;
}

export interface PdppChainGateway {
  getBuilder(
    granteeAddress: string,
  ): Promise<{ id: string; granteeAddress: string } | null>;
  /** The (owner, builder) slot, revoked or not; null when none exists. */
  findSlot(owner: string, granteeId: string): Promise<GatewaySlot | null>;
  getSlot(permissionId: string): Promise<GatewaySlot | null>;
  registerSlot(
    body: Record<string, unknown>,
    signature: string,
  ): Promise<GatewayAnswer>;
  revokeSlot(
    permissionId: string,
    body: Record<string, unknown>,
    signature: string,
  ): Promise<GatewayAnswer>;
  putScopeBindings(
    owner: string,
    bindings: PdppScopeBinding[],
  ): Promise<GatewayAnswer>;
  /** null when the gateway does not know the grant (404). Throws on outage. */
  getChainBinding(
    owner: string,
    pdppGrantId: string,
  ): Promise<GatewayChainBinding[] | null>;
}

export interface PdppScopeBinding {
  scope: string;
  sourceId: string;
  streams: string[];
}

export interface GatewaySigner {
  /** EIP-191 signer for Web3Signed request headers (the server account). */
  signMessage(message: string): Promise<`0x${string}`>;
}

async function readJson(response: Response): Promise<Record<string, unknown>> {
  const body: unknown = await response.json().catch(() => ({}));
  return body && typeof body === "object" && !Array.isArray(body)
    ? (body as Record<string, unknown>)
    : {};
}

function unwrap(body: Record<string, unknown>): unknown {
  return "data" in body ? body.data : body;
}

/** HTTP client for the gateway routes design 2 uses. `fetch` is injectable. */
export function createPdppChainGateway(options: {
  gatewayUrl: string;
  signer: GatewaySigner;
  fetch?: typeof fetch;
  /** Per-request timeout, so one hung call cannot stall the queue (F4). */
  timeoutMs?: number;
}): PdppChainGateway {
  const base = options.gatewayUrl.replace(/\/+$/u, "");
  const aud = new URL(base).origin;
  const rawFetch = options.fetch ?? globalThis.fetch;
  const timeoutMs = options.timeoutMs ?? 10_000;
  const doFetch = (url: string, init: RequestInit = {}) =>
    rawFetch(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
  const signed = (method: string, uri: string, body?: string) =>
    buildWeb3SignedHeader({
      signMessage: (m) => options.signer.signMessage(m),
      aud,
      method,
      uri,
      ...(body !== undefined && {
        bodyHash: `sha256:${createHash("sha256").update(body).digest("hex")}`,
      }),
    });
  const getJson = async (path: string): Promise<unknown | null> => {
    const response = await doFetch(`${base}${path}`, { cache: "no-store" });
    if (response.status === 404) return null;
    if (!response.ok) throw new Error(`gateway ${path}: ${response.status}`);
    return unwrap(await readJson(response));
  };
  const send = async (
    method: string,
    path: string,
    body: Record<string, unknown>,
    authorization: string,
  ): Promise<GatewayAnswer> => {
    const response = await doFetch(`${base}${path}`, {
      method,
      headers: { "content-type": "application/json", authorization },
      body: JSON.stringify(body),
    });
    return { status: response.status, body: await readJson(response) };
  };
  return {
    async getBuilder(granteeAddress) {
      const data = (await getJson(
        `/v1/builders/${encodeURIComponent(granteeAddress)}`,
      )) as { id?: unknown; granteeAddress?: unknown } | null;
      if (!data || typeof data.id !== "string") return null;
      return {
        id: data.id,
        granteeAddress:
          typeof data.granteeAddress === "string"
            ? data.granteeAddress
            : granteeAddress,
      };
    },
    async findSlot(owner, granteeId) {
      const query = new URLSearchParams({
        user: owner,
        builder: granteeId,
        active: "false",
      });
      const data = (await getJson(`/v1/grants?${query}`)) as {
        grants?: GatewaySlot[];
      } | null;
      return data?.grants?.[0] ?? null;
    },
    async getSlot(permissionId) {
      return (await getJson(
        `/v1/grants/${encodeURIComponent(permissionId)}`,
      )) as GatewaySlot | null;
    },
    registerSlot(body, signature) {
      return send("POST", "/v1/grants", body, `Web3Signed ${signature}`);
    },
    revokeSlot(permissionId, body, signature) {
      return send(
        "DELETE",
        `/v1/grants/${encodeURIComponent(permissionId)}`,
        body,
        `Web3Signed ${signature}`,
      );
    },
    async putScopeBindings(owner, bindings) {
      const body = { ownerAddress: owner, bindings };
      const text = JSON.stringify(body);
      return send(
        "PUT",
        "/v1/pdpp/scope-bindings",
        body,
        await signed("PUT", "/v1/pdpp/scope-bindings", text),
      );
    },
    async getChainBinding(owner, pdppGrantId) {
      const query = new URLSearchParams({
        user: owner.toLowerCase(),
        grantId: pdppGrantId,
      });
      const uri = `/v1/pdpp/chain-binding?${query}`;
      const response = await doFetch(`${base}${uri}`, {
        headers: { authorization: await signed("GET", uri) },
        cache: "no-store",
      });
      if (response.status === 404) return null;
      if (!response.ok)
        throw new Error(`gateway chain-binding: ${response.status}`);
      const data = unwrap(await readJson(response)) as {
        bindings?: GatewayChainBinding[];
      };
      return data.bindings ?? [];
    },
  };
}

// ─── Registrar ────────────────────────────────────────────────────────────

/** The GrantRegistration message the owner's server signs (EIP-712). */
export interface GrantRegistrationToSign {
  grantorAddress: `0x${string}`;
  granteeId: `0x${string}`;
  scopes: string[];
  grantVersion: bigint;
  expiresAt: bigint;
}

/** A PermissionsV2 slot as the chain holds it. */
export interface ChainPermission {
  grantorAddress: string;
  granteeId: string;
  scopes: string[];
  grantVersion: bigint;
  /** Unix seconds; 0 = no expiry. */
  expiresAt: bigint;
}

/**
 * Reads PermissionsV2 directly (not through the gateway). The registrar
 * signs nothing it has not verified here: the gateway's slot view is an
 * unauthenticated answer, so a scope it lists is kept only when this PS owns
 * it or the FINALIZED chain already lists it (review F2), and an entry is
 * ended only when the finalized chain no longer lists it (F5).
 */
export interface PermissionsV2Reader {
  /** `PermissionsV2.domainSeparator()`, for the slot id. */
  domainSeparator(): Promise<`0x${string}`>;
  /** The slot at the finalized block; null when none. Throws on RPC failure. */
  readFinalized(
    slotId: `0x${string}`,
  ): Promise<{ permission: ChainPermission | null; blockTimestamp: bigint }>;
}

const PERMISSIONS_V2_ABI = parseAbi([
  "struct Permission { address grantorAddress; bytes32 granteeId; string[] scopes; uint256 grantVersion; uint256 expiresAt; }",
  "function permissions(bytes32 id) external view returns (Permission)",
  "function domainSeparator() external view returns (bytes32)",
]);

/** The viem reader over the deployment's public RPC. */
export function createPermissionsV2Reader(input: {
  chainId: number;
  contractAddress: `0x${string}`;
  timeoutMs?: number;
}): PermissionsV2Reader {
  const chain = getChainConfig(input.chainId);
  if (!chain) throw new Error(`no RPC for chain ${input.chainId}`);
  const client = createPublicClient({
    chain,
    transport: http(undefined, { timeout: input.timeoutMs ?? 10_000 }),
  });
  let separator: Promise<`0x${string}`> | undefined;
  return {
    domainSeparator() {
      separator ??= client
        .readContract({
          address: input.contractAddress,
          abi: PERMISSIONS_V2_ABI,
          functionName: "domainSeparator",
        })
        .catch((err: unknown) => {
          separator = undefined;
          throw err;
        }) as Promise<`0x${string}`>;
      return separator;
    },
    async readFinalized(slotId) {
      const block = await client.getBlock({ blockTag: "finalized" });
      const p = await client.readContract({
        address: input.contractAddress,
        abi: PERMISSIONS_V2_ABI,
        functionName: "permissions",
        args: [slotId],
        blockNumber: block.number,
      });
      const empty = /^0x0{40}$/iu.test(p.grantorAddress);
      return {
        blockTimestamp: block.timestamp,
        permission: empty
          ? null
          : {
              grantorAddress: p.grantorAddress,
              granteeId: p.granteeId,
              scopes: [...p.scopes],
              grantVersion: p.grantVersion,
              expiresAt: p.expiresAt,
            },
      };
    },
  };
}

/** keccak256(abi.encode(domainSeparator, grantor, granteeId)), as PermissionsV2. */
export function pdppSlotId(
  domainSeparator: `0x${string}`,
  owner: `0x${string}`,
  granteeId: `0x${string}`,
): `0x${string}` {
  return keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "address" }, { type: "bytes32" }],
      [domainSeparator, owner, granteeId],
    ),
  );
}

export interface PdppChainRegistrarOptions {
  store: PdppAuthStore;
  gateway: PdppChainGateway;
  chain: PermissionsV2Reader;
  owner: `0x${string}`;
  deployment: { chainId: number; contractAddress: `0x${string}` };
  /** The app's grantee wallet from its client registration; null = none. */
  granteeAddressFor(clientId: string): `0x${string}` | null;
  /** Every gateway label the grant can read, with the streams it touches. */
  scopeBindingsFor(grant: Grant): PdppScopeBinding[];
  signGrantRegistration(msg: GrantRegistrationToSign): Promise<`0x${string}`>;
  logger: Logger;
  now?: () => Date;
  /** After a failed gateway attempt, wait this long before the next. */
  retryBackoffMs?: number;
  /**
   * After this long deferring a new registration behind another surface's
   * settling one (default 24 h), the owner view reports it. See `deferral`.
   */
  maxDeferralMs?: number;
  /** The token service's access-token TTL (default 1 h); see `grantEnded`. */
  accessTokenTtlSeconds?: number;
}

/** Registration outcomes that are still in progress at the gateway. */
const SETTLING = new Set(["pending", "sent", "confirmed"]);

const IN_FLIGHT = new Set(["SETTLEMENT_IN_FLIGHT", "REVOCATION_IN_FLIGHT"]);
/** The gateway's per-request limits on PUT /v1/pdpp/scope-bindings. */
const MAX_BINDING_STREAMS = 64;

function grantExpirySeconds(grant: Grant): bigint {
  if (!grant.expires_at) return 0n;
  return BigInt(Math.ceil(Date.parse(grant.expires_at) / 1000));
}

/** The later of two expiries, 0 meaning none. */
function laterExpiry(a: bigint, b: bigint): bigint {
  if (a === 0n || b === 0n) return 0n;
  return a > b ? a : b;
}

/** The earlier of two expiries, 0 meaning none. */
function earlierExpiry(a: bigint, b: bigint): bigint {
  if (a === 0n) return b;
  if (b === 0n) return a;
  return a < b ? a : b;
}

function slotLive(slot: GatewaySlot | null): slot is GatewaySlot {
  return !!slot && slot.revokedAt === null && !slot.expired;
}

function describe(answer: GatewayAnswer): string {
  const code = typeof answer.body.code === "string" ? answer.body.code : "";
  const error = typeof answer.body.error === "string" ? answer.body.error : "";
  return `gateway ${answer.status}${code ? ` ${code}` : ""}${error ? `: ${error}` : ""}`;
}

export class PdppChainRegistrar {
  /** One gateway conversation at a time: every write moves one slot version. */
  private queue: Promise<unknown> = Promise.resolve();
  private timer: ReturnType<typeof setInterval> | undefined;
  private reconciling: Promise<void> | undefined;

  constructor(private readonly options: PdppChainRegistrarOptions) {}

  private now(): Date {
    return this.options.now?.() ?? new Date();
  }

  private serial<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.queue.then(fn, fn);
    this.queue = run.catch(() => undefined);
    return run;
  }

  granteeAddressFor(clientId: string): `0x${string}` | null {
    return this.options.granteeAddressFor(clientId);
  }

  /**
   * The pending registration for a grant about to be stored: a fresh salt
   * and the entry over the exact grant document (the client's view). Null
   * when the client has no grantee address, so no slot can carry the grant.
   */
  prepare(
    grant: Grant,
  ): { granteeAddress: string; salt: string; entry: string } | null {
    const granteeAddress = this.options.granteeAddressFor(
      grant.client.client_id,
    );
    if (!granteeAddress) return null;
    const salt = newPdppGrantSalt();
    return { granteeAddress, salt, entry: computePdppGrantEntry(grant, salt) };
  }

  /** Register a pending grant now (no backoff). Resolves to its state. */
  register(grantId: string): Promise<ChainRegistration["status"] | null> {
    return this.serial(() => this.guarded(grantId, () => this.registerNow(grantId, true)));
  }

  /** Register a pending grant unless a failed attempt is backing off. */
  retry(grantId: string): Promise<ChainRegistration["status"] | null> {
    return this.serial(() =>
      this.guarded(grantId, () => this.registerNow(grantId, false)),
    );
  }

  /**
   * Turning chain grants on for a server with existing grants: every active
   * locked-rule grant with no registration gets a pending one (fresh salt,
   * entry over the client's document), so its reads answer "retry" until it
   * is on chain instead of `grant_revoked`. A grant whose client has no
   * grantee address gets none and stays unreadable (stated in the report).
   */
  backfill(): number {
    const { store } = this.options;
    const now = this.now();
    let created = 0;
    for (const stored of store.listAllGrants()) {
      // Locked-rule and v0.2 grants are both served under the chain gate.
      if (!grantUsesLockedRules(stored.grant) && !isV02Grant(stored.grant))
        continue;
      if (store.grantStatus(stored, now) !== "active") continue;
      if (store.getChainRegistration(stored.grant.grant_id)) continue;
      const prepared = this.prepare(store.clientGrantView(stored));
      if (!prepared) continue;
      if (
        store.createChainRegistration({
          grantId: stored.grant.grant_id,
          clientId: stored.clientId,
          ...prepared,
          now,
        })
      )
        created++;
    }
    return created;
  }

  /** Reconcile now and every `intervalMs` until `stop()` (unref'd timer). */
  start(intervalMs = 60_000): void {
    if (this.timer) return;
    void this.reconcile().catch(() => undefined);
    this.timer = setInterval(() => {
      void this.reconcile().catch(() => undefined);
    }, intervalMs);
    this.timer.unref?.();
  }

  /** Stop the timer and wait for the conversation in progress. */
  async stop(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    await this.queue.catch(() => undefined);
  }

  /** Whether the grant can no longer be read by its client at all. */
  private grantEnded(grantId: string, now: Date): boolean {
    const { store } = this.options;
    const stored = store.getGrant(grantId);
    if (!stored || store.grantStatus(stored, now) !== "active") return true;
    // A consumed single-use grant ends once its last access token is gone.
    return (
      stored.grant.access_mode === "single_use" &&
      stored.consumedAt !== null &&
      !store.hasLiveClientToken(
        grantId,
        now,
        this.options.accessTokenTtlSeconds,
      )
    );
  }

  /**
   * Move every registration to where its grant is: a grant that ended has
   * its entry removed, a pending one is registered, an ending one is
   * followed to finality on chain, and a bound one whose registration failed
   * at the gateway is registered again.
   */
  reconcile(): Promise<void> {
    // One reconcile at a time: a call while one is queued or running joins it.
    if (this.reconciling) return this.reconciling;
    const run = this.serial(async () => {
      const { store } = this.options;
      const now = this.now();
      for (const reg of store.listChainRegistrations(["pending", "bound"]))
        if (this.grantEnded(reg.grantId, now))
          store.markChainEnding(reg.grantId, now);
      for (const reg of store.listChainRegistrations(["bound"]))
        await this.guarded(reg.grantId, () => this.recheckBound(reg));
      for (const reg of store.listChainRegistrations(["pending"]))
        await this.guarded(reg.grantId, () => this.registerNow(reg.grantId, false));
      for (const reg of store.listChainRegistrations(["ending"]))
        await this.guarded(reg.grantId, () => this.endNow(reg.grantId, false));
    });
    this.reconciling = run.finally(() => {
      this.reconciling = undefined;
    });
    return this.reconciling;
  }

  private async guarded<T>(grantId: string, fn: () => Promise<T>): Promise<T | null> {
    try {
      return await fn();
    } catch (err) {
      this.options.store.noteChainError(
        grantId,
        (err as Error).message,
        this.now(),
      );
      this.options.logger.warn(
        { grantId, err: (err as Error).message },
        "PDPP chain registration: gateway or chain unreachable",
      );
      return null;
    }
  }

  /** A failed attempt waits out the backoff, so reads do not spend versions. */
  private backingOff(reg: ChainRegistration): boolean {
    if (!reg.lastError) return false;
    const wait = this.options.retryBackoffMs ?? 30_000;
    return this.now().getTime() - Date.parse(reg.updatedAt) < wait;
  }

  private async slotIdFor(granteeId: string): Promise<`0x${string}`> {
    return pdppSlotId(
      await this.options.chain.domainSeparator(),
      this.options.owner,
      granteeId as `0x${string}`,
    );
  }

  /** Entries of this PS's own live grants for this grantee (not ending). */
  private ownEntries(granteeAddress: string, except?: string): Map<string, Grant> {
    const { store } = this.options;
    const out = new Map<string, Grant>();
    for (const reg of store.listChainRegistrations(["pending", "bound"])) {
      if (reg.grantId === except) continue;
      if (reg.granteeAddress.toLowerCase() !== granteeAddress.toLowerCase())
        continue;
      const stored = store.getGrant(reg.grantId);
      if (stored) out.set(reg.entry, stored.grant);
    }
    return out;
  }

  /**
   * Entries of this PS's grants that ended (`ending` or `ended`): never
   * signed again, whatever the gateway or even the finalized chain lists
   * while their removal is in flight (review N4).
   */
  private endedEntries(except?: string): Set<string> {
    return new Set(
      this.options.store
        .listChainRegistrations(["ending", "ended"])
        .filter((r) => r.grantId !== except)
        .map((r) => r.entry),
    );
  }

  /**
   * One PUT per label, so a label the gateway already holds with another
   * stream set (409, bindings are immutable) cannot drop the others. A label
   * over the gateway's stream limit is not sent. Returns the labels not bound.
   */
  private async bindScopes(grantId: string, bindings: PdppScopeBinding[]): Promise<string[]> {
    const { gateway, owner, logger } = this.options;
    const unbound: string[] = [];
    for (const binding of bindings) {
      if (binding.streams.length > MAX_BINDING_STREAMS) {
        unbound.push(binding.scope);
        continue;
      }
      const answer = await gateway.putScopeBindings(owner, [binding]);
      if (answer.status >= 200 && answer.status < 300) continue;
      unbound.push(binding.scope);
      if (answer.status === 409)
        logger.warn(
          { grantId, scope: binding.scope },
          "PDPP chain registration: a scope label is already bound to another stream set",
        );
      else if (answer.status >= 500 || answer.status === 401 || answer.status === 403)
        throw new Error(`scope bindings: ${describe(answer)}`);
    }
    return unbound;
  }

  /**
   * New registrations only (a grant end never waits). The PS must never drop
   * a scope another surface (Account, MCP, another device) is still settling. When the gateway lists scopes for the slot
   * that are neither this PS's own entries nor on the finalized chain, and
   * the slot's latest registration is still in progress, the PS defers its
   * write and retries on the reconcile timer, until that registration is
   * finalized (its scopes are then on the finalized chain and are kept) or
   * has failed or reverted (they are then not kept: they never took effect).
   *
   * Bounded visibility, not a bounded wait (decided): after `maxDeferralMs`
   * (24 h) the PS still does not sign over the other scope. It logs once and
   * the owner sees `waiting_on_other_grant` with that registration's outcome
   * on GET /pdpp/v1/grants. Returns the reason to defer, or null.
   */
  private deferral(
    reg: ChainRegistration,
    slot: GatewaySlot | null,
    own: Map<string, Grant>,
    onChain: Set<string>,
  ): string | null {
    const { store } = this.options;
    const ended = this.endedEntries(reg.grantId);
    const unsettled = (slot?.scopes ?? []).filter(
      (s) =>
        s !== reg.entry && !own.has(s) && !ended.has(s) && !onChain.has(s),
    );
    // R2: a gateway older than 129b16e sends no `registrationOutcome`; a
    // listed scope the finalized chain lacks is then treated as settling.
    const settling =
      !!slot &&
      slot.revokedAt === null &&
      (slot.registrationOutcome === undefined ||
        slot.registrationOutcome === null ||
        SETTLING.has(slot.registrationOutcome));
    if (!settling || unsettled.length === 0) {
      if (reg.deferredSince) store.noteChainDeferral(reg.grantId, null);
      return null;
    }
    const outcome = slot!.registrationOutcome ?? "unknown";
    const since = store.noteChainDeferral(reg.grantId, this.now(), outcome);
    const waited = this.now().getTime() - Date.parse(since ?? "");
    if (waited > (this.options.maxDeferralMs ?? 24 * 60 * 60 * 1000)) {
      // Decided: never sign over another surface's settling scope, even after
      // the bound. The grant stays pending (reads: retry later) and the owner
      // sees `waiting_on_other_grant` on GET /pdpp/v1/grants. Warn once.
      if (!reg.lastError?.startsWith("deferred past bound"))
        this.options.logger.warn(
          { grantId: reg.grantId, unsettled: unsettled.length, outcome },
          "PDPP chain registration: another registration for this app has not settled within the bound; still waiting",
        );
      return `deferred past bound: another registration for this slot is ${outcome} (${unsettled.length} scope(s) not yet final)`;
    }
    return `deferred: another registration for this slot is ${outcome} (${unsettled.length} scope(s) not yet final)`;
  }

  private async registerNow(
    grantId: string,
    force: boolean,
  ): Promise<ChainRegistration["status"] | null> {
    const { store, gateway, owner, chain } = this.options;
    const reg = store.getChainRegistration(grantId);
    if (!reg || reg.status !== "pending") return reg?.status ?? null;
    if (!force && this.backingOff(reg)) return "pending";
    if (this.grantEnded(grantId, this.now())) {
      store.markChainEnding(grantId, this.now());
      return "ending";
    }
    const stored = store.getGrant(grantId)!;
    const document = store.clientGrantView(stored);

    const builder = await gateway.getBuilder(reg.granteeAddress);
    if (!builder) {
      store.noteChainError(grantId, "grantee is not a registered builder", this.now());
      return "pending";
    }
    const unbound = await this.bindScopes(
      grantId,
      this.options.scopeBindingsFor(stored.grant),
    );
    const slotId = await this.slotIdFor(builder.id);

    for (let attempt = 0; attempt < 2; attempt++) {
      const slot = await gateway.getSlot(slotId);
      if (slot && slot.id.toLowerCase() !== slotId.toLowerCase()) {
        store.noteChainError(grantId, "gateway answered for another slot id", this.now());
        return "pending";
      }
      const { permission } = await chain.readFinalized(slotId);
      const listed = slotLive(slot) ? slot.scopes : [];
      const failedAtGateway = slot?.status === "failed";
      if (listed.includes(reg.entry) && !failedAtGateway) {
        // An earlier attempt landed and its answer was lost.
        store.markChainBound({
          grantId,
          chainId: this.options.deployment.chainId,
          contractAddress: this.options.deployment.contractAddress,
          permissionId: slotId,
          granteeId: builder.id,
          registeredVersion: slot!.grantVersion,
          now: this.now(),
        });
        return "bound";
      }
      // F2: keep only what this PS owns or the finalized chain already holds;
      // a scope only the gateway claims is dropped (never added).
      const own = this.ownEntries(reg.granteeAddress, grantId);
      const onChain = new Set(permission?.scopes ?? []);
      const deferred = this.deferral(reg, slot, own, onChain);
      if (deferred) {
        store.noteChainError(grantId, deferred, this.now());
        return "pending";
      }
      const ended = this.endedEntries();
      const kept = listed.filter(
        (s) =>
          s !== reg.entry &&
          !ended.has(s) &&
          (own.has(s) || onChain.has(s)),
      );
      const foreign = kept.filter((s) => !own.has(s));
      // F1: never extend a scope this grant does not cover. With a foreign
      // scope in the slot, the slot keeps the earliest of its gateway and
      // finalized-chain expiry, and this grant is cut off on chain at that
      // time if it would last longer. With only this PS's own entries, the
      // slot lasts as long as the longest of those grants (each is also
      // bounded by its own `expires_at` at the PS and at the gateway).
      const expiresAt =
        foreign.length > 0
          ? earlierExpiry(
              BigInt(slot!.expiresAtSeconds),
              permission?.expiresAt ?? 0n,
            )
          : [...kept.map((e) => own.get(e)!), stored.grant]
              .map(grantExpirySeconds)
              .reduce((a, b) => laterExpiry(a, b));
      const scopes = [...kept, reg.entry];
      const grantVersion =
        (slot ? BigInt(slot.currentGrantVersion) : 0n) + 1n;
      const signature = await this.options.signGrantRegistration({
        grantorAddress: owner,
        granteeId: builder.id as `0x${string}`,
        scopes,
        grantVersion,
        expiresAt,
      });
      const answer = await gateway.registerSlot(
        {
          grantorAddress: owner,
          granteeId: builder.id,
          scopes,
          grantVersion: grantVersion.toString(),
          expiresAt: expiresAt.toString(),
          pdppGrants: [{ entry: reg.entry, grant: document, salt: reg.salt }],
        },
        signature,
      );
      if (answer.status === 200 || answer.status === 201) {
        store.markChainBound({
          grantId,
          chainId: this.options.deployment.chainId,
          contractAddress: this.options.deployment.contractAddress,
          permissionId: slotId,
          granteeId: builder.id,
          registeredVersion:
            typeof answer.body.grantVersion === "string"
              ? answer.body.grantVersion
              : grantVersion.toString(),
          now: this.now(),
        });
        if (unbound.length > 0)
          store.noteChainError(
            grantId,
            `bound; scope labels not bound at the gateway: ${unbound.join(", ")}`,
            this.now(),
          );
        return "bound";
      }
      // 409: another write moved the slot; read it again and sign above it.
      if (answer.status === 409 && attempt === 0) continue;
      store.noteChainError(
        grantId,
        IN_FLIGHT.has(String(answer.body.code))
          ? `slot is settling; retry later (${describe(answer)})`
          : `registration: ${describe(answer)}`,
        this.now(),
      );
      return "pending";
    }
    return "pending";
  }

  /**
   * A bound grant whose registration failed at the gateway (the transaction
   * did not land) and that the finalized chain does not list is registered
   * again.
   */
  private async recheckBound(reg: ChainRegistration): Promise<void> {
    const { store, gateway, chain } = this.options;
    if (!reg.permissionId) return;
    const slot = await gateway.getSlot(reg.permissionId);
    if (slot?.status !== "failed") return;
    const { permission } = await chain.readFinalized(
      reg.permissionId as `0x${string}`,
    );
    if (permission?.scopes.includes(reg.entry)) return;
    store.markChainPending(reg.grantId, this.now());
  }

  /** True when the finalized chain no longer lets the entry authorize. */
  private static endedOnChain(
    read: { permission: ChainPermission | null; blockTimestamp: bigint },
    entry: string,
  ): boolean {
    const p = read.permission;
    if (!p) return true;
    if (!p.scopes.includes(entry)) return true;
    return p.expiresAt !== 0n && p.expiresAt <= read.blockTimestamp;
  }

  private async endNow(grantId: string, force: boolean): Promise<void> {
    const { store, gateway, owner, chain } = this.options;
    const reg = store.getChainRegistration(grantId);
    if (!reg || reg.status !== "ending") return;
    if (!force && reg.endedVersion === null && this.backingOff(reg)) return;

    let granteeId = reg.granteeId;
    if (!granteeId) {
      const builder = await gateway.getBuilder(reg.granteeAddress);
      if (!builder) {
        // No builder: no slot can hold the entry, unless the chain says so.
        store.noteChainError(grantId, "grantee is not a registered builder", this.now());
        return;
      }
      granteeId = builder.id;
    }
    const slotId = await this.slotIdFor(granteeId);
    const read = await chain.readFinalized(slotId);
    // F5: `ended` only when the FINALIZED chain no longer lists the entry.
    if (PdppChainRegistrar.endedOnChain(read, reg.entry)) {
      store.markChainEnded(grantId, this.now());
      return;
    }

    const slot = await gateway.getSlot(slotId);
    if (!slot) {
      store.noteChainError(grantId, "entry on chain but the gateway knows no slot", this.now());
      return;
    }
    // N1: a second writer (e.g. Account signing from a stale read) put the
    // entry back on the finalized chain at a version above the end this PS
    // sent: that end is lost and is signed again.
    // R1: the same when the GATEWAY slot lists it again above that version
    // (a second writer's upsert that may never settle on chain).
    const reAdded =
      reg.endedVersion !== null &&
      ((read.permission !== null &&
        read.permission.scopes.includes(reg.entry) &&
        read.permission.grantVersion > BigInt(reg.endedVersion)) ||
        (slot.scopes.includes(reg.entry) &&
          BigInt(slot.grantVersion) > BigInt(reg.endedVersion)));
    const failed =
      reAdded ||
      slot.status === "failed" ||
      slot.revocationKind === "v2_reverted" ||
      slot.revocationOutcome === "superseded";
    // Something that drops the entry is already in flight at the gateway (an
    // upsert this PS sent, possibly before a crash, or an owner revocation):
    // wait for it to reach the chain. Only a failed one is signed again.
    const inFlight =
      !failed &&
      (reg.endedVersion !== null ||
        !slot.scopes.includes(reg.entry) ||
        (slot.revokedAt !== null && slot.revocationKind === "v2_upsert"));
    if (inFlight) return;

    // An ended grant never waits (decided): the owner's revocation outranks
    // another surface's registration still settling in this slot. The PS
    // signs at once over its own live entries plus finalized-chain scopes,
    // which overtakes that registration: the other grant must be signed
    // again by its surface. The PS's own pending registrations for this
    // slot are re-queued so they register on top of this write.
    const own = this.ownEntries(reg.granteeAddress, grantId);
    const onChain = new Set(read.permission?.scopes ?? []);
    const ended = this.endedEntries(grantId);
    const verified = (s: string) =>
      !ended.has(s) && (own.has(s) || onChain.has(s));
    const overtaken = slot.scopes.filter(
      (s) => s !== reg.entry && !verified(s),
    );
    // The PS's own bound entries are always kept, also when the gateway's
    // view does not list them (their documents are stored there already).
    const listedVerified = slot.scopes.filter(
      (e) => e !== reg.entry && verified(e),
    );
    const ownBound = store
      .listChainRegistrations(["bound"])
      .filter(
        (r) =>
          r.grantId !== grantId &&
          r.granteeAddress.toLowerCase() === reg.granteeAddress.toLowerCase() &&
          !listedVerified.includes(r.entry),
      )
      .map((r) => r.entry);
    const remaining = [...listedVerified, ...ownBound];
    const revocation = remaining.length === 0 || slot.revokedAt !== null;
    // A V2 revocation lists a non-empty subset of the gateway's scopes and a
    // past expiry; a removal-only upsert keeps the earliest known expiry, so
    // nothing it keeps outlives its terms (F1).
    const scopes = revocation
      ? slot.scopes.filter(verified)
      : remaining;
    if (scopes.length === 0) {
      store.noteChainError(grantId, "no verified scope to sign a revocation over", this.now());
      return;
    }
    const expiresAt = revocation
      ? BigInt(Math.floor(this.now().getTime() / 1000) - 300)
      : earlierExpiry(
          BigInt(slot.expiresAtSeconds),
          read.permission?.expiresAt ?? 0n,
        );
    const grantVersion = BigInt(slot.currentGrantVersion) + 1n;
    const signature = await this.options.signGrantRegistration({
      grantorAddress: owner,
      granteeId: granteeId as `0x${string}`,
      scopes,
      grantVersion,
      expiresAt,
    });
    const body = {
      grantorAddress: owner,
      grantVersion: grantVersion.toString(),
      scopes,
      expiresAt: expiresAt.toString(),
    };
    const answer = revocation
      ? await gateway.revokeSlot(slotId, body, signature)
      : await gateway.registerSlot({ ...body, granteeId }, signature);
    if (answer.status >= 200 && answer.status < 300) {
      store.noteChainEndingSent(
        grantId,
        grantVersion.toString(),
        revocation ? "revocation" : "removal",
        this.now(),
      );
      if (overtaken.length > 0)
        this.options.logger.warn(
          { grantId, overtaken: overtaken.length },
          "PDPP chain: grant end overtook a registration still settling in this slot; that grant must be signed again",
        );
      for (const pending of store.listChainRegistrations(["pending"]))
        if (
          pending.granteeAddress.toLowerCase() ===
          reg.granteeAddress.toLowerCase()
        )
          store.requeueChainRegistration(pending.grantId);
      return;
    }
    store.noteChainError(grantId, `end: ${describe(answer)}`, this.now());
  }
}

// ─── Read gate ────────────────────────────────────────────────────────────

/**
 * The chain check for PDPP client reads under design 2 (Vana-6.1: reads are
 * chain-enforced). Implements the same port as the version-bound adapter in
 * `chain-enforcement.ts`, which cannot serve design 2: there every new grant
 * in a slot moves the slot version and would invalidate all earlier
 * bindings, while here each grant is checked by its own entry.
 */
export function design2ChainEnforcement(options: {
  store: PdppAuthStore;
  registrar: PdppChainRegistrar;
  gateway: PdppChainGateway;
  owner: `0x${string}`;
  deployment: { chainId: number; contractAddress: `0x${string}` };
  logger: Logger;
}): PdppChainEnforcementPort {
  const deny = (reason: string, retryable = false): PdppChainDecision => ({
    ok: false,
    reason,
    retryable,
  });
  return {
    async authorize({ clientId, pdppGrantId }) {
      let reg = options.store.getChainRegistration(pdppGrantId);
      if (!reg) return deny("No chain binding for this grant");
      const grantee = options.registrar.granteeAddressFor(clientId);
      if (!grantee || grantee.toLowerCase() !== reg.granteeAddress.toLowerCase())
        return deny("Client is not the bound grantee for this grant");
      if (reg.status === "pending") {
        try {
          await options.registrar.retry(pdppGrantId);
        } catch (err) {
          options.logger.warn(
            { pdppGrantId, err: (err as Error).message },
            "PDPP chain gate: registration retry failed",
          );
        }
        reg = options.store.getChainRegistration(pdppGrantId)!;
        if (reg.status === "pending")
          return deny("Grant is not yet registered on chain", true);
      }
      if (reg.status !== "bound")
        return deny("Grant's chain entry has been removed");
      if (
        reg.chainId !== options.deployment.chainId ||
        reg.contractAddress?.toLowerCase() !==
          options.deployment.contractAddress.toLowerCase()
      )
        return deny("Binding is for a different chain deployment");

      let bindings: GatewayChainBinding[] | null;
      try {
        bindings = await options.gateway.getChainBinding(
          options.owner,
          pdppGrantId,
        );
      } catch (err) {
        options.logger.warn(
          { pdppGrantId, err: (err as Error).message },
          "PDPP chain gate: could not read chain binding",
        );
        return deny("Chain grant could not be read", true);
      }
      if (bindings === null) return deny("Gateway does not know this grant");
      const binding = bindings.find(
        (b) =>
          b.permissionId === reg!.permissionId &&
          b.entry === reg!.entry &&
          String(b.chainId) === String(options.deployment.chainId) &&
          b.contractAddress.toLowerCase() ===
            options.deployment.contractAddress.toLowerCase(),
      );
      if (!binding) return deny("Chain binding does not match this grant");
      const atGateway =
        binding.gateway.entryListed &&
        !binding.gateway.slotRevoked &&
        !binding.gateway.slotExpired &&
        !binding.pdppExpired;
      if (!atGateway) return deny("Grant is revoked or expired at the gateway");
      if (!binding.onChain.entryPresent || !binding.onChain.slotActive)
        // Listed at the gateway but not yet on chain: the registration is
        // still settling. Not knowing yet is not permission.
        return deny("Grant is not yet on chain", true);
      return { ok: true };
    },
  };
}

// ─── Scope labels ─────────────────────────────────────────────────────────

/**
 * The stream-sync physical scopes a grant can read, as gateway bindings:
 * each per-stream row `pdpp.<c>~<ns>.<stream>` names its one stream, and the
 * connection log row `pdpp.<c>~<ns>.~log` names EVERY declared stream of the
 * source, because one log segment carries operations of all of them. So a
 * grant that covers only some streams cannot pay for a log read.
 */
export function streamSyncScopeBindings(input: {
  grant: Grant;
  link: (
    instance: string,
    stream: string,
  ) => { connector: string; namespace: string } | null;
  declaredStreams: (sourceId: string) => string[];
  logScope: (connector: string, ns: string) => string;
  streamScope: (connector: string, ns: string, stream: string) => string;
}): PdppScopeBinding[] {
  const sourceId = input.grant.source.id;
  const out = new Map<string, PdppScopeBinding>();
  for (const stream of input.grant.streams) {
    for (const instance of stream.instance_ids) {
      const linked = input.link(instance, stream.name);
      if (!linked) continue;
      const perStream = input.streamScope(
        linked.connector,
        linked.namespace,
        stream.name,
      );
      out.set(perStream, { scope: perStream, sourceId, streams: [stream.name] });
      const log = input.logScope(linked.connector, linked.namespace);
      if (!out.has(log)) {
        const all = input.declaredStreams(sourceId);
        out.set(log, {
          scope: log,
          sourceId,
          streams: all.length > 0 ? all : [stream.name],
        });
      }
    }
  }
  return [...out.values()];
}


// ─── Host wiring ──────────────────────────────────────────────────────────

/**
 * Build the registrar and read gate for a boot with `pdpp.chainGrants` on.
 * With a prerequisite missing (no owner key, no records deps), it returns
 * the fail-closed pair: approvals are refused and every client read is
 * denied, so turning the setting on can never open reads without the chain.
 */
export function createDesign2ChainGrants(input: {
  store: PdppAuthStore;
  logger: Logger;
  ready:
    | {
        gatewayUrl: string;
        fetch?: typeof fetch;
        /** Defaults to the deployment's public RPC (`createPermissionsV2Reader`). */
        chain?: PermissionsV2Reader;
        /** See `PdppChainRegistrarOptions.retryBackoffMs` (default 30 s). */
        retryBackoffMs?: number;
        /** Per gateway request (default 10 s). */
        timeoutMs?: number;
        /** See `PdppChainRegistrarOptions.maxDeferralMs` (default 24 h). */
        maxDeferralMs?: number;
        owner: `0x${string}`;
        deployment: { chainId: number; contractAddress: `0x${string}` };
        signMessage(message: string): Promise<`0x${string}`>;
        signGrantRegistration(
          msg: GrantRegistrationToSign,
        ): Promise<`0x${string}`>;
        clients: ReadonlyArray<{ clientId: string; granteeAddress?: string }>;
        link?: (
          instance: string,
          stream: string,
        ) => { connector: string; namespace: string } | null;
        declaredStreams(sourceId: string): string[];
        /**
         * Legacy readable scopes this PS projects from a source's PDPP
         * streams (`LEGACY_SCOPE_BINDINGS`): each is bound to every stream
         * its projection reads, so a paid read of it needs one grant that
         * covers all of them (gateway pay rule).
         */
        legacyScopes?: (sourceId: string) => Array<{ scope: string; streams: string[] }>;
        logScope(connector: string, ns: string): string;
        streamScope(connector: string, ns: string, stream: string): string;
      }
    | null;
}): {
  registrar: Pick<
    PdppChainRegistrar,
    "prepare" | "register" | "reconcile" | "backfill" | "start" | "stop"
  >;
  gate: PdppChainEnforcementPort;
} {
  const { ready } = input;
  if (!ready) {
    input.logger.warn(
      "pdpp.chainGrants is on but this boot cannot register grants (owner key or records missing): PDPP approvals are refused and client reads denied",
    );
    return {
      registrar: {
        prepare: () => null,
        register: async () => null,
        reconcile: async () => undefined,
        backfill: () => 0,
        start: () => undefined,
        stop: async () => undefined,
      },
      gate: {
        authorize: async () => ({
          ok: false,
          retryable: false,
          reason: "Chain grants are not available on this server",
        }),
      },
    };
  }
  const gateway = createPdppChainGateway({
    gatewayUrl: ready.gatewayUrl,
    signer: { signMessage: ready.signMessage },
    fetch: ready.fetch,
    ...(ready.timeoutMs !== undefined && { timeoutMs: ready.timeoutMs }),
  });
  const registrar = new PdppChainRegistrar({
    store: input.store,
    gateway,
    chain:
      ready.chain ??
      createPermissionsV2Reader({
        chainId: ready.deployment.chainId,
        contractAddress: ready.deployment.contractAddress,
      }),
    owner: ready.owner,
    deployment: ready.deployment,
    granteeAddressFor: (clientId) => {
      const address = ready.clients.find(
        (c) => c.clientId === clientId,
      )?.granteeAddress;
      return address ? (address as `0x${string}`) : null;
    },
    scopeBindingsFor: (grant) => {
      const declared = new Set(ready.declaredStreams(grant.source.id));
      return [
        ...(ready.link
          ? streamSyncScopeBindings({
              grant,
              link: ready.link,
              declaredStreams: ready.declaredStreams,
              logScope: ready.logScope,
              streamScope: ready.streamScope,
            })
          : []),
        // Only legacy scopes whose streams the retained declaration has.
        ...(ready.legacyScopes?.(grant.source.id) ?? [])
          .filter((l) => l.streams.every((st) => declared.has(st)))
          .map((l) => ({
            scope: l.scope,
            sourceId: grant.source.id,
            streams: l.streams,
          })),
      ];
    },
    signGrantRegistration: ready.signGrantRegistration,
    logger: input.logger,
    ...(ready.retryBackoffMs !== undefined && {
      retryBackoffMs: ready.retryBackoffMs,
    }),
    ...(ready.maxDeferralMs !== undefined && {
      maxDeferralMs: ready.maxDeferralMs,
    }),
  });
  return {
    registrar,
    gate: design2ChainEnforcement({
      store: input.store,
      registrar,
      gateway,
      owner: ready.owner,
      deployment: ready.deployment,
      logger: input.logger,
    }),
  };
}
