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
import type {
  ChainRegistration,
  Grant,
  PdppAuthStore,
} from "@opendatalabs/personal-server-ts-core/pdpp";
import { buildWeb3SignedHeader } from "@opendatalabs/vana-sdk/browser";
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
}): PdppChainGateway {
  const base = options.gatewayUrl.replace(/\/+$/u, "");
  const aud = new URL(base).origin;
  const doFetch = options.fetch ?? globalThis.fetch;
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

export interface PdppChainRegistrarOptions {
  store: PdppAuthStore;
  gateway: PdppChainGateway;
  owner: `0x${string}`;
  deployment: { chainId: number; contractAddress: `0x${string}` };
  /** The app's grantee wallet from its client registration; null = none. */
  granteeAddressFor(clientId: string): `0x${string}` | null;
  /** Every gateway label the grant can read, with the streams it touches. */
  scopeBindingsFor(grant: Grant): PdppScopeBinding[];
  signGrantRegistration(msg: GrantRegistrationToSign): Promise<`0x${string}`>;
  logger: Logger;
  now?: () => Date;
}

const IN_FLIGHT = new Set(["SETTLEMENT_IN_FLIGHT", "REVOCATION_IN_FLIGHT"]);

function grantExpirySeconds(grant: Grant): bigint {
  if (!grant.expires_at) return 0n;
  return BigInt(Math.ceil(Date.parse(grant.expires_at) / 1000));
}

function laterExpiry(a: bigint, b: bigint): bigint {
  if (a === 0n || b === 0n) return 0n;
  return a > b ? a : b;
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
   * and the entry over the exact grant document. Null when the client has no
   * grantee address, so no slot can carry the grant.
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

  /** Register a pending grant. Resolves to its registration state. */
  register(grantId: string): Promise<ChainRegistration["status"] | null> {
    return this.serial(() => this.registerNow(grantId));
  }

  /**
   * Move every registration to where its grant is: a grant that ended has
   * its entry removed, a pending one is registered, an ending one is
   * followed to finality.
   */
  reconcile(): Promise<void> {
    return this.serial(async () => {
      const { store } = this.options;
      const now = this.now();
      for (const reg of store.listChainRegistrations(["pending", "bound"])) {
        const stored = store.getGrant(reg.grantId);
        if (!stored || store.grantStatus(stored, now) !== "active")
          store.markChainEnding(reg.grantId, now);
      }
      for (const reg of store.listChainRegistrations(["pending"]))
        await this.guard(reg.grantId, () => this.registerNow(reg.grantId));
      for (const reg of store.listChainRegistrations(["ending"]))
        await this.guard(reg.grantId, () => this.endNow(reg.grantId));
    });
  }

  private async guard(grantId: string, fn: () => Promise<unknown>) {
    try {
      await fn();
    } catch (err) {
      this.options.store.noteChainError(
        grantId,
        (err as Error).message,
        this.now(),
      );
      this.options.logger.warn(
        { grantId, err: (err as Error).message },
        "PDPP chain registration: gateway unreachable",
      );
    }
  }

  private async registerNow(
    grantId: string,
  ): Promise<ChainRegistration["status"] | null> {
    const { store, gateway, owner, logger } = this.options;
    const reg = store.getChainRegistration(grantId);
    if (!reg || reg.status !== "pending") return reg?.status ?? null;
    const stored = store.getGrant(grantId);
    if (!stored || store.grantStatus(stored, this.now()) !== "active") {
      store.markChainEnding(grantId, this.now());
      return "ending";
    }

    const builder = await gateway.getBuilder(reg.granteeAddress);
    if (!builder) {
      store.noteChainError(grantId, "grantee is not a registered builder");
      return "pending";
    }

    const bindings = this.options.scopeBindingsFor(stored.grant);
    if (bindings.length > 0) {
      const answer = await gateway.putScopeBindings(owner, bindings);
      // Bindings are immutable at the gateway: 409 means a label is already
      // bound (to the same or an earlier stream set). Registration goes on;
      // the conflict is recorded for the operator.
      if (answer.status === 409) {
        logger.warn(
          { grantId, status: answer.status },
          "PDPP chain registration: a scope label was already bound differently",
        );
      } else if (answer.status < 200 || answer.status >= 300) {
        store.noteChainError(grantId, `scope bindings: ${describe(answer)}`);
        return "pending";
      }
    }

    for (let attempt = 0; attempt < 2; attempt++) {
      const slot = await gateway.findSlot(owner, builder.id);
      const kept = slotLive(slot) ? slot.scopes : [];
      if (kept.includes(reg.entry)) {
        // An earlier attempt landed and its answer was lost.
        store.markChainBound({
          grantId,
          chainId: this.options.deployment.chainId,
          contractAddress: this.options.deployment.contractAddress,
          permissionId: slot!.id,
          granteeId: builder.id,
          registeredVersion: slot!.grantVersion,
          now: this.now(),
        });
        return "bound";
      }
      const scopes = [...kept, reg.entry];
      const grantVersion =
        (slot ? BigInt(slot.currentGrantVersion) : 0n) + 1n;
      const expiresAt =
        kept.length > 0
          ? laterExpiry(
              BigInt(slot!.expiresAtSeconds),
              grantExpirySeconds(stored.grant),
            )
          : grantExpirySeconds(stored.grant);
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
          pdppGrants: [
            // The document the entry fingerprints: the client's view.
            { entry: reg.entry, grant: store.clientGrantView(stored), salt: reg.salt },
          ],
        },
        signature,
      );
      if (answer.status === 200 || answer.status === 201) {
        const permissionId = answer.body.grantId;
        if (typeof permissionId !== "string") {
          store.noteChainError(grantId, "gateway returned no grant id");
          return "pending";
        }
        store.markChainBound({
          grantId,
          chainId: this.options.deployment.chainId,
          contractAddress: this.options.deployment.contractAddress,
          permissionId,
          granteeId: builder.id,
          registeredVersion:
            typeof answer.body.grantVersion === "string"
              ? answer.body.grantVersion
              : grantVersion.toString(),
          now: this.now(),
        });
        return "bound";
      }
      // 409: another write moved the slot; read it again and sign above it.
      if (answer.status === 409 && attempt === 0) continue;
      store.noteChainError(
        grantId,
        IN_FLIGHT.has(String(answer.body.code))
          ? `slot is settling; retry later (${describe(answer)})`
          : `registration: ${describe(answer)}`,
      );
      return "pending";
    }
    return "pending";
  }

  private async endNow(grantId: string): Promise<void> {
    const { store, gateway, owner } = this.options;
    const reg = store.getChainRegistration(grantId);
    if (!reg || reg.status !== "ending") return;

    let slot: GatewaySlot | null;
    if (reg.permissionId) {
      slot = await gateway.getSlot(reg.permissionId);
    } else {
      // Never confirmed bound: the registration may still have landed.
      const builder = await gateway.getBuilder(reg.granteeAddress);
      slot = builder ? await gateway.findSlot(owner, builder.id) : null;
    }
    if (!slot) {
      store.markChainEnded(grantId, this.now());
      return;
    }

    // Follow an upsert already sent to finality before sending another.
    if (reg.endedVersion !== null) {
      const done = this.endingFinal(reg, slot);
      if (done === "final") {
        store.markChainEnded(grantId, this.now());
        return;
      }
      if (done === "waiting") return;
      // "resign": the revocation reverted or was superseded on chain.
    }

    // Nothing to send: the entry is not in the slot, or the whole slot was
    // already revoked on chain by someone else (owner, Account).
    const revokedOnChainForGood =
      slot.revokedAt !== null &&
      slot.revocationKind === "v2_upsert" &&
      slot.revocationOutcome !== "superseded";
    if (
      !slot.scopes.includes(reg.entry) ||
      (reg.endedVersion === null && revokedOnChainForGood)
    ) {
      store.markChainEnded(grantId, this.now());
      return;
    }

    for (let attempt = 0; attempt < 2; attempt++) {
      const current =
        attempt === 0 ? slot : await gateway.getSlot(slot.id);
      if (!current) {
        store.markChainEnded(grantId, this.now());
        return;
      }
      const remaining = current.scopes.filter((e) => e !== reg.entry);
      const grantVersion = BigInt(current.currentGrantVersion) + 1n;
      const revocation = remaining.length === 0 || current.revokedAt !== null;
      // Removal-only upsert: the slot's own expiry is kept (a later one would
      // count as widening). A V2 revocation keeps every entry (the contract
      // refuses an empty list) and ends the relationship with a past expiry.
      const scopes = revocation ? current.scopes : remaining;
      const expiresAt = revocation
        ? BigInt(Math.floor(this.now().getTime() / 1000) - 300)
        : BigInt(current.expiresAtSeconds);
      const signature = await this.options.signGrantRegistration({
        grantorAddress: owner,
        granteeId: current.granteeId as `0x${string}`,
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
        ? await gateway.revokeSlot(current.id, body, signature)
        : await gateway.registerSlot(
            { ...body, granteeId: current.granteeId },
            signature,
          );
      if (answer.status >= 200 && answer.status < 300) {
        store.noteChainEndingSent(
          grantId,
          grantVersion.toString(),
          revocation ? "revocation" : "removal",
          this.now(),
        );
        return;
      }
      if (answer.status === 409 && attempt === 0) continue;
      store.noteChainError(grantId, `end: ${describe(answer)}`);
      return;
    }
  }

  /** Has the upsert that dropped the entry become final on chain? */
  private endingFinal(
    reg: ChainRegistration,
    slot: GatewaySlot,
  ): "final" | "waiting" | "resign" {
    if (reg.endingKind === "revocation") {
      if (slot.revocationKind === "v2_reverted") return "resign";
      if (slot.revocationKind !== "v2_upsert") return "resign";
      if (slot.revocationOutcome === "superseded") return "resign";
      return slot.revocationFinalizedAt !== null ? "final" : "waiting";
    }
    // The whole slot was revoked on chain for good after the removal: the
    // entry is gone with it.
    if (
      slot.revokedAt !== null &&
      slot.revocationKind === "v2_upsert" &&
      slot.revocationOutcome !== "superseded"
    )
      return slot.revocationFinalizedAt !== null ? "final" : "waiting";
    // Removal-only: final once the chain holds a registration at or past the
    // one that dropped the entry, and the entry is not listed.
    if (slot.scopes.includes(reg.entry)) return "resign";
    const settled = slot.status === "confirmed" || slot.status === "finalized";
    return settled && BigInt(slot.grantVersion) >= BigInt(reg.endedVersion!)
      ? "final"
      : "waiting";
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
          await options.registrar.register(pdppGrantId);
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
        logScope(connector: string, ns: string): string;
        streamScope(connector: string, ns: string, stream: string): string;
      }
    | null;
}): {
  registrar: Pick<PdppChainRegistrar, "prepare" | "register" | "reconcile">;
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
  });
  const registrar = new PdppChainRegistrar({
    store: input.store,
    gateway,
    owner: ready.owner,
    deployment: ready.deployment,
    granteeAddressFor: (clientId) => {
      const address = ready.clients.find(
        (c) => c.clientId === clientId,
      )?.granteeAddress;
      return address ? (address as `0x${string}`) : null;
    },
    scopeBindingsFor: (grant) =>
      ready.link
        ? streamSyncScopeBindings({
            grant,
            link: ready.link,
            declaredStreams: ready.declaredStreams,
            logScope: ready.logScope,
            streamScope: ready.streamScope,
          })
        : [],
    signGrantRegistration: ready.signGrantRegistration,
    logger: input.logger,
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
