/**
 * Design 2 on the Personal Server (Vana-6.1, Vana-6.2): issuance registers a
 * salted grant entry in the owner's PermissionsV2 slot, reads are gated on
 * that entry being live on chain, and a grant end removes the entry (or
 * revokes the slot when nothing else remains).
 *
 * The gateway is an HTTP fake that follows its wire contract (data-gateway
 * branch maciej/pdpp-design2 at 002541d): every signed version must be
 * exactly `currentGrantVersion + 1`; an identical re-registration is a no-op
 * that still spends the version; each new `pdpp:sha256:` entry needs its
 * document and salt, and the fake recomputes the fingerprint; scope bindings
 * are immutable; chain-binding answers the pay conjunction; a removal-only
 * upsert is fee-free; DELETE needs a past expiry and a subset of the scopes;
 * the chain only changes when the fake "settles". Signatures are real
 * EIP-712 signatures, recovered by the fake.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Hono, type Context } from "hono";
import pino from "pino";
import { privateKeyToAccount } from "viem/accounts";
import { recoverTypedDataAddress } from "viem";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  AuthorizationSessionStore,
  computeS256Challenge,
  openPdppAuthStore,
  PDPP_DATA_ACCESS_TYPE,
  PdppTokenService,
  type DeclarationSnapshot,
  type Grant,
  type PdppAuthStore,
} from "@opendatalabs/personal-server-ts-core/pdpp";
import { computePdppGrantEntry } from "@opendatalabs/personal-server-ts-core/grants";
import { logScope, streamScope } from "@opendatalabs/personal-server-ts-stream-sync";
import { pdppAuthRoutes } from "../routes/pdpp-auth.js";
import { createDesign2ChainGrants, streamSyncScopeBindings } from "./chain-grants.js";

const logger = pino({ level: "silent" });
const SERVER_KEY =
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const server = privateKeyToAccount(SERVER_KEY);
const OWNER = "0x1111111111111111111111111111111111111111" as const;
const GRANTEE = "0x2222222222222222222222222222222222222222" as const;
const BUILDER_ID = `0x${"b".repeat(64)}`;
const CHAIN_ID = 14800;
const CONTRACT = "0x4d3FA76064D88e0454cFc4CaD7e5FeC3e3124011" as const;
const GATEWAY = "https://gateway.example";
const CLIENT = "concert_finder";
const NO_GRANTEE_CLIENT = "url_hosted_app";
const REDIRECT = "https://app.example.com/callback";
const SOURCE_ID = "https://registry.pdpp.dev/connectors/spotify";
const INSTANCE = "spotify-account-a";
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

const DOMAIN = {
  name: "Vana Data Portability",
  version: "1",
  chainId: CHAIN_ID,
  verifyingContract: CONTRACT,
} as const;
const TYPES = {
  GrantRegistration: [
    { name: "grantorAddress", type: "address" },
    { name: "granteeId", type: "bytes32" },
    { name: "scopes", type: "string[]" },
    { name: "grantVersion", type: "uint256" },
    { name: "expiresAt", type: "uint256" },
  ],
} as const;

// ─── Fake gateway ─────────────────────────────────────────────────────────

interface Slot {
  id: string;
  scopes: string[];
  grantVersion: string;
  latest: bigint;
  expiresAtSeconds: string;
  revokedAt: string | null;
  revocationKind: string | null;
  revocationFinalizedAt: string | null;
  revocationOutcome: string | null;
  status: string;
  paymentStatus: "pending" | "paid";
  removalOnly: boolean;
}

class FakeGateway {
  slot: Slot | null = null;
  /** What PermissionsV2 holds; changes only on settle(). */
  chain: { scopes: string[]; expiresAt: bigint; version: bigint } | null =
    null;
  documents = new Map<string, { grant: Grant; salt: string; streams: string[] }>();
  bindings = new Map<string, { sourceId: string; streams: string[] }>();
  down = false;
  /** Process the next POST /v1/grants, then lose its answer. */
  dropNextRegistrationAnswer = false;
  /** When set, only this many more slot lookups succeed; then 500. */
  slotLookupsAllowed: number | null = null;
  requests: Array<{ method: string; path: string; body?: unknown }> = [];
  signedVersions: bigint[] = [];

  current(): bigint {
    if (!this.slot) return 0n;
    const v = BigInt(this.slot.grantVersion);
    return v > this.slot.latest ? v : this.slot.latest;
  }

  view() {
    const s = this.slot!;
    return {
      id: s.id,
      granteeId: BUILDER_ID,
      scopes: s.scopes,
      grantVersion: s.grantVersion,
      currentGrantVersion: this.current().toString(),
      expiresAtSeconds: s.expiresAtSeconds,
      expired:
        s.expiresAtSeconds !== "0" &&
        Number(s.expiresAtSeconds) * 1000 <= Date.now(),
      status: s.status,
      revokedAt: s.revokedAt,
      revocationKind: s.revocationKind,
      revocationFinalizedAt: s.revocationFinalizedAt,
      revocationOutcome: s.revocationOutcome,
      paymentStatus: s.paymentStatus,
    };
  }

  /** /v1/settle: send what the gateway holds to the chain. */
  settle(options: { revert?: boolean } = {}) {
    const s = this.slot;
    if (!s) return;
    if (s.revokedAt && s.revocationKind === "v2_upsert") {
      if (options.revert) {
        s.revocationKind = "v2_reverted";
        return;
      }
      this.chain = {
        scopes: s.scopes,
        expiresAt: BigInt(Math.floor(Date.now() / 1000) - 300),
        version: this.current(),
      };
      s.revocationFinalizedAt = new Date().toISOString();
      s.revocationOutcome = "sent";
      return;
    }
    this.chain = {
      scopes: [...s.scopes],
      expiresAt: BigInt(s.expiresAtSeconds),
      version: BigInt(s.grantVersion),
    };
    s.status = "finalized";
  }

  /** The gateway's design-2 pay rule for one label (Vana-6.1). */
  payResolves(label: string): { entry: string; grantId: string } | null {
    const binding = this.bindings.get(label);
    if (!binding || !this.slot || !this.chain) return null;
    if (this.slot.revokedAt) return null;
    for (const entry of this.chain.scopes) {
      const doc = this.documents.get(entry);
      if (
        doc &&
        this.slot.scopes.includes(entry) &&
        doc.grant.source.id === binding.sourceId &&
        binding.streams.every((st) => doc.streams.includes(st))
      )
        return { entry, grantId: doc.grant.grant_id };
    }
    return null;
  }

  private async signer(
    auth: string | null,
    message: Record<string, unknown>,
  ): Promise<string> {
    const signature = auth!.replace(/^Web3Signed /, "") as `0x${string}`;
    return recoverTypedDataAddress({
      domain: DOMAIN,
      types: TYPES,
      primaryType: "GrantRegistration",
      message: message as never,
      signature,
    });
  }

  private checkVersion(signed: bigint): Response | null {
    this.signedVersions.push(signed);
    if (signed !== this.current() + 1n)
      return Response.json(
        {
          success: false,
          error: "stale or jumped grantVersion",
          currentGrantVersion: this.current().toString(),
        },
        { status: 409 },
      );
    return null;
  }

  fetch = async (input: unknown, init?: RequestInit): Promise<Response> => {
    if (this.down) throw new TypeError("fetch failed");
    const response = await this.handle(input, init);
    if (
      this.dropNextRegistrationAnswer &&
      init?.method === "POST" &&
      new URL(String(input)).pathname === "/v1/grants"
    ) {
      this.dropNextRegistrationAnswer = false;
      throw new TypeError("connection reset");
    }
    return response;
  };

  private handle = async (
    input: unknown,
    init?: RequestInit,
  ): Promise<Response> => {
    const url = new URL(String(input));
    const method = init?.method ?? "GET";
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    this.requests.push({ method, path: url.pathname + url.search, body });
    const auth = new Headers(init?.headers).get("authorization");

    if (method === "GET" && url.pathname === `/v1/builders/${GRANTEE}`)
      return Response.json({ data: { id: BUILDER_ID, granteeAddress: GRANTEE } });
    if (method === "GET" && url.pathname.startsWith("/v1/builders/"))
      return new Response(null, { status: 404 });

    if (method === "GET" && url.pathname === "/v1/grants") {
      if (this.slotLookupsAllowed !== null && this.slotLookupsAllowed-- <= 0)
        return new Response(null, { status: 500 });
      expect(url.searchParams.get("active")).toBe("false");
      return Response.json({
        data: { grants: this.slot ? [this.view()] : [] },
      });
    }
    if (method === "GET" && url.pathname.startsWith("/v1/grants/"))
      return this.slot && url.pathname.endsWith(this.slot.id)
        ? Response.json({ data: this.view() })
        : new Response(null, { status: 404 });

    if (method === "PUT" && url.pathname === "/v1/pdpp/scope-bindings") {
      expect(auth).toMatch(/^Web3Signed /);
      expect(body.ownerAddress).toBe(OWNER);
      for (const b of body.bindings) {
        const prior = this.bindings.get(b.scope);
        if (
          prior &&
          JSON.stringify(prior) !==
            JSON.stringify({ sourceId: b.sourceId, streams: b.streams })
        )
          return Response.json({ error: "binding differs" }, { status: 409 });
      }
      for (const b of body.bindings)
        this.bindings.set(b.scope, { sourceId: b.sourceId, streams: b.streams });
      return Response.json({ data: { stored: body.bindings.length } });
    }

    if (method === "POST" && url.pathname === "/v1/grants") {
      const signer = await this.signer(auth, {
        grantorAddress: body.grantorAddress,
        granteeId: body.granteeId,
        scopes: body.scopes,
        grantVersion: BigInt(body.grantVersion),
        expiresAt: BigInt(body.expiresAt),
      });
      if (signer.toLowerCase() !== server.address.toLowerCase())
        return Response.json({ error: "bad signer" }, { status: 401 });
      const stale = this.checkVersion(BigInt(body.grantVersion));
      if (stale) return stale;
      for (const a of body.pdppGrants ?? []) {
        if (computePdppGrantEntry(a.grant, a.salt) !== a.entry)
          return Response.json(
            { code: "PDPP_GRANT_HASH_MISMATCH" },
            { status: 400 },
          );
        this.documents.set(a.entry, {
          grant: a.grant,
          salt: a.salt,
          streams: a.grant.streams.map((st: { name: string }) => st.name),
        });
      }
      for (const e of body.scopes as string[])
        if (e.startsWith("pdpp:") && !this.documents.has(e))
          return Response.json(
            { code: "PDPP_GRANT_DOCUMENT_REQUIRED" },
            { status: 400 },
          );
      const prior = this.slot;
      const removalOnly =
        !!prior &&
        !prior.revokedAt &&
        (body.scopes as string[]).every((e) => prior.scopes.includes(e));
      if (
        prior &&
        JSON.stringify(prior.scopes) === JSON.stringify(body.scopes) &&
        prior.expiresAtSeconds === body.expiresAt
      ) {
        prior.latest = BigInt(body.grantVersion);
        return Response.json({
          success: true,
          grantId: prior.id,
          grantVersion: body.grantVersion,
          unchanged: true,
        });
      }
      this.slot = {
        id: `0x${"a".repeat(64)}`,
        scopes: body.scopes,
        grantVersion: body.grantVersion,
        latest: BigInt(body.grantVersion),
        expiresAtSeconds: body.expiresAt,
        revokedAt: null,
        revocationKind: null,
        revocationFinalizedAt: null,
        revocationOutcome: null,
        status: "pending",
        paymentStatus: removalOnly ? "paid" : "pending",
        removalOnly,
      };
      return Response.json(
        {
          success: true,
          grantId: this.slot.id,
          grantVersion: body.grantVersion,
          overridden: !!prior,
        },
        { status: prior ? 200 : 201 },
      );
    }

    if (method === "DELETE" && url.pathname.startsWith("/v1/grants/")) {
      const s = this.slot!;
      const signer = await this.signer(auth, {
        grantorAddress: body.grantorAddress,
        granteeId: BUILDER_ID,
        scopes: body.scopes,
        grantVersion: BigInt(body.grantVersion),
        expiresAt: BigInt(body.expiresAt),
      });
      if (signer.toLowerCase() !== server.address.toLowerCase())
        return Response.json({ error: "bad signer" }, { status: 401 });
      if (BigInt(body.expiresAt) === 0n || Number(body.expiresAt) * 1000 > Date.now())
        return Response.json(
          { code: "REVOCATION_EXPIRY_NOT_PAST" },
          { status: 400 },
        );
      if (
        body.scopes.length === 0 ||
        !body.scopes.every((e: string) => s.scopes.includes(e))
      )
        return Response.json(
          { code: "REVOCATION_SCOPES_NOT_SUBSET" },
          { status: 400 },
        );
      if (s.revokedAt && s.revocationKind === "v2_upsert")
        return Response.json({ error: "Grant already revoked" }, { status: 409 });
      const stale = this.checkVersion(BigInt(body.grantVersion));
      if (stale) return stale;
      s.latest = BigInt(body.grantVersion);
      s.revokedAt = new Date().toISOString();
      s.revocationKind = "v2_upsert";
      s.revocationFinalizedAt = null;
      s.revocationOutcome = null;
      return Response.json({
        success: true,
        revocationKind: "v2_upsert",
        onChain: "queued",
        grantVersion: body.grantVersion,
      });
    }

    if (method === "GET" && url.pathname === "/v1/pdpp/chain-binding") {
      expect(auth).toMatch(/^Web3Signed /);
      const grantId = url.searchParams.get("grantId");
      const entry = [...this.documents.entries()].find(
        ([, d]) => d.grant.grant_id === grantId,
      )?.[0];
      if (!entry || !this.slot) return new Response(null, { status: 404 });
      const s = this.slot;
      const onChainActive =
        !!this.chain &&
        (this.chain.expiresAt === 0n ||
          this.chain.expiresAt * 1000n > BigInt(Date.now()));
      return Response.json({
        data: {
          bindings: [
            {
              chainId: String(CHAIN_ID),
              contractAddress: CONTRACT,
              permissionId: s.id,
              entry,
              pdppGrantId: grantId,
              pdppExpired: false,
              gateway: {
                entryListed: s.scopes.includes(entry),
                slotRevoked: s.revokedAt !== null,
                slotExpired: false,
              },
              onChain: {
                entryPresent: !!this.chain?.scopes.includes(entry),
                slotActive: onChainActive,
              },
              active: false,
            },
          ],
        },
      });
    }
    return new Response(null, { status: 404 });
  };
}

// ─── Harness ──────────────────────────────────────────────────────────────

const snapshot: DeclarationSnapshot = {
  source_id: SOURCE_ID,
  source_kind: "connector",
  version: "2026-08-11",
  digest: "d".repeat(64),
  streams: [
    {
      name: "top_artists",
      fields: ["id", "name"],
      required_fields: ["id"],
      primary_key: ["id"],
    },
    {
      name: "profile",
      fields: ["id", "display_name"],
      required_fields: ["id"],
      primary_key: ["id"],
    },
  ],
};

let dir: string;
let store: PdppAuthStore;
let tokens: PdppTokenService;
let app: Hono;
let gateway: FakeGateway;
let chain: ReturnType<typeof createDesign2ChainGrants>;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "pdpp-chain-grants-"));
  store = openPdppAuthStore(join(dir, "auth.db"));
  tokens = new PdppTokenService(store);
  gateway = new FakeGateway();
  chain = createDesign2ChainGrants({
    store,
    logger,
    ready: {
      gatewayUrl: GATEWAY,
      fetch: gateway.fetch as typeof fetch,
      owner: OWNER,
      deployment: { chainId: CHAIN_ID, contractAddress: CONTRACT },
      signMessage: (message) => server.signMessage({ message }),
      signGrantRegistration: (msg) =>
        server.signTypedData({
          domain: DOMAIN,
          types: TYPES,
          primaryType: "GrantRegistration",
          message: msg,
        }),
      clients: [
        { clientId: CLIENT, granteeAddress: GRANTEE },
        { clientId: NO_GRANTEE_CLIENT },
      ],
      link: (instance) =>
        instance === INSTANCE ? { connector: "spotify", namespace: "" } : null,
      declaredStreams: () => snapshot.streams.map((st) => st.name),
      logScope,
      streamScope,
    },
  });
  app = new Hono();
  app.route(
    "/pdpp/v1",
    pdppAuthRoutes({
      logger,
      store,
      tokens,
      sessions: new AuthorizationSessionStore(),
      issuer: "https://ps.example",
      resolveDeclaration: (id) => (id === SOURCE_ID ? snapshot : null),
      inventoryFor: () => ({ eligibleFor: () => [INSTANCE] }),
      currentSubjectId: (c: Context) =>
        c.req.header("authorization") ? OWNER : null,
      registeredClient: (id) =>
        id === CLIENT || id === NO_GRANTEE_CLIENT
          ? { client_id: id, redirect_uris: [REDIRECT] }
          : null,
      chainRegistrar: chain.registrar,
    }),
  );
});

afterEach(() => {
  store.close();
  rmSync(dir, { recursive: true, force: true });
});

function ownerToken(): string {
  return tokens.issueOwnerToken({ subjectId: OWNER, sourceId: SOURCE_ID })
    .access_token;
}

async function approve(
  clientId = CLIENT,
  streams = [{ name: "top_artists", fields: ["*"] }],
) {
  const token = ownerToken();
  const headers = {
    "content-type": "application/json",
    authorization: `Bearer ${token}`,
  };
  const created = await app.request("/pdpp/v1/authorize", {
    method: "POST",
    headers,
    body: JSON.stringify({
      client_id: clientId,
      redirect_uri: REDIRECT,
      state: "s",
      code_challenge: computeS256Challenge(VERIFIER),
      code_challenge_method: "S256",
      authorization_details: [
        {
          type: PDPP_DATA_ACCESS_TYPE,
          source: { id: SOURCE_ID },
          purpose_code: "https://pdpp.dev/purpose/personalization",
          access_mode: "continuous",
          streams,
        },
      ],
    }),
  });
  expect(created.status).toBe(201);
  const { session_id } = (await created.json()) as { session_id: string };
  const reviewed = await app.request(
    `/pdpp/v1/authorize/${session_id}/review`,
    { headers },
  );
  const { review } = (await reviewed.json()) as {
    review: { review_digest: string };
  };
  return app.request(`/pdpp/v1/authorize/${session_id}/approve`, {
    method: "POST",
    headers,
    body: JSON.stringify({ review_digest: review.review_digest }),
  });
}

async function approvedGrantId(
  streams?: Array<{ name: string; fields: string[] }>,
): Promise<string> {
  const res = await approve(CLIENT, streams);
  expect(res.status).toBe(200);
  const { grant_id } = (await res.json()) as { grant_id: string };
  // The route starts registration after responding; wait for the queue.
  await chain.registrar.reconcile();
  return grant_id;
}

/** Wait for the registrar queue (the route registers after responding). */
async function drain() {
  await chain.registrar.register("grt_none");
}

function read(grantId: string) {
  return chain.gate.authorize({ clientId: CLIENT, pdppGrantId: grantId });
}

async function ownerRevoke(grantId: string) {
  const res = await app.request("/pdpp/v1/revoke", {
    method: "POST",
    headers: {
      authorization: `Bearer ${ownerToken()}`,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({ grant_id: grantId, disposition: "keep" }),
  });
  expect(res.status).toBeLessThan(300);
  await chain.registrar.reconcile();
}

// ─── Tests ────────────────────────────────────────────────────────────────

describe("design 2 issuance: every grant gets a chain registration", () => {
  it("registers the salted entry at currentGrantVersion + 1 and stores the binding", async () => {
    const grantId = await approvedGrantId();
    const reg = store.getChainRegistration(grantId)!;
    expect(reg.status).toBe("bound");
    expect(reg).toMatchObject({
      chainId: CHAIN_ID,
      contractAddress: CONTRACT,
      permissionId: `0x${"a".repeat(64)}`,
      granteeId: BUILDER_ID,
      granteeAddress: GRANTEE,
      registeredVersion: "1",
    });
    // The entry is the gateway's fingerprint of the exact issued grant.
    const stored = store.getGrant(grantId)!;
    expect(reg.entry).toBe(computePdppGrantEntry(stored.grant, reg.salt));
    expect(gateway.slot!.scopes).toEqual([reg.entry]);
    expect(gateway.documents.get(reg.entry)!.grant).toEqual(stored.grant);
    expect(gateway.signedVersions).toEqual([1n]);
  });

  it("binds the stream-sync log row to every declared stream and each per-stream row to its stream", async () => {
    await approvedGrantId();
    expect(Object.fromEntries(gateway.bindings)).toEqual({
      "pdpp.spotify~.top_artists": {
        sourceId: SOURCE_ID,
        streams: ["top_artists"],
      },
      "pdpp.spotify~.~log": {
        sourceId: SOURCE_ID,
        streams: ["top_artists", "profile"],
      },
    });
  });

  it("keeps earlier entries when a second grant joins the slot, signing exactly one version above", async () => {
    const first = await approvedGrantId();
    const second = await approvedGrantId([
      { name: "profile", fields: ["*"] },
    ]);
    const a = store.getChainRegistration(first)!;
    const b = store.getChainRegistration(second)!;
    expect(gateway.slot!.scopes).toEqual([a.entry, b.entry]);
    expect(gateway.signedVersions).toEqual([1n, 2n]);
    expect(b.registeredVersion).toBe("2");
  });

  it("re-reads the slot and signs above it after a 409", async () => {
    // Another writer (e.g. Account) moved the slot to version 5 meanwhile.
    gateway.slot = {
      id: `0x${"a".repeat(64)}`,
      scopes: ["instagram.posts"],
      grantVersion: "3",
      latest: 5n,
      expiresAtSeconds: "0",
      revokedAt: null,
      revocationKind: null,
      revocationFinalizedAt: null,
      revocationOutcome: null,
      status: "finalized",
      paymentStatus: "paid",
      removalOnly: false,
    };
    const grantId = await approvedGrantId();
    expect(gateway.signedVersions).toEqual([6n]);
    // A legacy scope in the slot is kept beside the new entry.
    expect(gateway.slot!.scopes).toEqual([
      "instagram.posts",
      store.getChainRegistration(grantId)!.entry,
    ]);
  });

  it("refuses approval for a client with no grantee address, issuing nothing", async () => {
    const res = await approve(NO_GRANTEE_CLIENT);
    expect(res.status).toBe(403);
    expect(store.listAllGrants()).toHaveLength(0);
    expect(gateway.requests).toHaveLength(0);
  });

  it("issues but leaves the grant unusable while the gateway is unreachable, then binds on the next read", async () => {
    gateway.down = true;
    const grantId = await approvedGrantId();
    expect(store.getChainRegistration(grantId)!.status).toBe("pending");
    expect(await read(grantId)).toEqual({
      ok: false,
      retryable: true,
      reason: "Grant is not yet registered on chain",
    });
    gateway.down = false;
    // The read gate registers it, but the chain has not settled yet.
    expect(await read(grantId)).toMatchObject({ ok: false, retryable: true });
    expect(store.getChainRegistration(grantId)!.status).toBe("bound");
    gateway.settle();
    expect(await read(grantId)).toEqual({ ok: true });
  });
});

describe("design 2 reads are chain-enforced (Vana-6.1)", () => {
  it("denies a grant with no registration, definitively", async () => {
    expect(await read("grt_unknown")).toEqual({
      ok: false,
      retryable: false,
      reason: "No chain binding for this grant",
    });
  });

  it("allows only once the entry is on chain, and only for the bound app", async () => {
    const grantId = await approvedGrantId();
    expect(await read(grantId)).toMatchObject({ ok: false, retryable: true });
    gateway.settle();
    expect(await read(grantId)).toEqual({ ok: true });
    expect(
      await chain.gate.authorize({
        clientId: NO_GRANTEE_CLIENT,
        pdppGrantId: grantId,
      }),
    ).toMatchObject({ ok: false, retryable: false });
  });

  it("answers retry, not denial, when the gateway is down", async () => {
    const grantId = await approvedGrantId();
    gateway.settle();
    gateway.down = true;
    expect(await read(grantId)).toEqual({
      ok: false,
      retryable: true,
      reason: "Chain grant could not be read",
    });
  });

  it("lets the gateway resolve a paid read: label → streams → grant document → entry on chain", async () => {
    const grantId = await approvedGrantId();
    gateway.settle();
    const entry = store.getChainRegistration(grantId)!.entry;
    expect(gateway.payResolves("pdpp.spotify~.top_artists")).toEqual({
      entry,
      grantId,
    });
    // The log row carries every declared stream; a top_artists-only grant
    // cannot pay for it.
    expect(gateway.payResolves("pdpp.spotify~.~log")).toBeNull();
  });
});

describe("design 2 grant end and revocation on chain (Vana-6.2)", () => {
  it("drops one entry with a removal-only upsert and keeps the other grant readable", async () => {
    const first = await approvedGrantId();
    const second = await approvedGrantId([
      { name: "profile", fields: ["*"] },
    ]);
    gateway.settle();
    await ownerRevoke(first);
    const a = store.getChainRegistration(first)!;
    const b = store.getChainRegistration(second)!;
    expect(a).toMatchObject({
      status: "ending",
      endingKind: "removal",
      endedVersion: "3",
    });
    expect(gateway.slot!.scopes).toEqual([b.entry]);
    expect(gateway.slot!.paymentStatus).toBe("paid"); // fee-free removal
    expect(gateway.slot!.revokedAt).toBeNull();
    expect(await read(first)).toMatchObject({ ok: false, retryable: false });
    gateway.settle();
    await chain.registrar.reconcile();
    expect(store.getChainRegistration(first)!.status).toBe("ended");
    expect(await read(second)).toEqual({ ok: true });
  });

  it("revokes the slot on chain (V2 revocation, past expiry) when no entry remains", async () => {
    const grantId = await approvedGrantId();
    gateway.settle();
    await ownerRevoke(grantId);
    const del = gateway.requests.find((r) => r.method === "DELETE")!;
    expect(del.body).toMatchObject({
      grantorAddress: OWNER,
      grantVersion: "2",
      scopes: [store.getChainRegistration(grantId)!.entry],
    });
    expect(Number((del.body as { expiresAt: string }).expiresAt) * 1000).toBeLessThan(
      Date.now(),
    );
    expect(store.getChainRegistration(grantId)).toMatchObject({
      status: "ending",
      endingKind: "revocation",
    });
    // Not final until the gateway reports the revocation finalized.
    await chain.registrar.reconcile();
    expect(store.getChainRegistration(grantId)!.status).toBe("ending");
    gateway.settle();
    await chain.registrar.reconcile();
    expect(store.getChainRegistration(grantId)!.status).toBe("ended");
  });

  it("signs the revocation again when the on-chain revocation reverted", async () => {
    const grantId = await approvedGrantId();
    gateway.settle();
    await ownerRevoke(grantId);
    gateway.settle({ revert: true });
    expect(gateway.slot!.revocationKind).toBe("v2_reverted");
    await chain.registrar.reconcile();
    const deletes = gateway.requests.filter((r) => r.method === "DELETE");
    expect(deletes.map((d) => (d.body as { grantVersion: string }).grantVersion)).toEqual(["2", "3"]);
    gateway.settle();
    await chain.registrar.reconcile();
    expect(store.getChainRegistration(grantId)!.status).toBe("ended");
  });

  it("binds an entry whose registration landed but whose answer was lost, without signing again", async () => {
    gateway.dropNextRegistrationAnswer = true;
    const grantId = await approvedGrantId();
    // The retry found the entry already in the slot and bound to it.
    expect(store.getChainRegistration(grantId)!.status).toBe("bound");
    expect(gateway.signedVersions).toEqual([1n]);
    expect(
      gateway.requests.filter(
        (r) => r.method === "POST" && r.path === "/v1/grants",
      ),
    ).toHaveLength(1);
  });

  it("removes the entry of a grant that ended before its registration was confirmed", async () => {
    // The registration lands but its answer is lost, and every later slot
    // lookup fails, so the PS never learns the permission id.
    gateway.dropNextRegistrationAnswer = true;
    gateway.slotLookupsAllowed = 1;
    const res = await approve();
    const { grant_id: grantId } = (await res.json()) as { grant_id: string };
    await drain();
    expect(store.getChainRegistration(grantId)).toMatchObject({
      status: "pending",
      permissionId: null,
    });
    gateway.settle();
    await ownerRevoke(grantId);
    expect(store.getChainRegistration(grantId)!.status).toBe("ending");
    gateway.slotLookupsAllowed = null;
    await chain.registrar.reconcile();
    const del = gateway.requests.find((r) => r.method === "DELETE");
    expect(del?.body).toMatchObject({
      scopes: [store.getChainRegistration(grantId)!.entry],
    });
    expect(store.getChainRegistration(grantId)).toMatchObject({
      status: "ending",
      endingKind: "revocation",
    });
  });
});

describe("stream-sync scope labels", () => {
  it("skips instances with no link and dedupes the log row", () => {
    const grant = {
      source: { id: SOURCE_ID },
      streams: [
        { name: "a", instance_ids: ["i", "unlinked"] },
        { name: "b", instance_ids: ["i"] },
      ],
    } as unknown as Grant;
    expect(
      streamSyncScopeBindings({
        grant,
        link: (instance) =>
          instance === "i" ? { connector: "c", namespace: "" } : null,
        declaredStreams: () => ["a", "b", "c"],
        logScope,
        streamScope,
      }),
    ).toEqual([
      { scope: "pdpp.c~.a", sourceId: SOURCE_ID, streams: ["a"] },
      { scope: "pdpp.c~.~log", sourceId: SOURCE_ID, streams: ["a", "b", "c"] },
      { scope: "pdpp.c~.b", sourceId: SOURCE_ID, streams: ["b"] },
    ]);
  });
});

describe("fail closed when chain grants are on but cannot run", () => {
  it("refuses approvals and denies reads", async () => {
    const off = createDesign2ChainGrants({ store, logger, ready: null });
    expect(off.registrar.prepare({} as Grant)).toBeNull();
    expect(
      await off.gate.authorize({ clientId: CLIENT, pdppGrantId: "g" }),
    ).toMatchObject({ ok: false, retryable: false });
  });
});
