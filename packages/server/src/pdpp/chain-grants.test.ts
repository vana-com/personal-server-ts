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
import Database from "better-sqlite3";
import { Hono, type Context } from "hono";
import pino from "pino";
import { privateKeyToAccount } from "viem/accounts";
import {
  domainSeparator as viemDomainSeparator,
  encodeAbiParameters,
  keccak256,
  recoverTypedDataAddress,
} from "viem";
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
import {
  logScope,
  streamScope,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { pdppAuthRoutes } from "../routes/pdpp-auth.js";
import {
  createDesign2ChainGrants,
  streamSyncScopeBindings,
} from "./chain-grants.js";

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

// PermissionsV2's slot id, computed here independently of the PS code.
const SEPARATOR = viemDomainSeparator({ domain: DOMAIN });
const SLOT_ID = keccak256(
  encodeAbiParameters(
    [{ type: "bytes32" }, { type: "address" }, { type: "bytes32" }],
    [SEPARATOR, OWNER, BUILDER_ID as `0x${string}`],
  ),
);

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
  chain: { scopes: string[]; expiresAt: bigint; version: bigint } | null = null;
  documents = new Map<
    string,
    { grant: Grant; salt: string; streams: string[] }
  >();
  bindings = new Map<string, { sourceId: string; streams: string[] }>();
  down = false;
  /** Process the next POST /v1/grants, then lose its answer. */
  dropNextRegistrationAnswer = false;
  /** When set, only this many more slot lookups succeed; then 500. */
  slotLookupsAllowed: number | null = null;
  /** Fields the gateway's GET /v1/grants/:id lies about (F2). */
  lie: Partial<ReturnType<FakeGateway["view"]>> | null = null;
  chainDown = false;
  /** Play a gateway older than 129b16e (no registrationOutcome). */
  omitOutcome = false;
  /** Refuse an upsert listing an entry the gateway view does not list. */
  refuseUnlisted = false;
  /** Refuse (409 bound elsewhere) any upsert listing one of these. */
  refuseEntries = new Set<string>();
  bindingRequests = 0;
  /** Another writer moves the slot version just before the next POST. */
  bumpBeforeNextPost = false;
  /** Hang every request (no answer) when set (F4 timeouts). */
  hang = false;
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
      // gateway b16e9d7 registrationOutcomeOf, from the status this fake keeps
      // (omitted to play a gateway older than 129b16e)
      registrationOutcome: this.omitOutcome
        ? undefined
        : s.status === "failed"
          ? "reverted"
          : s.status === "finalized"
            ? "finalized"
            : "pending",
      paymentStatus: s.paymentStatus,
    };
  }

  /** /v1/settle: send what the gateway holds to the chain. */
  settle(options: { revert?: boolean; fail?: boolean } = {}) {
    const s = this.slot;
    if (!s) return;
    if (options.fail && !s.revokedAt) {
      // The registration transaction reverted: the chain is unchanged.
      s.status = "failed";
      return;
    }
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

  /** PermissionsV2 at the finalized block. */
  reader = {
    domainSeparator: async () => SEPARATOR,
    readFinalized: async (id: `0x${string}`) => {
      if (this.chainDown) throw new Error("rpc down");
      return {
        blockTimestamp: BigInt(Math.floor(Date.now() / 1000)),
        permission:
          this.chain && id === SLOT_ID
            ? {
                grantorAddress: OWNER,
                granteeId: BUILDER_ID,
                scopes: [...this.chain.scopes],
                grantVersion: this.chain.version,
                expiresAt: this.chain.expiresAt,
              }
            : null,
      };
    },
  };

  fetch = async (input: unknown, init?: RequestInit): Promise<Response> => {
    if (this.down) throw new TypeError("fetch failed");
    if (this.hang)
      return new Promise<Response>((_, reject) =>
        init?.signal?.addEventListener("abort", () =>
          reject(new DOMException("timed out", "TimeoutError")),
        ),
      );
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
      return Response.json({
        data: { id: BUILDER_ID, granteeAddress: GRANTEE },
      });
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
    if (method === "GET" && url.pathname.startsWith("/v1/grants/")) {
      if (this.slotLookupsAllowed !== null && this.slotLookupsAllowed-- <= 0)
        return new Response(null, { status: 500 });
      if (this.lie)
        return Response.json({ data: { ...this.view(), ...this.lie } });
      return this.slot && url.pathname.endsWith(this.slot.id)
        ? Response.json({ data: this.view() })
        : new Response(null, { status: 404 });
    }

    if (method === "PUT" && url.pathname === "/v1/pdpp/scope-bindings") {
      expect(auth).toMatch(/^Web3Signed /);
      expect(body.ownerAddress).toBe(OWNER);
      this.bindingRequests++;
      if (body.bindings.length > 100)
        return Response.json(
          { code: "PDPP_BINDINGS_TOO_MANY", maxBindings: 100 },
          { status: 400 },
        );
      // gateway 6ae5d92: per-binding results; conflicts do not block others.
      const results = (
        body.bindings as Array<{
          scope: string;
          sourceId: string;
          streams: string[];
        }>
      ).map((b) => {
        if (b.streams.length > 256)
          return { scope: b.scope, result: "invalid" };
        const prior = this.bindings.get(b.scope);
        if (!prior) {
          this.bindings.set(b.scope, {
            sourceId: b.sourceId,
            streams: b.streams,
          });
          return { scope: b.scope, result: "bound" };
        }
        const same =
          prior.sourceId === b.sourceId &&
          prior.streams.length === b.streams.length &&
          b.streams.every((st) => prior.streams.includes(st));
        return { scope: b.scope, result: same ? "unchanged" : "conflict" };
      });
      const conflicts = results.filter((r) => r.result === "conflict");
      return conflicts.length > 0
        ? Response.json(
            {
              code: "PDPP_SCOPE_BINDING_CONFLICT",
              scopes: conflicts.map((r) => r.scope),
              results,
            },
            { status: 409 },
          )
        : Response.json({ success: true, results });
    }

    if (method === "POST" && url.pathname === "/v1/grants") {
      if (this.bumpBeforeNextPost && this.slot) {
        this.bumpBeforeNextPost = false;
        this.slot.latest = this.current() + 1n;
      }
      const signer = await this.signer(auth, {
        grantorAddress: body.grantorAddress,
        granteeId: body.granteeId,
        scopes: body.scopes,
        grantVersion: BigInt(body.grantVersion),
        expiresAt: BigInt(body.expiresAt),
      });
      if (signer.toLowerCase() !== server.address.toLowerCase())
        return Response.json({ error: "bad signer" }, { status: 401 });
      if ((body.scopes as string[]).some((e) => this.refuseEntries.has(e)))
        return Response.json(
          { code: "PDPP_ENTRY_BOUND_ELSEWHERE" },
          { status: 409 },
        );
      if (this.refuseUnlisted) {
        const listed =
          (this.lie?.scopes as string[] | undefined) ?? this.slot?.scopes ?? [];
        const attached = new Set(
          (body.pdppGrants ?? []).map((a: { entry: string }) => a.entry),
        );
        if (
          (body.scopes as string[]).some(
            (e) =>
              e.startsWith("pdpp:") && !listed.includes(e) && !attached.has(e),
          )
        )
          return Response.json(
            { code: "PDPP_ENTRY_BOUND_ELSEWHERE" },
            { status: 409 },
          );
      }
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
        prior.status !== "failed" &&
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
        id: SLOT_ID,
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
      if (
        BigInt(body.expiresAt) === 0n ||
        Number(body.expiresAt) * 1000 > Date.now()
      )
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
        return Response.json(
          { error: "Grant already revoked" },
          { status: 409 },
        );
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
      chain: gateway.reader,
      retryBackoffMs: 0,
      timeoutMs: 200,
      maxDeferralMs: 1_000,
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
      legacyScopes: () => [
        { scope: "spotify.profile", streams: ["profile"] },
        { scope: "spotify.overview", streams: ["top_artists", "profile"] },
        // Names a stream the retained declaration lacks: not bound.
        { scope: "spotify.playlists", streams: ["playlists"] },
      ],
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
  opts: { target?: Hono; accessMode?: "continuous" | "single_use" } = {},
) {
  const app_ = opts.target ?? app;
  const token = ownerToken();
  const headers = {
    "content-type": "application/json",
    authorization: `Bearer ${token}`,
  };
  const created = await app_.request("/pdpp/v1/authorize", {
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
          access_mode: opts.accessMode ?? "continuous",
          streams,
        },
      ],
    }),
  });
  expect(created.status).toBe(201);
  const { session_id } = (await created.json()) as { session_id: string };
  const reviewed = await app_.request(
    `/pdpp/v1/authorize/${session_id}/review`,
    { headers },
  );
  const { review } = (await reviewed.json()) as {
    review: { review_digest: string };
  };
  return app_.request(`/pdpp/v1/authorize/${session_id}/approve`, {
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
      permissionId: SLOT_ID,
      granteeId: BUILDER_ID,
      granteeAddress: GRANTEE,
      registeredVersion: "1",
    });
    // The entry is the gateway's fingerprint of the exact issued grant: the
    // document the client holds (pairwise handles, AS item 29).
    const issued = store.clientGrantView(store.getGrant(grantId)!);
    expect(issued.streams[0].instance_ids[0]).toMatch(/^pwi_/);
    expect(reg.entry).toBe(computePdppGrantEntry(issued, reg.salt));
    expect(gateway.slot!.scopes).toEqual([reg.entry]);
    expect(gateway.documents.get(reg.entry)!.grant).toEqual(issued);
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
      // Legacy readable scopes, each bound to every stream it projects.
      "spotify.profile": { sourceId: SOURCE_ID, streams: ["profile"] },
      "spotify.overview": {
        sourceId: SOURCE_ID,
        streams: ["top_artists", "profile"],
      },
    });
  });

  it("lets a paid read of a legacy scope resolve only through a grant covering all its streams", async () => {
    const grantId = await approvedGrantId();
    gateway.settle();
    // top_artists only: cannot pay for spotify.profile or spotify.overview.
    expect(gateway.payResolves("spotify.profile")).toBeNull();
    expect(gateway.payResolves("spotify.overview")).toBeNull();
    const both = await approvedGrantId([
      { name: "top_artists", fields: ["*"] },
      { name: "profile", fields: ["*"] },
    ]);
    gateway.settle();
    expect(gateway.payResolves("spotify.overview")?.grantId).toBe(both);
    expect(gateway.payResolves("pdpp.spotify~.top_artists")?.grantId).toBe(
      grantId,
    );
  });

  it("keeps earlier entries when a second grant joins the slot, signing exactly one version above", async () => {
    const first = await approvedGrantId();
    const second = await approvedGrantId([{ name: "profile", fields: ["*"] }]);
    const a = store.getChainRegistration(first)!;
    const b = store.getChainRegistration(second)!;
    expect(gateway.slot!.scopes).toEqual([a.entry, b.entry]);
    expect(gateway.signedVersions).toEqual([1n, 2n]);
    expect(b.registeredVersion).toBe("2");
  });

  function legacySlot(expiresAtSeconds: string, scopes = ["instagram.posts"]) {
    gateway.slot = {
      id: SLOT_ID,
      scopes,
      grantVersion: "3",
      latest: 5n,
      expiresAtSeconds,
      revokedAt: null,
      revocationKind: null,
      revocationFinalizedAt: null,
      revocationOutcome: null,
      status: "finalized",
      paymentStatus: "paid",
      removalOnly: false,
    };
    gateway.chain = {
      scopes: [...scopes],
      expiresAt: BigInt(expiresAtSeconds),
      version: 3n,
    };
  }

  function lastRegistration() {
    return gateway.requests
      .filter((r) => r.method === "POST" && r.path === "/v1/grants")
      .at(-1)!.body as {
      scopes: string[];
      expiresAt: string;
      grantVersion: string;
    };
  }

  it("signs above the gateway's highest answered version, keeping a legacy scope the chain holds", async () => {
    // Another writer (e.g. Account) moved the slot to version 5 meanwhile.
    legacySlot("0");
    const grantId = await approvedGrantId();
    expect(gateway.signedVersions).toEqual([6n]);
    expect(gateway.slot!.scopes).toEqual([
      "instagram.posts",
      store.getChainRegistration(grantId)!.entry,
    ]);
  });

  it("F1: never extends a legacy scope's expiry: a perpetual PDPP grant keeps the slot's earlier end", async () => {
    const dec31 = String(Math.floor(Date.now() / 1000) + 30 * 86_400);
    legacySlot(dec31);
    await approvedGrantId();
    // The grant has no expiry; the signed slot expiry stays the legacy one.
    expect(lastRegistration().expiresAt).toBe(dec31);
  });

  it("F1: a slot of only this PS's entries lasts as long as its longest grant", async () => {
    const first = await approvedGrantId();
    expect(store.getGrant(first)!.grant.expires_at).toBeUndefined();
    expect(lastRegistration().expiresAt).toBe("0");
  });

  it("F2: never signs a scope only the gateway claims (lying gateway)", async () => {
    legacySlot("0");
    // The gateway's view adds scopes the finalized chain does not hold.
    gateway.lie = {
      scopes: [
        "instagram.posts",
        "linkedin.profile",
        "pdpp:sha256:" + "e".repeat(64),
      ],
    };
    const grantId = await approvedGrantId();
    const signed = lastRegistration().scopes;
    expect(signed).toEqual([
      "instagram.posts",
      store.getChainRegistration(grantId)!.entry,
    ]);
    expect(signed).not.toContain("linkedin.profile");
  });

  it("F2: refuses a gateway that answers for another slot id", async () => {
    legacySlot("0");
    gateway.lie = { id: `0x${"c".repeat(64)}` };
    const grantId = await approvedGrantId();
    expect(store.getChainRegistration(grantId)).toMatchObject({
      status: "pending",
      lastError: "gateway answered for another slot id",
    });
    expect(lastRegistrationOrNone()).toBeUndefined();
  });

  function lastRegistrationOrNone() {
    return gateway.requests.find(
      (r) => r.method === "POST" && r.path === "/v1/grants",
    );
  }

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
    // NEW-8: the read answers "retry later" at once and registers in the
    // background; the chain has not settled yet.
    expect(await read(grantId)).toMatchObject({ ok: false, retryable: true });
    await drain();
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
    const second = await approvedGrantId([{ name: "profile", fields: ["*"] }]);
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
    expect(
      Number((del.body as { expiresAt: string }).expiresAt) * 1000,
    ).toBeLessThan(Date.now());
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
    expect(
      deletes.map((d) => (d.body as { grantVersion: string }).grantVersion),
    ).toEqual(["2", "3"]);
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

describe("review round 2: finality, retries, labels, backfill", () => {
  async function bound(streams?: Array<{ name: string; fields: string[] }>) {
    const grantId = await approvedGrantId(streams);
    gateway.settle();
    expect(await read(grantId)).toEqual({ ok: true });
    return grantId;
  }

  it("F5: a removal whose answer was lost is not ended until the finalized chain drops the entry", async () => {
    const first = await bound();
    const second = await bound([{ name: "profile", fields: ["*"] }]);
    gateway.dropNextRegistrationAnswer = true;
    await ownerRevoke(first);
    // The gateway applied the removal (its view no longer lists the entry),
    // but the PS never saw the answer and the chain has not settled.
    const a = store.getChainRegistration(first)!;
    expect(gateway.slot!.scopes).not.toContain(a.entry);
    await chain.registrar.reconcile();
    expect(store.getChainRegistration(first)!.status).toBe("ending");
    gateway.settle();
    await chain.registrar.reconcile();
    expect(store.getChainRegistration(first)!.status).toBe("ended");
    expect(await read(second)).toEqual({ ok: true });
  });

  it("F5: re-signs a removal-only upsert whose transaction failed", async () => {
    const first = await bound();
    await bound([{ name: "profile", fields: ["*"] }]);
    await ownerRevoke(first);
    const sent = store.getChainRegistration(first)!;
    expect(sent).toMatchObject({ status: "ending", endingKind: "removal" });
    gateway.settle({ fail: true });
    await chain.registrar.reconcile();
    const again = store.getChainRegistration(first)!;
    expect(again.status).toBe("ending");
    expect(BigInt(again.endedVersion!)).toBeGreaterThan(
      BigInt(sent.endedVersion!),
    );
    gateway.settle();
    await chain.registrar.reconcile();
    expect(store.getChainRegistration(first)!.status).toBe("ended");
  });

  it("F5: an owner's revocation from elsewhere ends the entry only once final, and is re-signed if it reverts", async () => {
    const grantId = await bound();
    // Account revokes the whole relationship (V2 revocation) at the gateway.
    gateway.slot!.revokedAt = new Date().toISOString();
    gateway.slot!.revocationKind = "v2_upsert";
    gateway.slot!.latest = gateway.current() + 1n;
    await ownerRevoke(grantId);
    expect(store.getChainRegistration(grantId)!.status).toBe("ending");
    expect(gateway.requests.some((r) => r.method === "DELETE")).toBe(false);
    gateway.settle({ revert: true });
    await chain.registrar.reconcile();
    expect(gateway.requests.some((r) => r.method === "DELETE")).toBe(true);
    gateway.settle();
    await chain.registrar.reconcile();
    expect(store.getChainRegistration(grantId)!.status).toBe("ended");
  });

  it("F5: re-registers a bound grant whose registration failed on chain", async () => {
    const grantId = await approvedGrantId();
    gateway.settle({ fail: true });
    await chain.registrar.reconcile();
    expect(gateway.signedVersions).toEqual([1n, 2n]);
    expect(store.getChainRegistration(grantId)!.status).toBe("bound");
    gateway.settle();
    expect(await read(grantId)).toEqual({ ok: true });
  });

  it("F4: ends a consumed single-use grant once its access token is gone", async () => {
    const res = await approve(CLIENT, undefined, { accessMode: "single_use" });
    const { redirect_uri, grant_id } = (await res.json()) as {
      redirect_uri: string;
      grant_id: string;
    };
    await chain.registrar.reconcile();
    gateway.settle();
    const redeemed = tokens.redeemAuthorizationCode({
      code: new URL(redirect_uri).searchParams.get("code")!,
      clientId: CLIENT,
      redirectUri: REDIRECT,
      codeVerifier: VERIFIER,
    });
    expect(redeemed.ok).toBe(true);
    await chain.registrar.reconcile();
    expect(store.getChainRegistration(grant_id)!.status).toBe("bound");
    tokens.revokeAccessToken(redeemed.ok ? redeemed.issued.access_token : "");
    await chain.registrar.reconcile();
    expect(store.getChainRegistration(grant_id)!.status).toBe("ending");
    expect(gateway.requests.some((r) => r.method === "DELETE")).toBe(true);
  });

  it("F4: a hung gateway times out and does not stall the queue", async () => {
    gateway.down = true;
    const grantId = await approvedGrantId();
    gateway.down = false;
    gateway.hang = true;
    const started = Date.now();
    await chain.registrar.reconcile();
    expect(Date.now() - started).toBeLessThan(5_000);
    expect(store.getChainRegistration(grantId)!.lastError).toMatch(
      /time|abort/i,
    );
    gateway.hang = false;
    await chain.registrar.reconcile();
    expect(store.getChainRegistration(grantId)!.status).toBe("bound");
  });

  it("F4: start() reconciles at once and on a timer; stop() ends it", async () => {
    gateway.down = true;
    const grantId = await approvedGrantId();
    gateway.down = false;
    chain.registrar.start(20);
    await new Promise((r) => setTimeout(r, 120));
    await chain.registrar.stop();
    expect(store.getChainRegistration(grantId)!.status).toBe("bound");
  });

  it("F7: one conflicting label does not drop the other bindings", async () => {
    // The gateway already holds the log label with a smaller stream set.
    gateway.bindings.set("pdpp.spotify~.~log", {
      sourceId: SOURCE_ID,
      streams: ["top_artists"],
    });
    const grantId = await approvedGrantId([{ name: "profile", fields: ["*"] }]);
    expect(gateway.bindings.get("pdpp.spotify~.profile")).toEqual({
      sourceId: SOURCE_ID,
      streams: ["profile"],
    });
    expect(gateway.bindings.get("pdpp.spotify~.~log")!.streams).toEqual([
      "top_artists",
    ]);
    const reg = store.getChainRegistration(grantId)!;
    expect(reg.status).toBe("bound");
    expect(reg.lastError).toContain("pdpp.spotify~.~log");
  });

  it("backfill: grants issued while chain grants were off answer retry, not grant_revoked, then bind", async () => {
    const plain = new Hono();
    plain.route(
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
          id === CLIENT ? { client_id: id, redirect_uris: [REDIRECT] } : null,
      }),
    );
    const res = await approve(CLIENT, undefined, { target: plain });
    const { grant_id } = (await res.json()) as { grant_id: string };
    expect(store.getChainRegistration(grant_id)).toBeNull();
    expect(chain.registrar.backfill()).toBe(1);
    expect(chain.registrar.backfill()).toBe(0);
    gateway.down = true;
    expect(await read(grant_id)).toMatchObject({ ok: false, retryable: true });
    gateway.down = false;
    await chain.registrar.reconcile();
    gateway.settle();
    expect(await read(grant_id)).toEqual({ ok: true });
    // The entry fingerprints the client's document (pairwise handles).
    const reg = store.getChainRegistration(grant_id)!;
    expect(reg.entry).toBe(
      computePdppGrantEntry(
        store.clientGrantView(store.getGrant(grant_id)!),
        reg.salt,
      ),
    );
  });
});

describe("never drops a scope another surface is still settling", () => {
  /** Another surface (e.g. MCP) registered `instagram.posts`; not final yet. */
  function foreignSettling(extra: string[] = []) {
    const prior = gateway.slot;
    gateway.slot = {
      id: SLOT_ID,
      scopes: [...(prior?.scopes ?? []), ...extra, "instagram.posts"],
      grantVersion: String(gateway.current() + 1n),
      latest: gateway.current() + 1n,
      expiresAtSeconds: "0",
      revokedAt: null,
      revocationKind: null,
      revocationFinalizedAt: null,
      revocationOutcome: null,
      status: "pending",
      paymentStatus: "pending",
      removalOnly: false,
    };
  }
  const posts = () =>
    gateway.requests.filter(
      (r) => r.method === "POST" && r.path === "/v1/grants",
    );

  it("defers registration while the foreign registration settles, then keeps its scope", async () => {
    foreignSettling();
    const grantId = await approvedGrantId();
    expect(posts()).toHaveLength(0);
    const reg = store.getChainRegistration(grantId)!;
    expect(reg.status).toBe("pending");
    expect(reg.lastError).toMatch(
      /^deferred: another registration for this slot is pending/,
    );
    expect(reg.deferredSince).not.toBeNull();
    // What the PDPP grant sees meanwhile: retry later.
    expect(await read(grantId)).toMatchObject({ ok: false, retryable: true });

    gateway.settle(); // the foreign registration finalizes
    await chain.registrar.reconcile();
    expect(posts()).toHaveLength(1);
    expect((posts()[0].body as { scopes: string[] }).scopes).toEqual([
      "instagram.posts",
      reg.entry,
    ]);
    expect(store.getChainRegistration(grantId)).toMatchObject({
      status: "bound",
      deferredSince: null,
    });
  });

  it("does not keep a foreign scope whose registration reverted", async () => {
    foreignSettling();
    const grantId = await approvedGrantId();
    expect(posts()).toHaveLength(0);
    gateway.settle({ fail: true }); // the foreign registration reverts
    await chain.registrar.reconcile();
    expect((posts()[0].body as { scopes: string[] }).scopes).toEqual([
      store.getChainRegistration(grantId)!.entry,
    ]);
  });

  it("past the bound it still never signs over the settling scope, and tells the owner", async () => {
    foreignSettling();
    const grantId = await approvedGrantId();
    expect(posts()).toHaveLength(0);
    await new Promise((r) => setTimeout(r, 1_100));
    await chain.registrar.reconcile();
    expect(posts()).toHaveLength(0);
    expect(store.getChainRegistration(grantId)).toMatchObject({
      status: "pending",
      deferredOutcome: "pending",
    });
    expect(store.getChainRegistration(grantId)!.lastError).toMatch(
      /^deferred past bound/,
    );
    expect(await read(grantId)).toMatchObject({ ok: false, retryable: true });
    const owner = (await (
      await app.request("/pdpp/v1/grants", {
        headers: { authorization: `Bearer ${ownerToken()}` },
      })
    ).json()) as { grants: Array<{ grant_id: string; chain?: unknown }> };
    expect(owner.grants.find((g) => g.grant_id === grantId)!.chain).toEqual({
      status: "waiting_on_other_grant",
      registration_outcome: "pending",
      since: store.getChainRegistration(grantId)!.deferredSince,
      past_bound: true,
    });
    // Once the other registration finalizes, the PS registers over both.
    gateway.settle();
    await chain.registrar.reconcile();
    expect((posts()[0].body as { scopes: string[] }).scopes).toEqual([
      "instagram.posts",
      store.getChainRegistration(grantId)!.entry,
    ]);
  });

  it("never defers a grant end: the removal goes out at once and overtakes the settling foreign registration", async () => {
    const first = await approvedGrantId();
    const second = await approvedGrantId([{ name: "profile", fields: ["*"] }]);
    gateway.settle();
    const a = store.getChainRegistration(first)!.entry;
    const b = store.getChainRegistration(second)!.entry;
    foreignSettling();
    const before = posts().length;
    await ownerRevoke(first);
    // Sent at once, at currentGrantVersion + 1: own live entry + finalized
    // chain scopes; the foreign scope still settling is not kept.
    const removal = posts().at(-1)!.body as {
      scopes: string[];
      grantVersion: string;
    };
    expect(posts()).toHaveLength(before + 1);
    expect(removal.scopes).toEqual([b]);
    expect(removal.scopes).not.toContain(a);
    expect(removal.scopes).not.toContain("instagram.posts");
    expect(gateway.signedVersions.at(-1)).toBe(BigInt(removal.grantVersion));
    expect(store.getChainRegistration(first)).toMatchObject({
      status: "ending",
      endingKind: "removal",
    });
  });

  it("never defers a revocation either, and re-queues the PS's own pending registration", async () => {
    const first = await approvedGrantId();
    gateway.settle();
    foreignSettling();
    // A second grant for the app is deferred behind the foreign registration.
    const second = await approvedGrantId([{ name: "profile", fields: ["*"] }]);
    expect(store.getChainRegistration(second)!.lastError).toMatch(/^deferred/);
    await ownerRevoke(first);
    const del = gateway.requests.filter((r) => r.method === "DELETE");
    expect(del).toHaveLength(1);
    // The revocation lists only verified scopes (here the ended entry).
    expect((del[0].body as { scopes: string[] }).scopes).toEqual([
      store.getChainRegistration(first)!.entry,
    ]);
    // The own pending registration was re-queued (backoff and deferral
    // cleared) and registers at the next reconcile.
    expect(store.getChainRegistration(second)!.lastError).toBeNull();
    expect(store.getChainRegistration(second)!.deferredSince).toBeNull();
  });

  it("N1: re-signs a removal when a second writer puts the ended entry back", async () => {
    const first = await approvedGrantId();
    const second = await approvedGrantId([{ name: "profile", fields: ["*"] }]);
    gateway.settle();
    const a = store.getChainRegistration(first)!.entry;
    const b = store.getChainRegistration(second)!.entry;
    await ownerRevoke(first);
    const sent = store.getChainRegistration(first)!.endedVersion!;
    // Account, from a stale read, signs the slot with A again, above it.
    const v = gateway.current() + 1n;
    gateway.slot!.scopes = [a, b];
    gateway.slot!.grantVersion = String(v);
    gateway.slot!.latest = v;
    gateway.slot!.status = "pending";
    gateway.settle();
    expect(gateway.chain!.scopes).toContain(a);
    await chain.registrar.reconcile();
    const again = store.getChainRegistration(first)!;
    expect(again.status).toBe("ending");
    expect(BigInt(again.endedVersion!)).toBeGreaterThan(BigInt(sent));
    expect((posts().at(-1)!.body as { scopes: string[] }).scopes).toEqual([b]);
    gateway.settle();
    await chain.registrar.reconcile();
    expect(store.getChainRegistration(first)!.status).toBe("ended");
  });

  it("N4: never re-signs an ended entry a gateway re-lists while its removal is in flight", async () => {
    const first = await approvedGrantId();
    gateway.settle();
    const a = store.getChainRegistration(first)!.entry;
    await approvedGrantId([{ name: "profile", fields: ["*"] }]);
    gateway.settle();
    await ownerRevoke(first); // removal sent, not final
    gateway.lie = { scopes: [a, ...gateway.slot!.scopes] };
    const before = posts().length;
    const third = await approvedGrantId([
      { name: "top_artists", fields: ["id"] },
    ]);
    const after = posts()
      .slice(before)
      .map((p) => (p.body as { scopes: string[] }).scopes);
    // The third grant registers without A, and no later write re-adds A.
    // (The lie also hides the third entry, which the finalized chain does
    // not hold yet; under M1 the PS treats it as dropped and never puts it
    // back: fail closed.)
    expect(after[0]).toContain(store.getChainRegistration(third)!.entry);
    for (const signed of after) expect(signed).not.toContain(a);
  });

  it("N4: one reconcile at a time; a call while one runs joins it", () => {
    const one = chain.registrar.reconcile();
    const two = chain.registrar.reconcile();
    expect(two).toBe(one);
    return one;
  });

  it("N4: backfills a v0.2 grant issued while chain grants were off", () => {
    const grant = {
      version: "0.2.0",
      grant_id: "grt_v02",
      issued_at: new Date().toISOString(),
      subject: { id: OWNER },
      client: { client_id: CLIENT },
      source: { kind: "connector", id: SOURCE_ID },
      source_declaration: { version: "v1" },
      purpose_code: "https://pdpp.dev/purpose/personalization",
      access_mode: "continuous",
      streams: [
        { name: "top_artists", instance_ids: [INSTANCE], fields: ["id"] },
      ],
    } as unknown as Grant;
    store.insertGrant({ grant, subjectId: OWNER, reviewDigest: "r" });
    expect(chain.registrar.backfill()).toBe(1);
    expect(store.getChainRegistration("grt_v02")).toMatchObject({
      status: "pending",
      entry: computePdppGrantEntry(
        grant,
        store.getChainRegistration("grt_v02")!.salt,
      ),
    });
  });

  it("N4: a stored token with no expiry stops counting as usable after the access TTL", () => {
    const grant = {
      version: "0.2.0",
      grant_id: "grt_t",
      issued_at: new Date().toISOString(),
      subject: { id: OWNER },
      client: { client_id: CLIENT },
      source: { kind: "connector", id: SOURCE_ID },
      source_declaration: { version: "v1" },
      purpose_code: "p",
      access_mode: "single_use",
      streams: [
        { name: "top_artists", instance_ids: [INSTANCE], fields: ["id"] },
      ],
    } as unknown as Grant;
    store.insertGrant({ grant, subjectId: OWNER, reviewDigest: "r" });
    const issuedAt = new Date();
    store.issueAccessToken({
      token: "tok_noexp",
      grantId: "grt_t",
      subjectId: OWNER,
      clientId: CLIENT,
      tokenKind: "client",
      expiresAt: null,
      consumeSingleUse: true,
      now: issuedAt,
    });
    expect(store.hasLiveClientToken("grt_t", issuedAt)).toBe(true);
    expect(
      store.hasLiveClientToken(
        "grt_t",
        new Date(issuedAt.getTime() + 2 * 60 * 60 * 1000),
      ),
    ).toBe(false);
  });

  it("R1: re-signs a removal when the gateway slot lists the ended entry again above ended_version, even unsettled", async () => {
    const first = await approvedGrantId();
    const second = await approvedGrantId([{ name: "profile", fields: ["*"] }]);
    gateway.settle();
    const a = store.getChainRegistration(first)!.entry;
    const b = store.getChainRegistration(second)!.entry;
    await ownerRevoke(first);
    const sent = store.getChainRegistration(first)!.endedVersion!;
    // A second writer's upsert re-lists A at the gateway and never settles.
    const v = gateway.current() + 1n;
    gateway.slot!.scopes = [a, b];
    gateway.slot!.grantVersion = String(v);
    gateway.slot!.latest = v;
    gateway.slot!.status = "pending";
    await chain.registrar.reconcile();
    const again = store.getChainRegistration(first)!;
    expect(BigInt(again.endedVersion!)).toBeGreaterThan(BigInt(sent));
    expect((posts().at(-1)!.body as { scopes: string[] }).scopes).toEqual([b]);
  });

  it("R2: with a gateway that sends no registrationOutcome, a listed scope not on the finalized chain defers a new registration", async () => {
    gateway.omitOutcome = true;
    foreignSettling();
    const grantId = await approvedGrantId();
    expect(posts()).toHaveLength(0);
    expect(store.getChainRegistration(grantId)).toMatchObject({
      status: "pending",
      deferredOutcome: "unknown",
    });
    gateway.settle();
    await chain.registrar.reconcile();
    expect((posts()[0].body as { scopes: string[] }).scopes).toEqual([
      "instagram.posts",
      store.getChainRegistration(grantId)!.entry,
    ]);
  });

  it("R2: removals still never wait with such a gateway", async () => {
    const first = await approvedGrantId();
    const second = await approvedGrantId([{ name: "profile", fields: ["*"] }]);
    gateway.settle();
    gateway.omitOutcome = true;
    foreignSettling();
    const before = posts().length;
    await ownerRevoke(first);
    expect(posts()).toHaveLength(before + 1);
    expect((posts().at(-1)!.body as { scopes: string[] }).scopes).toEqual([
      store.getChainRegistration(second)!.entry,
    ]);
  });

  function setPermissionId(grantId: string, permissionId: string) {
    const db = new Database(join(dir, "auth.db"));
    db.prepare(
      "UPDATE pdpp_chain_registrations SET permission_id = ? WHERE grant_id = ?",
    ).run(permissionId, grantId);
    db.close();
  }

  it("final F1: never carries an own entry bound under another slot into a removal", async () => {
    const first = await approvedGrantId();
    const second = await approvedGrantId([{ name: "profile", fields: ["*"] }]);
    gateway.settle();
    const a = store.getChainRegistration(first)!.entry;
    const b = store.getChainRegistration(second)!.entry;
    // B is bound under an old slot; the gateway's view of THIS slot omits it.
    setPermissionId(second, `0x${"d".repeat(64)}`);
    gateway.lie = { scopes: [a] };
    await ownerRevoke(first);
    const written = gateway.requests
      .filter(
        (r) =>
          r.method === "DELETE" ||
          (r.method === "POST" && r.path === "/v1/grants"),
      )
      .at(-1)!;
    expect(written.method).toBe("DELETE");
    expect((written.body as { scopes: string[] }).scopes).toEqual([a]);
    expect((written.body as { scopes: string[] }).scopes).not.toContain(b);
  });

  it("final F1: a refused upsert carrying unlisted own entries is re-sent without them", async () => {
    const first = await approvedGrantId();
    const second = await approvedGrantId([{ name: "profile", fields: ["*"] }]);
    gateway.settle();
    const a = store.getChainRegistration(first)!.entry;
    const b = store.getChainRegistration(second)!.entry;
    gateway.lie = { scopes: [a] }; // the view omits B, bound to this slot
    gateway.refuseEntries = new Set([b]);
    const before = posts().length;
    await ownerRevoke(first);
    // Attempt 1: removal-only [B] (with B's document), refused 409;
    // attempt 2: nothing remains, so a V2 revocation over the verified scopes.
    expect(
      posts()
        .slice(before)
        .map((p) => (p.body as { scopes: string[] }).scopes),
    ).toEqual([[b]]);
    expect(
      (posts().at(-1)!.body as { pdppGrants?: Array<{ entry: string }> })
        .pdppGrants?.[0]?.entry,
    ).toBe(b);
    const del = gateway.requests.filter((r) => r.method === "DELETE");
    expect(del).toHaveLength(1);
    expect((del[0].body as { scopes: string[] }).scopes).toEqual([a]);
    expect(store.getChainRegistration(first)).toMatchObject({
      status: "ending",
      endingKind: "revocation",
    });
    // M1/L1: a carry-specific refusal only drops B; it is never re-added.
    expect(store.getChainRegistration(second)).toMatchObject({
      status: "ended",
      droppedElsewhereAt: expect.any(String),
    });
  });

  it("NEW-7: the fallback drops only the refused unlisted entry, never the listed live ones", async () => {
    const first = await approvedGrantId();
    const second = await approvedGrantId([{ name: "profile", fields: ["*"] }]);
    const third = await approvedGrantId([
      { name: "top_artists", fields: ["id"] },
    ]);
    const stale = await approvedGrantId([
      { name: "top_artists", fields: ["name"] },
    ]);
    gateway.settle();
    const [a, b, c, d] = [first, second, third, stale].map(
      (g) => store.getChainRegistration(g)!.entry,
    );
    setPermissionId(stale, `0x${"d".repeat(64)}`); // bound under an old slot
    // The view lists A and B (live), omits C (live, this slot) and D.
    gateway.lie = { scopes: [a, b] };
    gateway.refuseEntries = new Set([c]);
    const before = posts().length;
    await ownerRevoke(first);
    const written = posts()
      .slice(before)
      .map((p) => (p.body as { scopes: string[] }).scopes);
    expect(written).toEqual([[b, c], [b]]);
    for (const w of written) expect(w).not.toContain(d);
    expect(store.getChainRegistration(second)!.status).toBe("bound");
    // The refused carried entry is dropped, never re-queued (M1).
    expect(store.getChainRegistration(third)).toMatchObject({
      status: "ended",
      droppedElsewhereAt: expect.any(String),
    });
  });

  it("NEW-2: a label over 256 streams is not sent and the owner sees the grant as not fully bindable", async () => {
    const many = Array.from({ length: 257 }, (_, i) => `s${i}`);
    const wide = createDesign2ChainGrants({
      store,
      logger,
      ready: {
        gatewayUrl: GATEWAY,
        fetch: gateway.fetch as typeof fetch,
        chain: gateway.reader,
        retryBackoffMs: 0,
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
        clients: [{ clientId: CLIENT, granteeAddress: GRANTEE }],
        link: () => ({ connector: "spotify", namespace: "" }),
        declaredStreams: () => many,
        logScope,
        streamScope,
      },
    });
    // Issued while chain grants were off, then registered by `wide`.
    const plain = new Hono();
    plain.route(
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
          id === CLIENT ? { client_id: id, redirect_uris: [REDIRECT] } : null,
      }),
    );
    const res = await approve(CLIENT, undefined, { target: plain });
    const { grant_id } = (await res.json()) as { grant_id: string };
    expect(wide.registrar.backfill()).toBe(1);
    await wide.registrar.register(grant_id);
    const reg = store.getChainRegistration(grant_id)!;
    expect(reg.status).toBe("bound");
    expect(reg.unboundLabels).toEqual([
      { scope: "pdpp.spotify~.~log", reason: "too_many_streams" },
    ]);
    expect(gateway.bindings.has("pdpp.spotify~.~log")).toBe(false);
    expect(gateway.bindings.has("pdpp.spotify~.top_artists")).toBe(true);
  });

  it("NEW-2: the owner view reports unbound labels and bindable: false", async () => {
    const grantId = await approvedGrantId();
    store.noteUnboundLabels(grantId, [
      { scope: "pdpp.spotify~.~log", reason: "too_many_streams" },
    ]);
    const owner = (await (
      await app.request("/pdpp/v1/grants", {
        headers: { authorization: `Bearer ${ownerToken()}` },
      })
    ).json()) as { grants: Array<{ grant_id: string; chain?: unknown }> };
    expect(owner.grants.find((g) => g.grant_id === grantId)!.chain).toEqual({
      status: "bound",
      unbound_labels: [
        { scope: "pdpp.spotify~.~log", reason: "too_many_streams" },
      ],
      bindable: false,
    });
  });

  it("gateway 6ae5d92: labels are sent in one batched request with per-binding results; a conflict keeps the others", async () => {
    gateway.bindings.set("spotify.profile", {
      sourceId: SOURCE_ID,
      streams: ["other"],
    });
    const grantId = await approvedGrantId();
    expect(gateway.bindingRequests).toBe(1);
    expect(gateway.bindings.get("pdpp.spotify~.top_artists")).toBeDefined();
    expect(store.getChainRegistration(grantId)!.unboundLabels).toEqual([
      { scope: "spotify.profile", reason: "already_bound" },
    ]);
  });

  it("final F3: with no registrationOutcome, a failed slot is not settling", async () => {
    gateway.omitOutcome = true;
    foreignSettling();
    gateway.slot!.status = "failed";
    const grantId = await approvedGrantId();
    expect(posts()).toHaveLength(1);
    expect((posts()[0].body as { scopes: string[] }).scopes).toEqual([
      store.getChainRegistration(grantId)!.entry,
    ]);
    expect(store.getChainRegistration(grantId)!.deferredSince).toBeNull();
  });

  it("M1: an own entry another signer dropped is never put back, and stays dropped after another grant ends", async () => {
    const first = await approvedGrantId();
    const second = await approvedGrantId([{ name: "profile", fields: ["*"] }]);
    const third = await approvedGrantId([
      { name: "top_artists", fields: ["id"] },
    ]);
    gateway.settle();
    const [a, b, c] = [first, second, third].map(
      (g) => store.getChainRegistration(g)!.entry,
    );
    // Account drops B (POST without B) and it finalizes.
    const v = gateway.current() + 1n;
    gateway.slot!.scopes = [a, c];
    gateway.slot!.grantVersion = String(v);
    gateway.slot!.latest = v;
    gateway.settle();
    const before = posts().length;
    await ownerRevoke(first);
    const written = posts()
      .slice(before)
      .map((p) => (p.body as { scopes: string[] }).scopes);
    expect(written).toEqual([[c]]);
    expect(store.getChainRegistration(second)).toMatchObject({
      status: "ended",
      droppedElsewhereAt: expect.any(String),
    });
    // Reads refused; the owner sees it; no automatic re-registration.
    expect(await read(second)).toMatchObject({ ok: false, retryable: false });
    gateway.settle();
    await chain.registrar.reconcile();
    await chain.registrar.reconcile();
    for (const p of posts().slice(before))
      expect((p.body as { scopes: string[] }).scopes).not.toContain(b);
    const owner = (await (
      await app.request("/pdpp/v1/grants", {
        headers: { authorization: `Bearer ${ownerToken()}` },
      })
    ).json()) as {
      grants: Array<{ grant_id: string; chain?: { status: string } }>;
    };
    expect(owner.grants.find((g) => g.grant_id === second)!.chain!.status).toBe(
      "dropped_elsewhere",
    );
  });

  it("M1: reconcile marks a bound entry dropped when neither the gateway nor the finalized chain lists it", async () => {
    const first = await approvedGrantId();
    const second = await approvedGrantId([{ name: "profile", fields: ["*"] }]);
    gateway.settle();
    const a = store.getChainRegistration(first)!.entry;
    const v = gateway.current() + 1n;
    gateway.slot!.scopes = [a];
    gateway.slot!.grantVersion = String(v);
    gateway.slot!.latest = v;
    gateway.settle();
    await chain.registrar.reconcile();
    expect(
      store.getChainRegistration(second)!.droppedElsewhereAt,
    ).not.toBeNull();
    expect(store.getChainRegistration(first)!.status).toBe("bound");
  });

  it("L1: a stale-version 409 re-reads and retries the same write; nothing is dropped or re-queued", async () => {
    const first = await approvedGrantId();
    const second = await approvedGrantId([{ name: "profile", fields: ["*"] }]);
    gateway.settle();
    const b = store.getChainRegistration(second)!.entry;
    gateway.bumpBeforeNextPost = true;
    const before = posts().length;
    await ownerRevoke(first);
    const written = posts().slice(before);
    expect(written).toHaveLength(2);
    expect((written[1].body as { scopes: string[] }).scopes).toEqual([b]);
    expect(
      BigInt((written[1].body as { grantVersion: string }).grantVersion),
    ).toBeGreaterThan(
      BigInt((written[0].body as { grantVersion: string }).grantVersion),
    );
    expect(store.getChainRegistration(second)).toMatchObject({
      status: "bound",
      droppedElsewhereAt: null,
      lastError: null,
    });
    expect(store.getChainRegistration(first)).toMatchObject({
      status: "ending",
      endingKind: "removal",
    });
  });
});
