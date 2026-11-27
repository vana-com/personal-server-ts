/**
 * Review F6: design 2 through the real boot wiring (`createServer` with
 * `pdpp.chainGrants.enabled: true`), not through the ports. A client token's
 * record read and blob read are refused before the registration is on chain
 * (retry), served after it settles, and refused after the owner revokes.
 * The gateway is an HTTP fake injected as the server's outbound fetch; the
 * chain is a fake PermissionsV2 reader (the only two seams).
 */

import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { computeS256Challenge } from "@opendatalabs/personal-server-ts-core/pdpp";
import { recoverServerOwner } from "@opendatalabs/vana-sdk/node";
import type { ServerContext } from "./bootstrap.js";
import { createUnswitchedServer as createServer } from "./account-mode/unswitched-server.test-utils.js";
import { initializeDatabase } from "./storage/index-schema.js";
import {
  domainSeparator as viemDomainSeparator,
  encodeAbiParameters,
  keccak256,
} from "viem";
import { registerTestConnection } from "./pdpp/test-connections.js";

/** Derives a stable owner address; same signature the bootstrap suites use. */
const KNOWN_SIG =
  "0xedbb7743cce459345238442dcfb291f234a321d253485eaa58251aa0f28ea8f1410ab988bae2657b689cd24417b41e315efc22ba333024f4a6269c424ded8d361b";

const SOURCE_ID = "https://registry.pdpp.dev/connectors/spotify";
const SCOPE = "spotify.top_artists";
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE = computeS256Challenge(VERIFIER);
const REDIRECT = "https://app.example.com/callback";

/**
 * `source_updated_at` is the declared consent_time_field, and the grant below
 * requests a window over it while NOT requesting the field itself — the case
 * that must survive field projection.
 */
const DECLARATION = JSON.stringify({
  source_id: SOURCE_ID,
  source_kind: "connector",
  version: "2026-08-11",
  streams: [
    {
      name: "top_artists",
      fields: ["id", "name", "genres", "source_updated_at"],
      required_fields: ["id"],
      consent_time_field: "source_updated_at",
      // locked v0.1.0 (AS item 27): a consent_time_field must name a
      // declared date or date-time string property.
      schema: {
        properties: {
          source_updated_at: { type: "string", format: "date-time" },
        },
      },
      primary_key: ["id"],
    },
  ],
});


const DOMAIN = {
  name: "Vana Data Portability",
  version: "1",
  chainId: 14800,
  verifyingContract: "0x4d3FA76064D88e0454cFc4CaD7e5FeC3e3124011",
} as const;
const SEPARATOR = viemDomainSeparator({ domain: DOMAIN });

/** Just enough of the design-2 gateway for one owner and one app. */
class BootGateway {
  slotId: `0x${string}`;
  scopes: string[] = [];
  version = 0n;
  revoked = false;
  chainScopes: string[] | null = null;
  constructor(owner: string) {
    this.slotId = keccak256(
      encodeAbiParameters(
        [{ type: "bytes32" }, { type: "address" }, { type: "bytes32" }],
        [SEPARATOR, owner as `0x${string}`, BUILDER_ID],
      ),
    );
  }
  settle() {
    this.chainScopes = this.revoked ? [] : [...this.scopes];
  }
  reader = {
    domainSeparator: async () => SEPARATOR,
    readFinalized: async (id: `0x${string}`) => ({
      blockTimestamp: BigInt(Math.floor(Date.now() / 1000)),
      permission:
        this.chainScopes && id === this.slotId
          ? {
              grantorAddress: "0x0",
              granteeId: BUILDER_ID,
              scopes: this.chainScopes,
              grantVersion: this.version,
              expiresAt: 0n,
            }
          : null,
    }),
  };
  fetch = async (input: unknown, init?: RequestInit): Promise<Response> => {
    const url = new URL(String(input));
    const method = init?.method ?? "GET";
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    if (method === "GET" && url.pathname === `/v1/builders/${GRANTEE}`)
      return Response.json({ data: { id: BUILDER_ID, granteeAddress: GRANTEE } });
    if (method === "PUT" && url.pathname === "/v1/pdpp/scope-bindings")
      return Response.json({ data: {} });
    if (method === "GET" && url.pathname === `/v1/grants/${this.slotId}`)
      return this.version === 0n
        ? new Response(null, { status: 404 })
        : Response.json({
            data: {
              id: this.slotId,
              granteeId: BUILDER_ID,
              scopes: this.scopes,
              grantVersion: this.version.toString(),
              currentGrantVersion: this.version.toString(),
              expiresAtSeconds: "0",
              expired: false,
              status: "finalized",
              revokedAt: this.revoked ? new Date().toISOString() : null,
              revocationKind: this.revoked ? "v2_upsert" : null,
              revocationFinalizedAt: null,
              revocationOutcome: null,
            },
          });
    if (method === "POST" && url.pathname === "/v1/grants") {
      if (BigInt(body.grantVersion) !== this.version + 1n)
        return Response.json({ currentGrantVersion: this.version.toString() }, { status: 409 });
      this.version = BigInt(body.grantVersion);
      this.scopes = body.scopes;
      return Response.json(
        { success: true, grantId: this.slotId, grantVersion: body.grantVersion },
        { status: 201 },
      );
    }
    if (method === "DELETE" && url.pathname === `/v1/grants/${this.slotId}`) {
      this.version = BigInt(body.grantVersion);
      this.revoked = true;
      return Response.json({ success: true, revocationKind: "v2_upsert" });
    }
    if (method === "GET" && url.pathname === "/v1/pdpp/chain-binding") {
      const entry = this.scopes.find((s) => s.startsWith("pdpp:"));
      if (!entry) return new Response(null, { status: 404 });
      return Response.json({
        data: {
          bindings: [
            {
              chainId: "14800",
              contractAddress: DOMAIN.verifyingContract,
              permissionId: this.slotId,
              entry,
              pdppGrantId: url.searchParams.get("grantId"),
              pdppExpired: false,
              gateway: { entryListed: true, slotRevoked: this.revoked, slotExpired: false },
              onChain: {
                entryPresent: !!this.chainScopes?.includes(entry),
                slotActive: !!this.chainScopes,
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

let gateway: BootGateway;

let tempDir: string;
let ctx: ServerContext | undefined;

/**
 * Seed the real index so the connector inventory is non-empty. The
 * declaration trust policy is derived from what this PS actually serves, so
 * without data for `spotify` the declaration is (correctly) refused and
 * `/pdpp/v1` never mounts.
 */
function seedScope(scope: string): void {
  const db = initializeDatabase(join(tempDir, "index.db"));
  db.prepare(
    `INSERT INTO data_files (file_id, path, scope, collected_at, size_bytes)
     VALUES (?, ?, ?, ?, ?)`,
  ).run(
    "file-1",
    `${scope.split(".").join("/")}/2026-01-01T00:00:00Z.json`,
    scope,
    "2026-01-01T00:00:00Z",
    128,
  );
  db.close();
}

async function writeDeclaration(document = DECLARATION): Promise<string> {
  const dir = join(tempDir, "declarations");
  await mkdir(dir, { recursive: true });
  const path = join(dir, "spotify.json");
  await writeFile(path, document, "utf-8");
  return path;
}

/**
 * `redirect_uri` is validated by exact match against a registered client, so
 * a real deployment must register one. The redirect-rejection test below
 * relies on `https://evil.attacker.example/steal` NOT being in this list.
 */
const CLIENT_ID = "music_recommendations";
const GRANTEE = "0x2222222222222222222222222222222222222222";
const BUILDER_ID = `0x${"b".repeat(64)}` as `0x${string}`;

function pdppConfig(declarationPaths: string[]) {
  return ServerConfigSchema.parse({
    tunnel: { enabled: false },
    pdpp: {
      enabled: true,
      declarationPaths,
      methods: declarationPaths.map((declaration_path) => ({
        method_id: "spotify",
        declaration_path,
      })),
      clients: [
        { clientId: CLIENT_ID, redirectUris: [REDIRECT], granteeAddress: GRANTEE },
      ],
      chainGrants: { enabled: true },
    },
  });
}

async function boot() {
  return createServer(pdppConfig([await writeDeclaration()]), {
    serverDir: tempDir,
    dataDir: join(tempDir, "data"),
    outboundFetch: gateway.fetch as typeof fetch,
    pdppChainReader: gateway.reader,
  });
}

/** Mint a real owner token through the mounted route, behind the owner proof. */
async function ownerToken(context: ServerContext): Promise<string> {
  const serverOwner = await recoverServerOwner(KNOWN_SIG);
  return registerTestConnection(
    context.app,
    context.devToken,
    serverOwner,
    SOURCE_ID,
  );
}

/**
 * Drive the real AS on a real server to a grant-bound client access token.
 * Every step is a real HTTP call against the bootstrapped app; nothing is
 * constructed by hand.
 */
async function obtainGrantBoundToken(
  context: ServerContext,
): Promise<{ grantId: string; accessToken: string }> {
  const app = context.app;
  const owner = await ownerToken(context);
  const ownerAuth = { authorization: `Bearer ${owner}` };

  const authorized = await app.request("/pdpp/v1/authorize", {
    method: "POST",
    headers: { ...ownerAuth, "content-type": "application/json" },
    body: JSON.stringify({
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT,
      code_challenge: CHALLENGE,
      code_challenge_method: "S256",
      client_display: { name: "Concert Finder" },
      authorization_details: [
        {
          type: "https://pdpp.dev/data-access",
          source: { id: SOURCE_ID },
          purpose_code: "https://pdpp.dev/purpose/personalization",
          access_mode: "continuous",
          // `name` only: neither the required `id` floor nor the
          // consent_time_field is requested explicitly.
          streams: [
            {
              name: "top_artists",
              fields: ["name"],
              time_range: { since: "2026-01-01T00:00:00.000Z" },
            },
          ],
        },
      ],
    }),
  });
  expect(authorized.status).toBe(201);
  const { session_id } = (await authorized.json()) as { session_id: string };

  const reviewed = await app.request(
    `/pdpp/v1/authorize/${session_id}/review`,
    { headers: ownerAuth },
  );
  expect(reviewed.status).toBe(200);
  const review = (await reviewed.json()) as {
    review?: { review_digest: string };
  };
  expect(review.review?.review_digest).toBeTruthy();

  const approved = await app.request(
    `/pdpp/v1/authorize/${session_id}/approve`,
    {
      method: "POST",
      headers: { ...ownerAuth, "content-type": "application/json" },
      body: JSON.stringify({ review_digest: review.review!.review_digest }),
    },
  );
  expect(approved.status).toBe(200);
  const approval = (await approved.json()) as {
    redirect_uri: string;
    grant_id: string;
  };

  const code = new URL(approval.redirect_uri).searchParams.get("code");
  expect(code).toBeTruthy();

  const tokenRes = await app.request("/pdpp/v1/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: code!,
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT,
      code_verifier: VERIFIER,
    }).toString(),
  });
  expect(tokenRes.status).toBe(200);
  const token = (await tokenRes.json()) as { access_token: string };
  expect(token.access_token).toBeTruthy();

  return { grantId: approval.grant_id, accessToken: token.access_token };
}

beforeEach(async () => {
  gateway = new BootGateway(await recoverServerOwner(KNOWN_SIG));
  tempDir = await mkdtemp(join(tmpdir(), "pdpp-chain-boot-"));
  vi.stubEnv("VANA_MASTER_KEY_SIGNATURE", KNOWN_SIG);
  seedScope(SCOPE);
});

afterEach(async () => {
  await ctx?.cleanup();
  ctx = undefined;
  await rm(tempDir, { recursive: true, force: true });
  vi.unstubAllEnvs();
});


describe("design 2 through createServer (review F6)", () => {
  it("records and blob reads: retry before settle, served after, revoked after the owner revokes", async () => {
    ctx = await boot();
    const { grantId, accessToken } = await obtainGrantBoundToken(ctx);
    const auth = { authorization: `Bearer ${accessToken}` };
    const records = () =>
      ctx!.app.request("/v1/streams/top_artists/records", { headers: auth });
    // The gate runs before any blob lookup, so an unknown blob id shows it:
    // denied by the gate, or past it (404 blob_not_found).
    const blob = async () => {
      const handle = (
        (await (
          await ctx!.app.request("/pdpp/v1/introspect", {
            method: "POST",
            headers: {
              authorization: `Bearer ${await ownerToken(ctx!)}`,
              "content-type": "application/x-www-form-urlencoded",
            },
            body: new URLSearchParams({ token: accessToken }).toString(),
          })
        ).json()) as {
          authorization_details?: { grant: { streams: { instance_ids: string[] }[] } }[];
        }
      ).authorization_details?.[0]?.grant.streams[0].instance_ids[0];
      return ctx!.app.request(
        `/v1/blobs/blob_x?instance_id=${encodeURIComponent(handle ?? "none")}`,
        { headers: auth },
      );
    };

    // Registered (the route registers after approval) but not settled.
    await new Promise((r) => setTimeout(r, 50));
    expect(gateway.scopes.some((s) => s.startsWith("pdpp:sha256:"))).toBe(true);
    for (const res of [await records(), await blob()]) {
      expect(res.status).toBe(500);
      expect(res.headers.get("retry-after")).toBe("5");
    }

    gateway.settle();
    expect((await records()).status).toBe(200);
    const pastGate = await blob();
    expect(pastGate.status).toBe(404);
    expect(((await pastGate.json()) as { error: { code: string } }).error.code).toBe(
      "blob_not_found",
    );

    const revoked = await ctx.app.request("/pdpp/v1/revoke", {
      method: "POST",
      headers: {
        authorization: `Bearer ${await ownerToken(ctx)}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ grant_id: grantId, disposition: "keep" }).toString(),
    });
    expect(revoked.status).toBeLessThan(300);
    for (const res of [await records(), await blob()]) expect(res.status).toBe(401);
    // The grant end reached the gateway as a V2 revocation.
    await new Promise((r) => setTimeout(r, 50));
    expect(gateway.revoked).toBe(true);
  });
});
