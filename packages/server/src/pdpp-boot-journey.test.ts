/**
 * PDPP boot journey: the integrated journey on a REAL bootstrapped server.
 *
 * The sibling `pdpp-integrated-journey.test.ts` proves the AS<->RS seam by
 * composing both route modules into a hand-built `createApp`. This file
 * removes that harness: everything here goes through `createServer` — the
 * same entrypoint the CLI and Docker image use — with a real config, a real
 * on-disk storage root, a real SQLite index, a real derived server owner,
 * real declaration files on disk, and a real owner token minted by the
 * mounted `POST /pdpp/v1/owner/token` route behind the server's own owner
 * proof.
 *
 * What is a fixture here and what is not:
 *   - FIXTURE (legitimate): the declaration document and the seeded records.
 *     Those are test *data*; they have to be deterministic.
 *   - NOT FIXTURE: the server, the config parsing, the index, the owner
 *     derivation, the owner token, the declaration trust policy, the grant,
 *     the access token, and every enforcement decision. No fabricated grant
 *     or token is accepted anywhere in this file.
 *
 * The AS lane's own `pdpp/bootstrap.test.ts` already covers the AS half on a
 * real server (authorize -> review -> approve -> token -> introspect ->
 * revoke). This file deliberately does NOT duplicate that. It covers the part
 * neither lane's suite reaches: whether a real bootstrapped server can serve
 * a grant-bound RESOURCE read, and whether grant state survives a restart.
 *
 * Deployment-shaped helpers (KNOWN_SIG, seedScope, writeDeclaration,
 * pdppConfig, boot, ownerToken) follow `packages/server/src/pdpp/
 * bootstrap.test.ts` from the AS lane (`feat/pdpp-as-grants`), as that lane
 * offered — they are deployment mechanics, not assertions, and duplicating
 * them differently would only risk the two suites disagreeing about what a
 * real boot looks like.
 */

import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { computeS256Challenge } from "@opendatalabs/personal-server-ts-core/pdpp";
import { createServer, type ServerContext } from "./bootstrap.js";
import { initializeDatabase } from "./storage/index-schema.js";

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
      primary_key: ["id"],
    },
  ],
});

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

function pdppConfig(declarationPaths: string[]) {
  return ServerConfigSchema.parse({
    tunnel: { enabled: false },
    pdpp: {
      enabled: true,
      declarationPaths,
      clients: [{ clientId: CLIENT_ID, redirectUris: [REDIRECT] }],
    },
  });
}

async function boot() {
  return createServer(pdppConfig([await writeDeclaration()]), {
    serverDir: tempDir,
    dataDir: join(tempDir, "data"),
  });
}

/** Mint a real owner token through the mounted route, behind the owner proof. */
async function ownerToken(context: ServerContext): Promise<string> {
  const response = await context.app.request("/pdpp/v1/owner/token", {
    method: "POST",
    headers: { authorization: `Bearer ${context.devToken}` },
  });
  expect(response.status).toBe(200);
  const body = (await response.json()) as { access_token: string };
  return body.access_token;
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
  tempDir = await mkdtemp(join(tmpdir(), "pdpp-boot-journey-"));
  vi.stubEnv("VANA_MASTER_KEY_SIGNATURE", KNOWN_SIG);
  seedScope(SCOPE);
});

afterEach(async () => {
  await ctx?.cleanup();
  ctx = undefined;
  await rm(tempDir, { recursive: true, force: true });
  vi.unstubAllEnvs();
});

describe("PDPP boot journey: real createServer", () => {
  it("issues a real grant-bound token on a real bootstrapped server", async () => {
    ctx = await boot();
    const { grantId, accessToken } = await obtainGrantBoundToken(ctx);
    expect(grantId).toBeTruthy();

    // Introspection is the AS's own statement about the token it minted.
    // RFC 7662 requires the caller to authenticate; on this co-located
    // deployment the owner token is that credential.
    const introspected = await ctx.app.request("/pdpp/v1/introspect", {
      method: "POST",
      headers: {
        authorization: `Bearer ${await ownerToken(ctx)}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ token: accessToken }).toString(),
    });
    expect(introspected.status).toBe(200);
    const body = (await introspected.json()) as {
      active: boolean;
      pdpp_token_kind?: string;
      grant_id?: string;
      authorization_details?: {
        streams: { name: string; fields: string[]; instance_ids: string[] }[];
      }[];
    };

    expect(body.active).toBe(true);
    expect(body.pdpp_token_kind).toBe("client");
    expect(body.grant_id).toBe(grantId);

    // Axis resolution really ran against the on-disk declaration: the field
    // set is the requested `name` plus the declaration's required `id` floor,
    // and the instance handle was resolved from the deployment's inventory
    // rather than asserted by the client.
    const stream = body.authorization_details?.[0]?.streams.find(
      (s) => s.name === "top_artists",
    );
    expect(stream).toBeDefined();
    expect(new Set(stream!.fields)).toEqual(new Set(["id", "name"]));
    expect(stream!.instance_ids).toHaveLength(1);
  });

  /**
   * BLOCKER, and the reason this file exists.
   *
   * `createServer` wires ONLY the Authorization Server (`createPdppAuthDeps`
   * -> `pdppAuth` -> `/pdpp/v1`). It never populates `AppDeps.pdpp`, which is
   * what mounts the Resource Server surface (`/v1/streams`, `/v1/blobs`,
   * `/.well-known/oauth-protected-resource`). Verified: `pdpp:` does not
   * appear in `packages/server/src/bootstrap.ts`.
   *
   * So on a REAL Personal Server today, PDPP can issue a perfectly valid
   * grant-bound token that has nothing to read: the token is real, the grant
   * is real, and the resource surface does not exist. The composed
   * `createApp` journey cannot see this, because that harness supplies
   * `deps.pdpp` itself.
   *
   * This test asserts the INTENDED behavior (a grant-bound read succeeds) and
   * therefore FAILS until the RS is bootstrapped. It is not a characterization
   * test and must not be weakened to match current behavior.
   *
   * Owner: this is `createServer` wiring plus an RS record-store/declaration
   * source, so it needs the RS lane and whoever owns bootstrap to agree where
   * the record store comes from on a real deployment.
   */
  it("serves a grant-bound resource read on a real bootstrapped server", async () => {
    ctx = await boot();
    const { accessToken } = await obtainGrantBoundToken(ctx);

    const res = await ctx.app.request("/v1/streams/top_artists/records", {
      headers: { authorization: `Bearer ${accessToken}` },
    });

    // The RS surface must exist and must honor the grant. A 404 here means
    // the route is not mounted at all on a real server.
    expect(res.status).not.toBe(404);
    expect(res.status).toBe(200);
  });

  /**
   * RFC 9728 protected-resource metadata is how a client discovers where to
   * authorize. It is part of the RS surface, so it shares the gap above.
   */
  it("publishes protected-resource metadata on a real bootstrapped server", async () => {
    ctx = await boot();
    const res = await ctx.app.request("/.well-known/oauth-protected-resource");
    expect(res.status).toBe(200);
  });

  /**
   * SECURITY BLOCKER — open redirect / authorization-code exfiltration.
   *
   * `POST /pdpp/v1/authorize` checks only that `redirect_uri` is PRESENT
   * (`routes/pdpp-auth.ts`: `if (!body.client_id || !body.redirect_uri)`).
   * It is never validated against registered client metadata, never checked
   * for scheme, host, or exact match, and no `client_id_metadata_document`
   * lookup constrains it. The session stores it verbatim and
   * `/approve` echoes it back with the authorization code appended.
   *
   * Confirmed on a REAL bootstrapped server, not a stub:
   *   authorizeStatus: 201
   *   approveStatus:   200
   *   redirect: "https://evil.attacker.example/steal?code=pdpp_code_3dba37..."
   *
   * Impact: any party who can start an authorization for a client_id receives
   * the code at a host of their choosing. PKCE does NOT close this — the same
   * party supplies the challenge, so it holds the verifier too. The owner sees
   * a consent screen naming a legitimate client and approves a real grant
   * whose code is delivered to an attacker.
   *
   * OWNER: AS / security (`pdpp-as-build-0917`). The fix is redirect_uri
   * validation at `/authorize` against the client's registered or
   * document-resolved redirect URIs, with exact matching.
   *
   * This asserts the INTENDED behavior and therefore FAILS today. It is a
   * security regression test, not a characterization test, and must not be
   * relaxed to match current behavior.
   */
  it("refuses an authorization request with an unregistered redirect_uri", async () => {
    ctx = await boot();
    const owner = await ownerToken(ctx);

    const authorized = await ctx.app.request("/pdpp/v1/authorize", {
      method: "POST",
      headers: {
        authorization: `Bearer ${owner}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        client_id: CLIENT_ID,
        redirect_uri: "https://evil.attacker.example/steal",
        code_challenge: CHALLENGE,
        code_challenge_method: "S256",
        client_display: { name: "Concert Finder" },
        authorization_details: [
          {
            type: "https://pdpp.dev/data-access",
            source: { id: SOURCE_ID },
            purpose_code: "https://pdpp.dev/purpose/personalization",
            access_mode: "continuous",
            streams: [{ name: "top_artists", fields: ["name"] }],
          },
        ],
      }),
    });

    // An unregistered redirect target must be refused before the owner is
    // ever shown a consent screen — RFC 6749 §3.1.2.4 / §10.6.
    expect(authorized.status).toBe(400);
  });

  /**
   * One client, one `PDPP-Version`, both halves of the same server.
   *
   * The two lanes picked version constants independently and of different
   * kinds — the AS used `PDPP_API_VERSION = "0.1.0"` (semver), the RS routes
   * used `PDPP_VERSION = "2026-04-06"` (a date). Both surfaces hard-reject an
   * unrecognized value, so before this was unified a client pinning either
   * one could reach only half the server:
   *
   *   AS + "0.1.0"      -> 201     AS + "2026-04-06" -> 400 unsupported_version
   *   RS + "2026-04-06" -> 200     RS + "0.1.0"      -> 400 unsupported_version
   *
   * Every existing test missed it by omitting the header or by sending the
   * value matching the one surface under test. This sends ONE header to BOTH
   * halves, which is the only shape that catches a divergence.
   */
  it("negotiates one PDPP-Version across both the AS and the RS", async () => {
    ctx = await boot();
    const { accessToken } = await obtainGrantBoundToken(ctx);
    const owner = await ownerToken(ctx);

    // Whatever the server echoes is the version a real client would pin.
    const probe = await ctx.app.request("/v1/streams", {
      headers: { authorization: `Bearer ${accessToken}` },
    });
    const negotiated = probe.headers.get("PDPP-Version");
    expect(negotiated).toBeTruthy();

    // The RS accepts it and echoes it back.
    const rs = await ctx.app.request("/v1/streams", {
      headers: {
        authorization: `Bearer ${accessToken}`,
        "PDPP-Version": negotiated!,
      },
    });
    expect(rs.status).toBe(200);
    expect(rs.headers.get("PDPP-Version")).toBe(negotiated);

    // The AS must accept the SAME value, not a different one.
    const as = await ctx.app.request("/pdpp/v1/introspect", {
      method: "POST",
      headers: {
        authorization: `Bearer ${owner}`,
        "content-type": "application/x-www-form-urlencoded",
        "PDPP-Version": negotiated!,
      },
      body: new URLSearchParams({ token: accessToken }).toString(),
    });
    expect(as.status).toBe(200);
    expect(as.headers.get("PDPP-Version")).toBe(negotiated);
  });

  /**
   * Durability: an issued grant must survive a process restart against the
   * same storage root, without a fresh owner signature. The AS lane proves
   * the grant row persists; this adds the part that matters operationally —
   * the ALREADY-ISSUED ACCESS TOKEN still resolves after restart, so a client
   * holding a token does not silently lose access when the server bounces.
   */
  it("keeps an issued token valid across a restart of the same storage root", async () => {
    ctx = await boot();
    const { grantId, accessToken } = await obtainGrantBoundToken(ctx);

    await ctx.cleanup();
    ctx = await boot();

    const introspected = await ctx.app.request("/pdpp/v1/introspect", {
      method: "POST",
      headers: {
        authorization: `Bearer ${await ownerToken(ctx)}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ token: accessToken }).toString(),
    });
    expect(introspected.status).toBe(200);
    const body = (await introspected.json()) as {
      active: boolean;
      grant_id?: string;
    };
    expect(body.active).toBe(true);
    expect(body.grant_id).toBe(grantId);
  });

  /**
   * Revocation must also be durable in the other direction: a revoked grant
   * must stay revoked across a restart. A revocation that a restart forgets
   * would resurrect access the owner explicitly withdrew, which is the more
   * dangerous failure of the two.
   */
  it("keeps a revoked grant revoked across a restart", async () => {
    ctx = await boot();
    const { grantId, accessToken } = await obtainGrantBoundToken(ctx);
    const owner = await ownerToken(ctx);

    const revoked = await ctx.app.request("/pdpp/v1/revoke", {
      method: "POST",
      headers: {
        authorization: `Bearer ${owner}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ grant_id: grantId }).toString(),
    });
    expect(revoked.status).toBe(200);

    await ctx.cleanup();
    ctx = await boot();

    const introspected = await ctx.app.request("/pdpp/v1/introspect", {
      method: "POST",
      headers: {
        authorization: `Bearer ${await ownerToken(ctx)}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ token: accessToken }).toString(),
    });
    expect(introspected.status).toBe(200);
    // RFC 7662 §2.2: an inactive token reveals nothing else.
    expect((await introspected.json()) as unknown).toEqual({ active: false });
  });
});
