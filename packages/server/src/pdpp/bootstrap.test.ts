/**
 * Acceptance: the PDPP Authorization Server on a REAL bootstrapped Personal
 * Server.
 *
 * Everything here goes through `createServer` — the same entrypoint the CLI
 * and Docker image use — with a real config, a real on-disk storage root, a
 * real SQLite index, a real derived server owner, and the real declaration
 * trust policy. No hand-constructed Hono app, no injected fake store, no
 * fabricated owner token: the token is minted by the mounted
 * `POST /pdpp/v1/owner/token` route behind the server's own owner proof.
 *
 * The journey asserted is the full OAuth grant flow with PKCE:
 *
 *   owner token -> authorize -> review -> approve -> redeem code -> introspect
 *   -> revoke -> introspect again
 *
 * The negative cases matter as much as the happy path, so the mounting tests
 * below prove the surface stays absent when the deployment cannot support it.
 */

import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { computeS256Challenge } from "@opendatalabs/personal-server-ts-core/pdpp";
import { recoverServerOwner } from "@opendatalabs/vana-sdk/node";
import { createServer, type ServerContext } from "../bootstrap.js";
import { initializeDatabase } from "../storage/index-schema.js";

/**
 * The signature the existing bootstrap suite uses; `recoverServerOwner`
 * derives a stable owner address from it, which is what the AS binds to.
 */
const KNOWN_SIG =
  "0xedbb7743cce459345238442dcfb291f234a321d253485eaa58251aa0f28ea8f1410ab988bae2657b689cd24417b41e315efc22ba333024f4a6269c424ded8d361b";

const SOURCE_ID = "https://registry.pdpp.dev/connectors/spotify";
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE = computeS256Challenge(VERIFIER);
const REDIRECT = "https://app.example.com/callback";

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
 * Seed the real index with a scope so the connector inventory is non-empty.
 * The declaration trust policy is derived from what this PS actually serves,
 * so without data for `spotify` the declaration is (correctly) refused.
 */
async function seedScope(scope: string): Promise<void> {
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

function pdppConfig(
  declarationPaths: string[],
  clients: Array<{
    clientId: string;
    redirectUris: string[];
    grantLifetimeSeconds?: number;
  }> = [{ clientId: "music_recommendations", redirectUris: [REDIRECT] }],
) {
  return ServerConfigSchema.parse({
    tunnel: { enabled: false },
    pdpp: {
      enabled: true,
      declarationPaths,
      methods: declarationPaths.map((declaration_path) => ({
        method_id: "spotify",
        declaration_path,
      })),
      // redirect_uri is validated by exact match against this registration.
      clients,
    },
  });
}

async function boot(config: ReturnType<typeof pdppConfig>) {
  return createServer(config, {
    serverDir: tempDir,
    dataDir: join(tempDir, "data"),
  });
}

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), "pdpp-boot-"));
  vi.stubEnv("VANA_MASTER_KEY_SIGNATURE", KNOWN_SIG);
});

afterEach(async () => {
  await ctx?.cleanup();
  ctx = undefined;
  await rm(tempDir, { recursive: true, force: true });
  vi.unstubAllEnvs();
});

describe("mounting is conditional on the deployment being able to serve PDPP", () => {
  it("does not mount when pdpp.enabled is false", async () => {
    ctx = await boot(ServerConfigSchema.parse({ tunnel: { enabled: false } }));
    const response = await ctx.app.request("/pdpp/v1/owner/token", {
      method: "POST",
    });
    expect(response.status).toBe(404);
  });

  it("does not mount when no declarations are retained", async () => {
    // Enabled, but nothing configured: an AS with no declarations can issue
    // nothing, so the surface stays absent rather than existing uselessly.
    await seedScope("spotify.top_artists");
    ctx = await boot(pdppConfig([]));
    const response = await ctx.app.request("/pdpp/v1/owner/token", {
      method: "POST",
    });
    expect(response.status).toBe(404);
  });

  it("mounts a configured declaration for a connector with no data here yet", async () => {
    // Configuration is the admission decision. A fresh install holds no
    // legacy data for the source it was just configured for, and must still
    // mount it; only runtime submissions are held to the data inventory.
    await seedScope("instagram.profile");
    ctx = await boot(pdppConfig([await writeDeclaration()]));
    const response = await ctx.app.request("/pdpp/v1/owner/token", {
      method: "POST",
    });
    expect(response.status).not.toBe(404);
  });

  it("does not mount a malformed declaration", async () => {
    await seedScope("spotify.top_artists");
    const path = await writeDeclaration(
      JSON.stringify({ source_id: SOURCE_ID, source_kind: "connector" }),
    );
    ctx = await boot(pdppConfig([path]));
    const response = await ctx.app.request("/pdpp/v1/owner/token", {
      method: "POST",
    });
    expect(response.status).toBe(404);
  });

  it("mounts when the server owns data for the declared connector", async () => {
    await seedScope("spotify.top_artists");
    ctx = await boot(pdppConfig([await writeDeclaration()]));
    // Present, and guarded: no owner proof means no token, not a 404.
    const response = await ctx.app.request("/pdpp/v1/owner/token", {
      method: "POST",
    });
    expect(response.status).not.toBe(404);
  });

  it("leaves the existing OAuth surface untouched", async () => {
    await seedScope("spotify.top_artists");
    ctx = await boot(pdppConfig([await writeDeclaration()]));

    // The legacy token endpoint still answers its own contract, unchanged.
    const legacy = await ctx.app.request("/oauth/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "client_credentials",
      }).toString(),
    });
    expect(legacy.status).not.toBe(404);
    // And health is unaffected.
    expect((await ctx.app.request("/health")).status).toBe(200);
  });
});

describe("the real OAuth grant flow on a bootstrapped server", () => {
  /**
   * Mint an owner token through the mounted route.
   *
   * The dev token is the deployment's own owner-proof shortcut: `web3-auth`
   * accepts it and populates the server owner, exactly as it does for the
   * other owner routes. That is a real path through the middleware, not a
   * bypass of it — the assertion that an unauthenticated call is refused is
   * in the test below.
   */
  async function ownerToken(context: ServerContext): Promise<string> {
    const response = await context.app.request("/pdpp/v1/owner/token", {
      method: "POST",
      headers: { authorization: `Bearer ${context.devToken}` },
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as { access_token: string };
    return body.access_token;
  }

  beforeEach(async () => {
    await seedScope("spotify.top_artists");
    ctx = await boot(pdppConfig([await writeDeclaration()]));
  });

  it("refuses to mint an owner token without the owner proof", async () => {
    const response = await ctx!.app.request("/pdpp/v1/owner/token", {
      method: "POST",
    });
    expect(response.status).toBe(401);
  });

  it("runs authorize → review → approve → token → introspect → revoke", async () => {
    const app = ctx!.app;
    const token = await ownerToken(ctx!);

    // 1. The client asks, with PKCE.
    const authorized = await app.request("/pdpp/v1/authorize", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        client_id: "music_recommendations",
        redirect_uri: REDIRECT,
        state: "xyz",
        code_challenge: CHALLENGE,
        code_challenge_method: "S256",
        client_display: { name: "Concert Finder" },
        authorization_details: [
          {
            type: "https://pdpp.dev/data-access",
            source: { id: SOURCE_ID },
            purpose_code: "https://pdpp.dev/purpose/personalization",
            access_mode: "continuous",
            streams: [{ name: "top_artists" }],
          },
        ],
      }),
    });
    expect(authorized.status).toBe(201);
    const { session_id } = (await authorized.json()) as { session_id: string };

    // 2. The owner reviews, against the retained declaration.
    const reviewed = await app.request(
      `/pdpp/v1/authorize/${session_id}/review`,
      { headers: { authorization: `Bearer ${token}` } },
    );
    expect(reviewed.status).toBe(200);
    const { review } = (await reviewed.json()) as {
      review: {
        review_digest: string;
        data: { streams: Array<{ name: string; fields: string[] }> };
      };
    };
    // Resolved from the declaration, with the schema-required floor included.
    expect(review.data.streams[0].name).toBe("top_artists");
    expect(review.data.streams[0].fields).toContain("id");

    // 3. The owner approves.
    const approved = await app.request(
      `/pdpp/v1/authorize/${session_id}/approve`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ review_digest: review.review_digest }),
      },
    );
    expect(approved.status).toBe(200);
    const { redirect_uri, grant_id } = (await approved.json()) as {
      redirect_uri: string;
      grant_id: string;
    };
    const code = new URL(redirect_uri).searchParams.get("code")!;
    expect(code).toBeTruthy();

    // 4. The client redeems, presenting the verifier.
    const tokenResponse = await app.request("/pdpp/v1/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        client_id: "music_recommendations",
        redirect_uri: REDIRECT,
        code_verifier: VERIFIER,
      }).toString(),
    });
    expect(tokenResponse.status).toBe(200);
    expect(tokenResponse.headers.get("cache-control")).toBe("no-store");
    const issued = (await tokenResponse.json()) as {
      access_token: string;
      refresh_token?: string;
    };
    expect(issued.refresh_token).toBeTruthy();

    // 5. The RS-facing view carries the full enforcement context.
    const introspected = await app.request("/pdpp/v1/introspect", {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization: `Bearer ${token}`,
      },
      body: new URLSearchParams({ token: issued.access_token }).toString(),
    });
    const context = (await introspected.json()) as {
      active: boolean;
      grant_id: string;
      authorization_details: Array<{ streams: Array<{ fields: string[] }> }>;
    };
    expect(context.active).toBe(true);
    expect(context.grant_id).toBe(grant_id);
    expect(context.authorization_details[0].streams[0].fields).toContain("id");

    // 6. Revocation is immediate.
    const revoked = await app.request("/pdpp/v1/revoke", {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization: `Bearer ${token}`,
      },
      body: new URLSearchParams({ grant_id }).toString(),
    });
    expect(revoked.status).toBe(200);

    const afterRevoke = await app.request("/pdpp/v1/introspect", {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization: `Bearer ${token}`,
      },
      body: new URLSearchParams({ token: issued.access_token }).toString(),
    });
    expect(await afterRevoke.json()).toEqual({ active: false });
  });

  it("enforces PKCE on the bootstrapped server", async () => {
    const app = ctx!.app;
    const token = await ownerToken(ctx!);

    // No challenge: refused before the owner is ever asked.
    const noPkce = await app.request("/pdpp/v1/authorize", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        client_id: "music_recommendations",
        redirect_uri: REDIRECT,
        authorization_details: [
          {
            type: "https://pdpp.dev/data-access",
            source: { id: SOURCE_ID },
            purpose_code: "https://pdpp.dev/purpose/personalization",
            access_mode: "continuous",
            streams: [{ name: "top_artists" }],
          },
        ],
      }),
    });
    expect(noPkce.status).toBe(400);

    // With a challenge, a code is issued — and is useless without the verifier.
    const authorized = await app.request("/pdpp/v1/authorize", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        client_id: "music_recommendations",
        redirect_uri: REDIRECT,
        code_challenge: CHALLENGE,
        code_challenge_method: "S256",
        authorization_details: [
          {
            type: "https://pdpp.dev/data-access",
            source: { id: SOURCE_ID },
            purpose_code: "https://pdpp.dev/purpose/personalization",
            access_mode: "continuous",
            streams: [{ name: "top_artists" }],
          },
        ],
      }),
    });
    const { session_id } = (await authorized.json()) as { session_id: string };
    const reviewed = await app.request(
      `/pdpp/v1/authorize/${session_id}/review`,
      { headers: { authorization: `Bearer ${token}` } },
    );
    const { review } = (await reviewed.json()) as {
      review: { review_digest: string };
    };
    const approved = await app.request(
      `/pdpp/v1/authorize/${session_id}/approve`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ review_digest: review.review_digest }),
      },
    );
    const { redirect_uri } = (await approved.json()) as {
      redirect_uri: string;
    };
    const code = new URL(redirect_uri).searchParams.get("code")!;

    const stolen = await app.request("/pdpp/v1/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        client_id: "music_recommendations",
        redirect_uri: REDIRECT,
      }).toString(),
    });
    expect(stolen.status).toBe(400);
    expect((await stolen.json()).error).toBe("invalid_grant");
  });

  it("rejects a forged approval that carries no owner token", async () => {
    const app = ctx!.app;
    const token = await ownerToken(ctx!);

    const authorized = await app.request("/pdpp/v1/authorize", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        client_id: "music_recommendations",
        redirect_uri: REDIRECT,
        code_challenge: CHALLENGE,
        code_challenge_method: "S256",
        authorization_details: [
          {
            type: "https://pdpp.dev/data-access",
            source: { id: SOURCE_ID },
            purpose_code: "https://pdpp.dev/purpose/personalization",
            access_mode: "continuous",
            streams: [{ name: "top_artists" }],
          },
        ],
      }),
    });
    const { session_id } = (await authorized.json()) as { session_id: string };
    const reviewed = await app.request(
      `/pdpp/v1/authorize/${session_id}/review`,
      { headers: { authorization: `Bearer ${token}` } },
    );
    const { review } = (await reviewed.json()) as {
      review: { review_digest: string };
    };

    // The correct digest, from a real review, with no owner authentication.
    const forged = await app.request(
      `/pdpp/v1/authorize/${session_id}/approve`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ review_digest: review.review_digest }),
      },
    );
    expect(forged.status).toBe(401);
  });

  it("persists grants across a restart of the same storage root", async () => {
    const token = await ownerToken(ctx!);
    const app = ctx!.app;

    const authorized = await app.request("/pdpp/v1/authorize", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        client_id: "music_recommendations",
        redirect_uri: REDIRECT,
        code_challenge: CHALLENGE,
        code_challenge_method: "S256",
        authorization_details: [
          {
            type: "https://pdpp.dev/data-access",
            source: { id: SOURCE_ID },
            purpose_code: "https://pdpp.dev/purpose/personalization",
            access_mode: "continuous",
            streams: [{ name: "top_artists" }],
          },
        ],
      }),
    });
    const { session_id } = (await authorized.json()) as { session_id: string };
    const reviewed = await app.request(
      `/pdpp/v1/authorize/${session_id}/review`,
      { headers: { authorization: `Bearer ${token}` } },
    );
    const { review } = (await reviewed.json()) as {
      review: { review_digest: string };
    };
    const approved = await app.request(
      `/pdpp/v1/authorize/${session_id}/approve`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ review_digest: review.review_digest }),
      },
    );
    const { redirect_uri, grant_id } = (await approved.json()) as {
      redirect_uri: string;
      grant_id: string;
    };
    const code = new URL(redirect_uri).searchParams.get("code")!;
    const issued = (await (
      await app.request("/pdpp/v1/token", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          client_id: "music_recommendations",
          redirect_uri: REDIRECT,
          code_verifier: VERIFIER,
        }).toString(),
      })
    ).json()) as { access_token: string };

    // Restart against the same storage root.
    await ctx!.cleanup();
    ctx = await boot(
      pdppConfig([join(tempDir, "declarations", "spotify.json")]),
    );
    const secondToken = await ownerToken(ctx);

    // The grant and its token survived: this is real persistence, not memory.
    const introspected = await ctx.app.request("/pdpp/v1/introspect", {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization: `Bearer ${secondToken}`,
      },
      body: new URLSearchParams({ token: issued.access_token }).toString(),
    });
    const context = (await introspected.json()) as {
      active: boolean;
      grant_id: string;
    };
    expect(context.active).toBe(true);
    expect(context.grant_id).toBe(grant_id);
  });
});

describe("redirect_uri is validated on the bootstrapped server", () => {
  beforeEach(async () => {
    await seedScope("spotify.top_artists");
    ctx = await boot(pdppConfig([await writeDeclaration()]));
  });

  /**
   * The end-to-end form of the exfiltration attack: an attacker opens an
   * authorization session pointing at their own host. If the AS accepts it,
   * the owner approves a legitimate-looking screen and the code is delivered
   * to the attacker, who holds the PKCE verifier because they chose the
   * challenge.
   */
  async function authorizeWith(
    redirectUri: string,
    clientId = "music_recommendations",
  ) {
    const minted = (await (
      await ctx!.app.request("/pdpp/v1/owner/token", {
        method: "POST",
        headers: { authorization: `Bearer ${ctx!.devToken}` },
      })
    ).json()) as { access_token: string };
    return ctx!.app.request("/pdpp/v1/authorize", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${minted.access_token}`,
      },
      body: JSON.stringify({
        client_id: clientId,
        redirect_uri: redirectUri,
        code_challenge: CHALLENGE,
        code_challenge_method: "S256",
        authorization_details: [
          {
            type: "https://pdpp.dev/data-access",
            source: { id: SOURCE_ID },
            purpose_code: "https://pdpp.dev/purpose/personalization",
            access_mode: "continuous",
            streams: [{ name: "top_artists" }],
          },
        ],
      }),
    });
  }

  it("EXPLOIT: refuses to open a session targeting an attacker host", async () => {
    const response = await authorizeWith("https://evil.example.com/steal");
    expect(response.status).toBe(400);
    // No session exists, so no consent screen can ever be rendered for it.
    expect((await response.json()).session_id).toBeUndefined();
  });

  it("refuses an unregistered client even with a plausible redirect", async () => {
    const response = await authorizeWith(REDIRECT, "never_registered");
    expect(response.status).toBe(400);
  });

  it("refuses a javascript: target", async () => {
    expect((await authorizeWith("javascript:alert(1)")).status).toBe(400);
  });

  it("accepts the registered redirect", async () => {
    expect((await authorizeWith(REDIRECT)).status).toBe(201);
  });
});

describe("review C5 — /authorize binds an authenticated owner", () => {
  beforeEach(async () => {
    await seedScope("spotify.top_artists");
    ctx = await boot(pdppConfig([await writeDeclaration()]));
  });

  function authorizeBody() {
    return {
      client_id: "music_recommendations",
      redirect_uri: REDIRECT,
      code_challenge: CHALLENGE,
      code_challenge_method: "S256",
      authorization_details: [
        {
          type: "https://pdpp.dev/data-access",
          source: { id: SOURCE_ID },
          purpose_code: "https://pdpp.dev/purpose/personalization",
          access_mode: "continuous",
          streams: [{ name: "top_artists" }],
        },
      ],
    };
  }

  it("refuses to open a session for an unauthenticated caller", async () => {
    // Single-owner is a deployment property, not a licence for anyone to
    // create sessions bound to the owner's subject. Previously this returned
    // 201 and allocated a session against the owner.
    const response = await ctx!.app.request("/pdpp/v1/authorize", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(authorizeBody()),
    });
    expect(response.status).toBe(401);
  });

  it("refuses a client token in place of an owner token", async () => {
    const response = await ctx!.app.request("/pdpp/v1/authorize", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer pdpp_at_not_an_owner_token",
      },
      body: JSON.stringify(authorizeBody()),
    });
    expect(response.status).toBe(401);
  });

  it("opens a session for the authenticated owner and binds their subject", async () => {
    const minted = (await (
      await ctx!.app.request("/pdpp/v1/owner/token", {
        method: "POST",
        headers: { authorization: `Bearer ${ctx!.devToken}` },
      })
    ).json()) as { access_token: string };

    const response = await ctx!.app.request("/pdpp/v1/authorize", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${minted.access_token}`,
      },
      body: JSON.stringify(authorizeBody()),
    });
    expect(response.status).toBe(201);

    // The session is the owner's: their token reviews it.
    const { session_id } = (await response.json()) as { session_id: string };
    const reviewed = await ctx!.app.request(
      `/pdpp/v1/authorize/${session_id}/review`,
      { headers: { authorization: `Bearer ${minted.access_token}` } },
    );
    expect(reviewed.status).toBe(200);
  });
});

describe("review C1 — PDPP-Version is the spec's HTTP contract version", () => {
  beforeEach(async () => {
    await seedScope("spotify.top_artists");
    ctx = await boot(pdppConfig([await writeDeclaration()]));
  });

  it("accepts the normative header value from Core §8", async () => {
    // Core §8 "API versioning" states `PDPP-Version: 2026-04-06`. The AS
    // previously advertised the GRANT SCHEMA version here, which §7 says must
    // not be conflated with the HTTP contract version — so a client pinning
    // the spec's own value could reach the RS but not the AS.
    const response = await ctx!.app.request("/pdpp/v1/owner/token", {
      method: "POST",
      headers: {
        authorization: `Bearer ${ctx!.devToken}`,
        "pdpp-version": "2026-04-06",
      },
    });
    expect(response.status).toBe(200);
    expect(response.headers.get("pdpp-version")).toBe("2026-04-06");
  });

  it("rejects the grant schema version as an API version", async () => {
    const response = await ctx!.app.request("/pdpp/v1/owner/token", {
      method: "POST",
      headers: {
        authorization: `Bearer ${ctx!.devToken}`,
        "pdpp-version": "0.1.0",
      },
    });
    expect(response.status).toBe(400);
    expect((await response.json()).error).toBe("unsupported_version");
  });
});

/**
 * The real boot path, fed the real normative producer document.
 *
 * The AS previously did not mount for a §5-conformant declaration at all. The
 * deployment loader read the flat `source_id` directly, so a normative
 * document — which nests it under `source.id` — was skipped BEFORE
 * `parseDeclaration` (which understands both shapes) ever saw it. The whole
 * failure surfaced as one warning about a missing field the document was
 * never supposed to have, and then `/pdpp/v1` simply was not there.
 *
 * So the check that matters is not "does the parser accept this" — it always
 * did — but "does a server booted the way the CLI boots it actually serve the
 * AS for this document". That is what these drive, using the byte-for-byte
 * Unity producer artifact rather than a hand-written substitute, because a
 * fixture I wrote to match my own loader would prove nothing about the
 * documents real producers publish.
 */
describe("the real boot path mounts the AS for a normative declaration", () => {
  /** The vendored producer artifact: normative §5, no flat `source_id`. */
  async function writeNormativeDeclaration(): Promise<string> {
    const source = await readFile(
      join(
        import.meta.dirname,
        "../../../core/src/pdpp/__fixtures__/instagram.source-declaration.json",
      ),
      "utf-8",
    );
    // Guard the premise: if this ever grows a flat source_id, these tests
    // would silently stop covering the normative shape.
    expect(JSON.parse(source).source_id).toBeUndefined();
    expect(JSON.parse(source).source.id).toBe(
      "https://registry.pdpp.dev/connectors/instagram",
    );

    const dir = join(tempDir, "declarations");
    await mkdir(dir, { recursive: true });
    const path = join(dir, "instagram.source-declaration.json");
    await writeFile(path, source, "utf-8");
    return path;
  }

  it("mounts /pdpp/v1 for a normative-only document", async () => {
    await seedScope("instagram.profile");
    ctx = await boot(pdppConfig([await writeNormativeDeclaration()]));

    const response = await ctx.app.request("/pdpp/v1/owner/token", {
      method: "POST",
      headers: { authorization: `Bearer ${ctx.devToken}` },
    });

    // Previously 404: nothing was retained, so the AS never mounted.
    expect(response.status).toBe(200);
  });

  it("resolves the normative declaration in a real authorize request", async () => {
    await seedScope("instagram.profile");
    ctx = await boot(pdppConfig([await writeNormativeDeclaration()]));

    const minted = await ctx.app.request("/pdpp/v1/owner/token", {
      method: "POST",
      headers: { authorization: `Bearer ${ctx.devToken}` },
    });
    expect(minted.status).toBe(200);
    const { access_token } = (await minted.json()) as { access_token: string };

    const authorized = await ctx.app.request("/pdpp/v1/authorize", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${access_token}`,
      },
      body: JSON.stringify({
        client_id: "music_recommendations",
        redirect_uri: REDIRECT,
        state: "xyz",
        code_challenge: CHALLENGE,
        code_challenge_method: "S256",
        authorization_details: [
          {
            type: "https://pdpp.dev/data-access",
            source: { id: "https://registry.pdpp.dev/connectors/instagram" },
            purpose_code: "https://pdpp.dev/purpose/personalization",
            access_mode: "continuous",
            streams: [{ name: "profile" }],
          },
        ],
      }),
    });

    // The end of the chain: mounted, retained under the id the document
    // nests, and resolvable by an authorize request naming that same id.
    expect(authorized.status).toBe(201);

    // And the fields projected out of the document's JSON Schema are real:
    // the review the owner would see lists them.
    const { session_id } = (await authorized.json()) as { session_id: string };
    const reviewed = await ctx.app.request(
      `/pdpp/v1/authorize/${session_id}/review`,
      { headers: { authorization: `Bearer ${access_token}` } },
    );
    expect(reviewed.status).toBe(200);
    const review = (await reviewed.json()) as {
      review: { data: { streams: { name: string; fields: string[] }[] } };
    };
    const profile = review.review.data.streams.find(
      (stream) => stream.name === "profile",
    );
    expect(profile?.fields.length).toBeGreaterThan(0);
  });
});

/**
 * Operator per-client grant lifetime policy (`pdpp.clients[].grantLifetimeSeconds`).
 *
 * This is deployment policy, not a protocol extension: the client never
 * requests or sees an expiry parameter, and a client with no configured
 * lifetime is unaffected — asserted below against the SAME declaration and
 * SAME boot path, with an ordinary client registered alongside the
 * short-lived one.
 *
 * The real clock is used (no wall-clock monkeypatch): the fixture client's
 * lifetime is a few seconds and the test waits past it with a real
 * `setTimeout`, matching the pattern already used elsewhere in this suite
 * (see the restart test above and `bootstrap.test.ts`'s other `setTimeout`
 * waits). Both clients share a SINGLE real sleep so the suite pays for one
 * wait, not two.
 */
describe("operator per-client grant lifetime policy", () => {
  const SHORT_LIVED_CLIENT = "expiring_widget";
  const ORDINARY_CLIENT = "music_recommendations";
  const GRANT_LIFETIME_SECONDS = 3;

  beforeEach(async () => {
    await seedScope("spotify.top_artists");
    ctx = await boot(
      pdppConfig(
        [await writeDeclaration()],
        [
          { clientId: ORDINARY_CLIENT, redirectUris: [REDIRECT] },
          {
            clientId: SHORT_LIVED_CLIENT,
            redirectUris: [REDIRECT],
            grantLifetimeSeconds: GRANT_LIFETIME_SECONDS,
          },
        ],
      ),
    );
  });

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
   * The subject the AS binds the owner to, derived the same way the server
   * itself derives it from `KNOWN_SIG`. Used to compute the exact `instance`
   * handle a seeded record must carry to be within the grant's resources.
   */
  async function ownerSubjectId(): Promise<string> {
    const owner = await recoverServerOwner(KNOWN_SIG);
    return owner.toLowerCase();
  }

  /**
   * Seed a real, known `top_artists` record through the actual owner-token
   * ingest route — not a store or DB bypass — so the read assertions below
   * exercise the same RS enforcement path a real RS consumer would.
   */
  async function seedKnownRecord(
    ownerAccessToken: string,
    recordId: string,
  ): Promise<void> {
    const instance = `spotify:${await ownerSubjectId()}`;
    const response = await ctx!.app.request(
      "/v1/streams/top_artists/records/ingest?method=spotify&binding_generation=1",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${ownerAccessToken}`,
        },
        body: JSON.stringify({
          instance,
          key: recordId,
          data: { id: recordId, name: "The Midnight" },
          emitted_at: "2026-01-01T00:00:00.000Z",
        }),
      },
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as { accepted: number };
    expect(body.accepted).toBe(1);
  }

  /** Drive the real authorize -> review -> approve -> redeem journey for one client. */
  async function issueGrantFor(clientId: string): Promise<{
    accessToken: string;
    ownerAccessToken: string;
    grantExpiresAt?: string;
  }> {
    const app = ctx!.app;
    const token = await ownerToken(ctx!);

    const authorized = await app.request("/pdpp/v1/authorize", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        client_id: clientId,
        redirect_uri: REDIRECT,
        code_challenge: CHALLENGE,
        code_challenge_method: "S256",
        authorization_details: [
          {
            type: "https://pdpp.dev/data-access",
            source: { id: SOURCE_ID },
            purpose_code: "https://pdpp.dev/purpose/personalization",
            access_mode: "continuous",
            streams: [{ name: "top_artists" }],
          },
        ],
      }),
    });
    expect(authorized.status).toBe(201);
    const { session_id } = (await authorized.json()) as { session_id: string };

    const reviewed = await app.request(
      `/pdpp/v1/authorize/${session_id}/review`,
      { headers: { authorization: `Bearer ${token}` } },
    );
    expect(reviewed.status).toBe(200);
    const { review } = (await reviewed.json()) as {
      review: {
        review_digest: string;
        data: { expires_at?: string };
      };
    };

    const approved = await app.request(
      `/pdpp/v1/authorize/${session_id}/approve`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ review_digest: review.review_digest }),
      },
    );
    expect(approved.status).toBe(200);
    const { redirect_uri } = (await approved.json()) as {
      redirect_uri: string;
    };
    const code = new URL(redirect_uri).searchParams.get("code")!;

    const tokenResponse = await app.request("/pdpp/v1/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        client_id: clientId,
        redirect_uri: REDIRECT,
        code_verifier: VERIFIER,
      }).toString(),
    });
    expect(tokenResponse.status).toBe(200);
    const issued = (await tokenResponse.json()) as { access_token: string };
    return {
      accessToken: issued.access_token,
      ownerAccessToken: token,
      grantExpiresAt: review.data.expires_at,
    };
  }

  /** Read the RS-facing enforcement view through the real /introspect route. */
  async function introspect(
    ownerAccessToken: string,
    accessToken: string,
  ): Promise<{ active: boolean }> {
    const response = await ctx!.app.request("/pdpp/v1/introspect", {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization: `Bearer ${ownerAccessToken}`,
      },
      body: new URLSearchParams({ token: accessToken }).toString(),
    });
    return (await response.json()) as { active: boolean };
  }

  /** Read the known record through the real RS route, as the client would. */
  async function readRecord(
    clientAccessToken: string,
    recordId: string,
  ): Promise<Response> {
    return ctx!.app.request(
      `/v1/streams/top_artists/records/${encodeURIComponent(recordId)}`,
      { headers: { authorization: `Bearer ${clientAccessToken}` } },
    );
  }

  it(
    "reads the known record before expiry, then refuses the SAME token after — leaving an ordinary client's grant unaffected",
    async () => {
      const RECORD_ID = "artist_1";

      const shortLived = await issueGrantFor(SHORT_LIVED_CLIENT);
      await seedKnownRecord(shortLived.ownerAccessToken, RECORD_ID);

      // The policy the review computed is frozen into the session, and the
      // owner sees it before approving — not just enforced silently later.
      expect(shortLived.grantExpiresAt).toBeTruthy();
      expect(Date.parse(shortLived.grantExpiresAt!)).toBeGreaterThan(
        Date.now(),
      );

      const ordinary = await issueGrantFor(ORDINARY_CLIENT);
      // No grantLifetimeSeconds configured for this client, so no AS-imposed
      // expiry is computed at all.
      expect(ordinary.grantExpiresAt).toBeUndefined();

      // Positive, before the wait: the SAME token the short-lived client
      // holds can read the SAME seeded record, and introspection agrees.
      const beforeRead = await readRecord(shortLived.accessToken, RECORD_ID);
      expect(beforeRead.status).toBe(200);
      const beforeBody = (await beforeRead.json()) as {
        data: { id: string; name: string };
      };
      expect(beforeBody.data.id).toBe(RECORD_ID);
      expect(beforeBody.data.name).toBe("The Midnight");
      expect(
        (await introspect(shortLived.ownerAccessToken, shortLived.accessToken))
          .active,
      ).toBe(true);

      // Wait past the configured lifetime once, using the real clock — both
      // clients' post-wait assertions below share this single sleep.
      await new Promise((resolve) =>
        setTimeout(resolve, (GRANT_LIFETIME_SECONDS + 2) * 1000),
      );

      // The SAME token, unchanged, is now refused reading the SAME record —
      // grant expiry, not a fabricated or alternate token or record.
      const afterRead = await readRecord(shortLived.accessToken, RECORD_ID);
      expect(afterRead.status).toBe(403);
      expect((await afterRead.json()).error.code).toBe("grant_expired");
      expect(
        (await introspect(shortLived.ownerAccessToken, shortLived.accessToken))
          .active,
      ).toBe(false);

      // The ordinary client's grant, issued alongside it, stays active past
      // the same window: the policy is per-client, not global.
      expect(
        (await introspect(ordinary.ownerAccessToken, ordinary.accessToken))
          .active,
      ).toBe(true);
    },
    (GRANT_LIFETIME_SECONDS + 5) * 1000,
  );
});
