/**
 * Scoped owner tokens on a REAL bootstrapped Personal Server.
 *
 * This covers the PR #351 blocker where an instance-scoped owner token could
 * use the AS consent path to approve a grant for another instance. The RS
 * already refused the scoped owner token directly; the missing constraint was
 * authorize/review/approve producing a new client credential.
 */

import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { recoverServerOwner } from "@opendatalabs/vana-sdk/node";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import {
  computeS256Challenge,
  openPdppAuthStore,
  PdppTokenService,
} from "@opendatalabs/personal-server-ts-core/pdpp";
import { createServer, type ServerContext } from "./bootstrap.js";
import { singleInstanceInventory } from "./pdpp/deployment.js";

const KNOWN_SIG =
  "0xedbb7743cce459345238442dcfb291f234a321d253485eaa58251aa0f28ea8f1410ab988bae2657b689cd24417b41e315efc22ba333024f4a6269c424ded8d361b";

const CLAUDE = "https://registry.pdpp.dev/connectors/claude";
const OURA = "https://registry.pdpp.dev/connectors/oura";
const REDIRECT = "https://app.example.com/callback";
const CLIENT_ID = "sleep_recommendations";
const VERIFIER = "scoped-owner-verifier-0123456789abcdefghijklmnopqrstuvwxyz";
const CHALLENGE = computeS256Challenge(VERIFIER);

const CLAUDE_DECLARATION = JSON.stringify({
  source_id: CLAUDE,
  source_kind: "connector",
  version: "1",
  streams: [
    {
      name: "profile",
      fields: ["id", "name"],
      required_fields: ["id"],
      primary_key: ["id"],
    },
  ],
});

const OURA_DECLARATION = JSON.stringify({
  source_id: OURA,
  source_kind: "connector",
  version: "1",
  streams: [
    {
      name: "sleep",
      fields: ["id", "score"],
      required_fields: ["id"],
      primary_key: ["id"],
    },
  ],
});

let tempDir: string;
let ctx: ServerContext | undefined;
let owner: string;

async function writeDeclaration(name: string, document: string) {
  const dir = join(tempDir, "declarations");
  await mkdir(dir, { recursive: true });
  const path = join(dir, `${name}.json`);
  await writeFile(path, document, "utf-8");
  return path;
}

async function bootBoth() {
  const claude = await writeDeclaration("claude", CLAUDE_DECLARATION);
  const oura = await writeDeclaration("oura", OURA_DECLARATION);
  return createServer(
    ServerConfigSchema.parse({
      tunnel: { enabled: false },
      pdpp: {
        enabled: true,
        declarationPaths: [claude, oura],
        methods: [
          { method_id: "claude", declaration_path: claude },
          { method_id: "oura", declaration_path: oura },
        ],
        clients: [{ clientId: CLIENT_ID, redirectUris: [REDIRECT] }],
      },
    }),
    { serverDir: tempDir, dataDir: join(tempDir, "data") },
  );
}

function instance(sourceId: string) {
  return singleInstanceInventory(owner, sourceId).eligibleFor("")[0];
}

async function ownerToken(sourceId: string): Promise<string> {
  const response = await ctx!.app.request("/pdpp/v1/owner/token", {
    method: "POST",
    headers: {
      authorization: `Bearer ${ctx!.devToken}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      source_id: sourceId,
      instance_id: instance(sourceId),
    }),
  });
  expect(response.status).toBe(200);
  return ((await response.json()) as { access_token: string }).access_token;
}

function unscopedOwnerToken(): string {
  const store = openPdppAuthStore(join(tempDir, "pdpp-auth.db"));
  try {
    return new PdppTokenService(store).issueOwnerToken({
      subjectId: owner,
    }).access_token;
  } finally {
    store.close();
  }
}

function multiInstanceOwnerToken(): string {
  const store = openPdppAuthStore(join(tempDir, "pdpp-auth.db"));
  try {
    return new PdppTokenService(store).issueOwnerToken({
      subjectId: owner,
      instanceIds: [instance(CLAUDE), instance(OURA)],
    }).access_token;
  } finally {
    store.close();
  }
}

async function ingestOuraSleep(token: string) {
  const response = await ctx!.app.request(
    "/v1/streams/sleep/records/ingest?method=oura&binding_generation=1",
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        instance: instance(OURA),
        key: "sleep-1",
        data: { id: "sleep-1", score: 91 },
        emitted_at: "2026-09-01T00:00:00Z",
      }),
    },
  );
  expect(response.status).toBe(200);
}

async function authorizeOura(token: string): Promise<string> {
  const response = await ctx!.app.request("/pdpp/v1/authorize", {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT,
      code_challenge: CHALLENGE,
      code_challenge_method: "S256",
      authorization_details: [
        {
          type: "https://pdpp.dev/data-access",
          source: { id: OURA },
          purpose_code: "https://pdpp.dev/purpose/personalization",
          access_mode: "continuous",
          streams: [{ name: "sleep" }],
        },
      ],
    }),
  });
  expect(response.status).toBe(201);
  return ((await response.json()) as { session_id: string }).session_id;
}

async function authorizeClaude(token: string): Promise<string> {
  const response = await ctx!.app.request("/pdpp/v1/authorize", {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT,
      code_challenge: CHALLENGE,
      code_challenge_method: "S256",
      authorization_details: [
        {
          type: "https://pdpp.dev/data-access",
          source: { id: CLAUDE },
          purpose_code: "https://pdpp.dev/purpose/personalization",
          access_mode: "continuous",
          streams: [{ name: "profile" }],
        },
      ],
    }),
  });
  expect(response.status).toBe(201);
  return ((await response.json()) as { session_id: string }).session_id;
}

async function issueOuraGrant(token: string): Promise<{
  accessToken: string;
  grantId: string;
}> {
  const sessionId = await authorizeOura(token);
  const reviewed = await ctx!.app.request(
    `/pdpp/v1/authorize/${sessionId}/review`,
    { headers: { authorization: `Bearer ${token}` } },
  );
  expect(reviewed.status).toBe(200);
  const { review } = (await reviewed.json()) as {
    review: { review_digest: string };
  };

  const approved = await ctx!.app.request(
    `/pdpp/v1/authorize/${sessionId}/approve`,
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ review_digest: review.review_digest }),
    },
  );
  expect(approved.status).toBe(200);
  const { grant_id, redirect_uri } = (await approved.json()) as {
    grant_id: string;
    redirect_uri: string;
  };
  const code = new URL(redirect_uri).searchParams.get("code");
  expect(code).toBeTruthy();

  const redeemed = await ctx!.app.request("/pdpp/v1/token", {
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
  expect(redeemed.status).toBe(200);
  return {
    accessToken: ((await redeemed.json()) as { access_token: string })
      .access_token,
    grantId: grant_id,
  };
}

async function readSleep(token: string) {
  const response = await ctx!.app.request("/v1/streams/sleep/records/sleep-1", {
    headers: { authorization: `Bearer ${token}` },
  });
  return {
    status: response.status,
    body: (await response.json()) as { data?: unknown },
  };
}

async function json(response: Response) {
  return (await response.json()) as Record<string, unknown>;
}

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), "pdpp-scoped-owner-as-"));
  vi.stubEnv("VANA_MASTER_KEY_SIGNATURE", KNOWN_SIG);
  owner = (await recoverServerOwner(KNOWN_SIG)).toLowerCase();
  ctx = await bootBoth();
});

afterEach(async () => {
  await ctx?.cleanup();
  ctx = undefined;
  await rm(tempDir, { recursive: true, force: true });
  vi.unstubAllEnvs();
});

describe("scoped owner tokens in the AS consent path", () => {
  it("does not let a Claude-scoped owner token approve or redeem an Oura grant and read Oura data", async () => {
    const claudeToken = await ownerToken(CLAUDE);
    const ouraToken = await ownerToken(OURA);
    await ingestOuraSleep(ouraToken);

    const directRead = await readSleep(claudeToken);
    expect(directRead.status).toBe(404);

    const authorized = await ctx!.app.request("/pdpp/v1/authorize", {
      method: "POST",
      headers: {
        authorization: `Bearer ${claudeToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT,
        code_challenge: CHALLENGE,
        code_challenge_method: "S256",
        authorization_details: [
          {
            type: "https://pdpp.dev/data-access",
            source: { id: OURA },
            purpose_code: "https://pdpp.dev/purpose/personalization",
            access_mode: "continuous",
            streams: [{ name: "sleep" }],
          },
        ],
      }),
    });
    expect(authorized.status).toBe(403);
    expect(await json(authorized)).toMatchObject({
      error: "access_denied",
      error_description:
        "owner token is not scoped to an instance for the requested source",
    });

    const ouraSession = await authorizeOura(ouraToken);
    const claudeReview = await ctx!.app.request(
      `/pdpp/v1/authorize/${ouraSession}/review`,
      { headers: { authorization: `Bearer ${claudeToken}` } },
    );
    expect(claudeReview.status).toBe(403);
    expect(await json(claudeReview)).toMatchObject({
      error: "access_denied",
      error_description:
        "owner token is not scoped to an instance for the requested source",
    });

    const ouraReview = await ctx!.app.request(
      `/pdpp/v1/authorize/${ouraSession}/review`,
      { headers: { authorization: `Bearer ${ouraToken}` } },
    );
    expect(ouraReview.status).toBe(200);
    const { review } = (await ouraReview.json()) as {
      review: { review_digest: string };
    };

    const claudeApprove = await ctx!.app.request(
      `/pdpp/v1/authorize/${ouraSession}/approve`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${claudeToken}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ review_digest: review.review_digest }),
      },
    );
    expect(claudeApprove.status).toBe(403);
    const claudeApprovalBody = await json(claudeApprove);
    expect(claudeApprovalBody).toMatchObject({
      error: "access_denied",
      error_description:
        "owner token is not scoped to an instance for the requested source",
    });
    expect(claudeApprovalBody.redirect_uri).toBeUndefined();

    const secondOuraRead = await readSleep(claudeToken);
    expect(secondOuraRead.status).toBe(404);
  });

  it("allows a scoped owner token for the same instance to authorize, review, approve, redeem, and read", async () => {
    const ouraToken = await ownerToken(OURA);
    await ingestOuraSleep(ouraToken);

    const { accessToken, grantId } = await issueOuraGrant(ouraToken);
    const read = await readSleep(accessToken);

    expect(read.status).toBe(200);
    expect(read.body.data).toEqual({ id: "sleep-1", score: 91 });

    const introspected = await ctx!.app.request("/pdpp/v1/introspect", {
      method: "POST",
      headers: {
        authorization: `Bearer ${ouraToken}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ token: accessToken }).toString(),
    });
    expect(introspected.status).toBe(200);
    expect(await json(introspected)).toMatchObject({
      active: true,
      grant_id: grantId,
    });

    const grants = await ctx!.app.request("/pdpp/v1/grants", {
      headers: { authorization: `Bearer ${ouraToken}` },
    });
    expect(grants.status).toBe(200);
    expect(await json(grants)).toMatchObject({
      grants: [expect.objectContaining({ grant_id: grantId })],
    });

    const revoked = await ctx!.app.request("/pdpp/v1/revoke", {
      method: "POST",
      headers: {
        authorization: `Bearer ${ouraToken}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ grant_id: grantId }).toString(),
    });
    expect(revoked.status).toBe(200);
  });

  it("does not show Oura existing grant metadata in a Claude-scoped review for the same client", async () => {
    const ouraToken = await ownerToken(OURA);
    const claudeToken = await ownerToken(CLAUDE);
    await ingestOuraSleep(ouraToken);

    const { grantId: ouraGrantId } = await issueOuraGrant(ouraToken);
    const claudeSession = await authorizeClaude(claudeToken);

    const reviewed = await ctx!.app.request(
      `/pdpp/v1/authorize/${claudeSession}/review`,
      { headers: { authorization: `Bearer ${claudeToken}` } },
    );
    expect(reviewed.status).toBe(200);
    const body = (await reviewed.json()) as {
      review: {
        existing_grants?: Array<{
          grant_id: string;
          purpose_code?: string;
          streams?: Array<{ name: string }>;
        }>;
      };
    };

    const existing = body.review.existing_grants ?? [];
    expect(existing.map((grant) => grant.grant_id)).not.toContain(ouraGrantId);
    expect(JSON.stringify(existing)).not.toContain("sleep");
  });

  it("refuses old unscoped owner tokens for AS grant and consent", async () => {
    const ouraToken = await ownerToken(OURA);
    await ingestOuraSleep(ouraToken);

    const legacyToken = unscopedOwnerToken();
    const multiToken = multiInstanceOwnerToken();
    const authorized = await ctx!.app.request("/pdpp/v1/authorize", {
      method: "POST",
      headers: {
        authorization: `Bearer ${legacyToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT,
        code_challenge: CHALLENGE,
        code_challenge_method: "S256",
        authorization_details: [
          {
            type: "https://pdpp.dev/data-access",
            source: { id: OURA },
            purpose_code: "https://pdpp.dev/purpose/personalization",
            access_mode: "continuous",
            streams: [{ name: "sleep" }],
          },
        ],
      }),
    });
    expect(authorized.status).toBe(403);
    expect(await json(authorized)).toMatchObject({
      error: "access_denied",
      error_description: "owner token is not scoped to an instance",
    });

    const multiAuthorized = await ctx!.app.request("/pdpp/v1/authorize", {
      method: "POST",
      headers: {
        authorization: `Bearer ${multiToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT,
        code_challenge: CHALLENGE,
        code_challenge_method: "S256",
        authorization_details: [
          {
            type: "https://pdpp.dev/data-access",
            source: { id: OURA },
            purpose_code: "https://pdpp.dev/purpose/personalization",
            access_mode: "continuous",
            streams: [{ name: "sleep" }],
          },
        ],
      }),
    });
    expect(multiAuthorized.status).toBe(403);
    expect(await json(multiAuthorized)).toMatchObject({
      error: "access_denied",
      error_description: "owner token is not scoped to an instance",
    });

    const ouraSession = await authorizeOura(ouraToken);
    const reviewed = await ctx!.app.request(
      `/pdpp/v1/authorize/${ouraSession}/review`,
      { headers: { authorization: `Bearer ${legacyToken}` } },
    );
    expect(reviewed.status).toBe(403);
    expect(await json(reviewed)).toMatchObject({
      error: "access_denied",
      error_description: "owner token is not scoped to an instance",
    });

    const ouraReview = await ctx!.app.request(
      `/pdpp/v1/authorize/${ouraSession}/review`,
      { headers: { authorization: `Bearer ${ouraToken}` } },
    );
    expect(ouraReview.status).toBe(200);
    const { review } = (await ouraReview.json()) as {
      review: { review_digest: string };
    };

    const approved = await ctx!.app.request(
      `/pdpp/v1/authorize/${ouraSession}/approve`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${legacyToken}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ review_digest: review.review_digest }),
      },
    );
    expect(approved.status).toBe(403);
    expect(await json(approved)).toMatchObject({
      error: "access_denied",
      error_description: "owner token is not scoped to an instance",
    });

    const grants = await ctx!.app.request("/pdpp/v1/grants", {
      headers: { authorization: `Bearer ${legacyToken}` },
    });
    expect(grants.status).toBe(403);
    expect(await json(grants)).toMatchObject({
      error: "access_denied",
      error_description: "a scoped owner token is required",
    });

    const introspected = await ctx!.app.request("/pdpp/v1/introspect", {
      method: "POST",
      headers: {
        authorization: `Bearer ${legacyToken}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ token: ouraToken }).toString(),
    });
    expect(introspected.status).toBe(403);
    expect(await json(introspected)).toMatchObject({
      error: "access_denied",
      error_description: "introspection requires a scoped owner token",
    });

    const revoked = await ctx!.app.request("/pdpp/v1/revoke", {
      method: "POST",
      headers: {
        authorization: `Bearer ${legacyToken}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ grant_id: "grant-never-reached" }).toString(),
    });
    expect(revoked.status).toBe(403);
    expect(await json(revoked)).toMatchObject({
      error: "access_denied",
      error_description: "a scoped owner token is required",
    });
  });
});
