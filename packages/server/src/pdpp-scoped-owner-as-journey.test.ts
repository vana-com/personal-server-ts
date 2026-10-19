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
import Database from "better-sqlite3";
import { recoverServerOwner } from "@opendatalabs/vana-sdk/node";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import {
  computeS256Challenge,
  openPdppAuthStore,
  PdppTokenService,
} from "@opendatalabs/personal-server-ts-core/pdpp";
import { createServer, type ServerContext } from "./bootstrap.js";
import { registerTestConnection } from "./pdpp/test-connections.js";

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
  const connector = sourceId.split("/").filter(Boolean).at(-1) ?? sourceId;
  return `${connector}:${owner}`;
}

async function ownerToken(sourceId: string): Promise<string> {
  return registerTestConnection(ctx!.app, ctx!.devToken, owner, sourceId);
}

function unscopedOwnerToken(): string {
  const store = openPdppAuthStore(join(tempDir, "pdpp-auth.db"));
  try {
    return new PdppTokenService(store).issueOwnerToken({
      subjectId: owner,
      sourceId: OURA,
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
      sourceId: OURA,
    }).access_token;
  } finally {
    store.close();
  }
}

async function ingestOuraSleep(
  token: string,
  instanceId = instance(OURA),
  score = 91,
) {
  const response = await ctx!.app.request(
    "/v1/streams/sleep/records/ingest?method=oura&binding_generation=1",
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        instance: instanceId,
        key: "sleep-1",
        data: { id: "sleep-1", score },
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

async function issueOuraGrant(
  token: string,
  instanceChoices?: Record<string, string[]>,
): Promise<{
  accessToken: string;
  grantId: string;
}> {
  const sessionId = await authorizeOura(token);
  const choiceQuery = instanceChoices
    ? `?${new URLSearchParams(
        Object.entries(instanceChoices).map(([stream, [instanceId]]) => [
          `instance[${stream}]`,
          instanceId,
        ]),
      )}`
    : "";
  const reviewed = await ctx!.app.request(
    `/pdpp/v1/authorize/${sessionId}/review${choiceQuery}`,
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
      body: JSON.stringify({
        review_digest: review.review_digest,
        ...(instanceChoices && { instance_choices: instanceChoices }),
      }),
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
      error_description: "owner token is not scoped to the requested source",
    });

    const ouraSession = await authorizeOura(ouraToken);
    const claudeReview = await ctx!.app.request(
      `/pdpp/v1/authorize/${ouraSession}/review`,
      { headers: { authorization: `Bearer ${claudeToken}` } },
    );
    expect(claudeReview.status).toBe(403);
    expect(await json(claudeReview)).toMatchObject({
      error: "access_denied",
      error_description: "owner token is not scoped to the requested source",
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
      error_description: "owner token is not scoped to the requested source",
    });
    expect(claudeApprovalBody.redirect_uri).toBeUndefined();

    const secondOuraRead = await readSleep(claudeToken);
    expect(secondOuraRead.status).toBe(404);
  });

  it("restarts after the owner deletes the legacy account-one connection", async () => {
    const token = await ownerToken(OURA);
    await ingestOuraSleep(token);

    const connectionId = instance(OURA);
    const deleted = await ctx!.app.request(
      `/pdpp/connections/${encodeURIComponent(connectionId)}`,
      { method: "DELETE", headers: { authorization: `Bearer ${token}` } },
    );
    expect(deleted.status).toBe(200);

    await ctx!.cleanup();
    ctx = undefined;
    ctx = await bootBoth();

    const reRegistered = await ctx.app.request(
      `/pdpp/connections/${encodeURIComponent(connectionId)}`,
      {
        method: "PUT",
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          source_id: OURA,
          method_id: "oura",
          label: "Personal",
        }),
      },
    );
    expect(reRegistered.status).toBe(409);
    expect(await json(reRegistered)).toMatchObject({
      error: { code: "connection_deleted" },
    });
  });

  it("restores known legacy account-one bindings on boot without a Desktop PUT", async () => {
    const token = await ownerToken(OURA);
    await ingestOuraSleep(token);
    const { accessToken } = await issueOuraGrant(token);

    await ctx!.cleanup();
    ctx = undefined;
    const db = new Database(join(tempDir, "index.db"));
    try {
      // Restore the base PS v5 schema. Its known method and legacy id remain;
      // v6 must add the connection metadata before boot can adopt the row.
      db.exec(`
        ALTER TABLE pdpp_instance_binding DROP COLUMN deleted_at;
        ALTER TABLE pdpp_instance_binding DROP COLUMN label;
        ALTER TABLE pdpp_instance_binding DROP COLUMN source_id;
        UPDATE pdpp_schema_version SET version = 5 WHERE id = 1;
      `);
    } finally {
      db.close();
    }

    ctx = await bootBoth();

    const existingRead = await readSleep(accessToken);
    expect(existingRead.status).toBe(200);
    expect(existingRead.body.data).toEqual({ id: "sleep-1", score: 91 });
    const existingList = await ctx.app.request("/v1/streams/sleep/records", {
      headers: { authorization: `Bearer ${accessToken}` },
    });
    expect(existingList.status).toBe(200);

    const desktopMint = await ctx.app.request("/pdpp/v1/owner/token", {
      method: "POST",
      headers: {
        authorization: `Bearer ${ctx.devToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        source_id: OURA,
        instance_id: instance(OURA),
      }),
    });
    expect(desktopMint.status).toBe(200);
    const { access_token: ownerAccess } = (await desktopMint.json()) as {
      access_token: string;
    };
    const write = await ctx.app.request(
      "/v1/streams/sleep/records/ingest?method=oura&binding_generation=1",
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${ownerAccess}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          instance: instance(OURA),
          key: "sleep-2",
          data: { id: "sleep-2", score: 50 },
          emitted_at: "2026-09-02T00:00:00Z",
        }),
      },
    );
    expect(write.status).toBe(200);
    expect((await authorizeOura(ownerAccess)).length).toBeGreaterThan(0);
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

  it("uses source-wide owner tokens for consent and grant management", async () => {
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
    expect(authorized.status).toBe(201);

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
    expect(multiAuthorized.status).toBe(201);

    const ouraSession = await authorizeOura(ouraToken);
    const reviewed = await ctx!.app.request(
      `/pdpp/v1/authorize/${ouraSession}/review`,
      { headers: { authorization: `Bearer ${legacyToken}` } },
    );
    expect(reviewed.status).toBe(200);

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
    expect(approved.status).toBe(200);

    const grants = await ctx!.app.request("/pdpp/v1/grants", {
      headers: { authorization: `Bearer ${legacyToken}` },
    });
    expect(grants.status).toBe(200);

    const introspected = await ctx!.app.request("/pdpp/v1/introspect", {
      method: "POST",
      headers: {
        authorization: `Bearer ${legacyToken}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ token: ouraToken }).toString(),
    });
    expect(introspected.status).toBe(200);
    expect(await json(introspected)).toMatchObject({
      active: true,
      source_id: OURA,
    });

    const revoked = await ctx!.app.request("/pdpp/v1/revoke", {
      method: "POST",
      headers: {
        authorization: `Bearer ${legacyToken}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ grant_id: "grant-never-reached" }).toString(),
    });
    expect(revoked.status).toBe(404);
    expect(await json(revoked)).toMatchObject({
      error: "not_found",
      error_description: "grant not found",
    });
  });

  it("keeps deleted-connection grants listed and revocable while each read returns 404", async () => {
    const owner = await ownerToken(OURA);
    await ingestOuraSleep(owner);
    const { accessToken, grantId } = await issueOuraGrant(owner);

    const deleted = await ctx!.app.request(
      `/pdpp/connections/${encodeURIComponent(instance(OURA))}`,
      { method: "DELETE", headers: { authorization: `Bearer ${owner}` } },
    );
    expect(deleted.status).toBe(200);

    for (const path of [
      "/v1/streams/sleep/records",
      "/v1/streams/sleep/records?changes_since=0",
      "/v1/streams/sleep/records/sleep-1",
      "/v1/blobs/sha256:missing",
    ]) {
      const response = await ctx!.app.request(path, {
        headers: { authorization: `Bearer ${accessToken}` },
      });
      expect(response.status, path).toBe(404);
      expect(await json(response), path).toMatchObject({
        error: { code: "instance_unavailable" },
      });
    }

    const grants = await ctx!.app.request("/pdpp/v1/grants", {
      headers: { authorization: `Bearer ${owner}` },
    });
    expect(await json(grants)).toMatchObject({
      grants: [expect.objectContaining({ grant_id: grantId })],
    });

    const revoked = await ctx!.app.request("/pdpp/v1/revoke", {
      method: "POST",
      headers: {
        authorization: `Bearer ${owner}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ grant_id: grantId }).toString(),
    });
    expect(revoked.status).toBe(200);
  });

  it("asks for an account when two connections exist and grants only the chosen account", async () => {
    const owner = await ownerToken(OURA);
    const accountB = "conn_123e4567-e89b-42d3-a456-426614174000";
    const registration = await ctx!.app.request(
      `/pdpp/connections/${encodeURIComponent(accountB)}`,
      {
        method: "PUT",
        headers: {
          authorization: `Bearer ${owner}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          source_id: OURA,
          method_id: "oura",
          label: "Work",
        }),
      },
    );
    expect(registration.status).toBe(200);
    await ingestOuraSleep(owner, instance(OURA), 91);
    await ingestOuraSleep(owner, accountB, 44);

    const sessionId = await authorizeOura(owner);
    const unchosen = await ctx!.app.request(
      `/pdpp/v1/authorize/${sessionId}/review`,
      { headers: { authorization: `Bearer ${owner}` } },
    );
    const choice = (await json(unchosen)).instance_choice_required as {
      stream: string;
      candidates: string[];
    }[];
    expect(choice).toHaveLength(1);
    expect(choice[0]).toMatchObject({
      stream: "sleep",
      candidates: [instance(OURA), accountB].sort(),
    });

    const fanInSessionId = await authorizeOura(owner);
    const fanIn = await ctx!.app.request(
      `/pdpp/v1/authorize/${fanInSessionId}/approve`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${owner}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          instance_choices: { sleep: [instance(OURA), accountB] },
        }),
      },
    );
    expect(fanIn.status).toBe(400);
    expect(await json(fanIn)).toMatchObject({
      error: "unsupported_instance_fan_in",
    });

    const { accessToken } = await issueOuraGrant(owner, { sleep: [accountB] });
    const read = await readSleep(accessToken);
    expect(read.status).toBe(200);
    expect(read.body.data).toEqual({ id: "sleep-1", score: 44 });
  });

  it("keeps the other connection's data and change feed after deleting one account", async () => {
    const owner = await ownerToken(OURA);
    const accountA = instance(OURA);
    const accountB = "conn_123e4567-e89b-42d3-a456-426614174000";
    const registration = await ctx!.app.request(
      `/pdpp/connections/${encodeURIComponent(accountB)}`,
      {
        method: "PUT",
        headers: {
          authorization: `Bearer ${owner}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          source_id: OURA,
          method_id: "oura",
          label: "Work",
        }),
      },
    );
    expect(registration.status).toBe(200);

    await ingestOuraSleep(owner, accountA, 91);
    await ingestOuraSleep(owner, accountB, 44);
    const grantA = await issueOuraGrant(owner, {
      sleep: [accountA],
    });
    const grantB = await issueOuraGrant(owner, {
      sleep: [accountB],
    });

    const beforeDelete = await readSleep(grantB.accessToken);
    expect(beforeDelete.status).toBe(200);
    expect(beforeDelete.body.data).toEqual({ id: "sleep-1", score: 44 });

    const baselineA = await ctx!.app.request(
      "/v1/streams/sleep/records?changes_since=",
      { headers: { authorization: `Bearer ${grantA.accessToken}` } },
    );
    const baselineB = await ctx!.app.request(
      "/v1/streams/sleep/records?changes_since=",
      { headers: { authorization: `Bearer ${grantB.accessToken}` } },
    );
    expect(baselineA.status).toBe(200);
    expect(baselineB.status).toBe(200);
    const baselineABody = (await json(baselineA)) as {
      data: Array<{ data: unknown }>;
      next_changes_since: string;
    };
    const baselineBBody = (await json(baselineB)) as {
      data: Array<{ data: unknown }>;
      next_changes_since: string;
    };
    expect(baselineABody.data).toEqual([
      expect.objectContaining({ data: { id: "sleep-1", score: 91 } }),
    ]);
    expect(baselineBBody.data).toEqual([
      expect.objectContaining({ data: { id: "sleep-1", score: 44 } }),
    ]);
    expect(baselineABody.next_changes_since).not.toBe(
      baselineBBody.next_changes_since,
    );

    const deleted = await ctx!.app.request(
      `/pdpp/connections/${encodeURIComponent(accountA)}`,
      { method: "DELETE", headers: { authorization: `Bearer ${owner}` } },
    );
    expect(deleted.status).toBe(200);

    const afterDelete = await readSleep(grantB.accessToken);
    expect(afterDelete.status).toBe(200);
    expect(afterDelete.body.data).toEqual({ id: "sleep-1", score: 44 });

    const changes = await ctx!.app.request(
      `/v1/streams/sleep/records?changes_since=${encodeURIComponent(baselineBBody.next_changes_since)}`,
      { headers: { authorization: `Bearer ${grantB.accessToken}` } },
    );
    expect(changes.status).toBe(200);
    expect(await json(changes)).toMatchObject({ data: [] });
  });
});
