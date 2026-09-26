/**
 * PDPP owner bearer bridge for the legacy /v1/data surface.
 *
 * These tests go through a real createServer app. The accepted token is minted
 * by /pdpp/v1/owner/token; the negative bearer cases use the same bootstrapped
 * PDPP auth store so the data route must resolve real PDPP token state instead
 * of fabricated route mocks.
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
const CLIENT_ID = "sleep_recommendations";
const REDIRECT = "https://app.example.com/callback";
const VERIFIER =
  "legacy-owner-bridge-verifier-0123456789abcdefghijklmnopqrstuvwxyz";
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

function instance(sourceId: string, subject = owner) {
  return singleInstanceInventory(subject, sourceId).eligibleFor("")[0];
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

function issueForeignOwnerToken(): string {
  const foreignSubject = "0x0000000000000000000000000000000000000f01";
  const store = openPdppAuthStore(join(tempDir, "pdpp-auth.db"));
  try {
    return new PdppTokenService(store).issueOwnerToken({
      subjectId: foreignSubject,
      instanceIds: [instance(OURA, foreignSubject)],
    }).access_token;
  } finally {
    store.close();
  }
}

function issueUnscopedOwnerToken(): string {
  const store = openPdppAuthStore(join(tempDir, "pdpp-auth.db"));
  try {
    return new PdppTokenService(store).issueOwnerToken({
      subjectId: owner,
    }).access_token;
  } finally {
    store.close();
  }
}

function issueStaleInstanceOwnerToken(): string {
  const store = openPdppAuthStore(join(tempDir, "pdpp-auth.db"));
  try {
    return new PdppTokenService(store).issueOwnerToken({
      subjectId: owner,
      instanceIds: [`oura:${owner}:stale`],
    }).access_token;
  } finally {
    store.close();
  }
}

async function issueClientToken(): Promise<string> {
  const token = await ownerToken(OURA);
  const authorized = await ctx!.app.request("/pdpp/v1/authorize", {
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
  expect(authorized.status).toBe(201);
  const { session_id } = (await authorized.json()) as { session_id: string };

  const reviewed = await ctx!.app.request(
    `/pdpp/v1/authorize/${session_id}/review`,
    { headers: { authorization: `Bearer ${token}` } },
  );
  expect(reviewed.status).toBe(200);
  const { review } = (await reviewed.json()) as {
    review: { review_digest: string };
  };

  const approved = await ctx!.app.request(
    `/pdpp/v1/authorize/${session_id}/approve`,
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
  const { redirect_uri } = (await approved.json()) as { redirect_uri: string };
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
  return ((await redeemed.json()) as { access_token: string }).access_token;
}

async function postLegacy(scope: string, token: string) {
  return ctx!.app.request(`/v1/data/${scope}`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ id: "row-1", score: 91 }),
  });
}

async function deleteLegacy(scope: string, token: string) {
  return ctx!.app.request(`/v1/data/${scope}`, {
    method: "DELETE",
    headers: { authorization: `Bearer ${token}` },
  });
}

async function responseCode(response: Response): Promise<string | undefined> {
  const body = (await response.json()) as {
    error?: string | { errorCode?: string };
  };
  return typeof body.error === "string" ? body.error : body.error?.errorCode;
}

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), "pdpp-owner-bearer-legacy-"));
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

describe("PDPP owner bearer bridge for POST /v1/data/:scope", () => {
  it("accepts a configured owner token for its source namespace and lists versions with the same bearer", async () => {
    const token = await ownerToken(OURA);

    const written = await postLegacy("oura.sleep", token);
    expect(written.status).toBe(201);

    const versions = await ctx!.app.request("/v1/data/oura.sleep/versions", {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(versions.status).toBe(200);
    const body = (await versions.json()) as { total: number; scope: string };
    expect(body.scope).toBe("oura.sleep");
    expect(body.total).toBe(1);
  });

  it("rejects a PDPP client bearer with a specific owner-bridge reason", async () => {
    const token = await issueClientToken();

    const response = await postLegacy("oura.sleep", token);

    expect(response.status).toBe(403);
    expect(await responseCode(response)).toBe("PDPP_CLIENT_BEARER_NOT_OWNER");
  });

  it("rejects a foreign PDPP owner bearer with a specific owner-bridge reason", async () => {
    const token = issueForeignOwnerToken();

    const response = await postLegacy("oura.sleep", token);

    expect(response.status).toBe(403);
    expect(await responseCode(response)).toBe("PDPP_OWNER_BEARER_FOREIGN");
  });

  it("rejects an old unscoped owner bearer instead of giving subject-wide legacy write authority", async () => {
    const token = issueUnscopedOwnerToken();

    const response = await postLegacy("oura.sleep", token);

    expect(response.status).toBe(403);
    expect(await responseCode(response)).toBe(
      "PDPP_OWNER_BEARER_UNSCOPED_INSTANCE",
    );
  });

  it("rejects an owner bearer whose instance is no longer currently owned", async () => {
    const token = issueStaleInstanceOwnerToken();

    const response = await postLegacy("oura.sleep", token);

    expect(response.status).toBe(403);
    expect(await responseCode(response)).toBe("PDPP_OWNER_BEARER_FOREIGN");
  });

  it("does not let an owner token for one source post a different source namespace", async () => {
    const token = await ownerToken(CLAUDE);

    const response = await postLegacy("oura.sleep", token);

    expect(response.status).toBe(403);
    expect(await responseCode(response)).toBe(
      "PDPP_OWNER_BEARER_SCOPE_MISMATCH",
    );
  });

  it("does not authorize DELETE with a PDPP owner bearer", async () => {
    const token = await ownerToken(OURA);

    const response = await deleteLegacy("oura.sleep", token);

    expect(response.status).toBe(401);
    expect(await responseCode(response)).toBe("INVALID_SIGNATURE");
  });
});
