/**
 * Wire oracles for the locked PDPP Core v0.1.0 held-data lifecycle (work
 * package 6): the grant lifecycle operation (AS item 39), owner ending
 * paths with explicit dispositions (item 41), erasure requests and stages
 * (items 42, 43), decommission and token disabling (item 46), lifecycle
 * recovery (item 47), final-review held-data statements (item 45), and the
 * fail-closed behaviour of every route while the history is not current
 * (item 44). The case-by-case conformance matrix runs at the Core layer in
 * packages/core/src/pdpp/wp6-held-data-lifecycle.test.ts.
 */

import { copyFileSync, existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Hono, type Context } from "hono";
import pino from "pino";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  AuthorizationSessionStore,
  computeS256Challenge,
  defaultAnchorIo,
  GrantLifecycleService,
  openPdppAuthStore,
  PDPP_DATA_ACCESS_TYPE,
  PDPP_GRANT_LIFECYCLE_TYPE,
  PdppTokenService,
  type DeclarationSnapshot,
  type PdppAuthStore,
} from "@opendatalabs/personal-server-ts-core/pdpp";
import { pdppAuthRoutes } from "./pdpp-auth.js";

const logger = pino({ level: "silent" });
const OWNER = "user_abc123";
const CLIENT = "music_recommendations";
const REDIRECT = "https://app.example.com/callback";
const SOURCE_ID = "https://registry.pdpp.dev/connectors/spotify";
const INSTANCE = "spotify-account-a";
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE = computeS256Challenge(VERIFIER);

const snapshot: DeclarationSnapshot = {
  source_id: SOURCE_ID,
  source_kind: "connector",
  version: "2026-08-11",
  digest: "d".repeat(64),
  display: { name: "Spotify" },
  streams: [
    {
      name: "top_artists",
      fields: ["id", "name", "genres"],
      required_fields: ["id"],
      primary_key: ["id"],
    },
  ],
};

let dir: string;
let dbPath: string;
let store: PdppAuthStore;
let tokens: PdppTokenService;
let app: Hono;
let queryLimit: number | undefined;

function build() {
  store = openPdppAuthStore(dbPath);
  tokens = new PdppTokenService(store);
  const lifecycle = new GrantLifecycleService(store, {
    ...(queryLimit && { queriesPerRetryInterval: queryLimit }),
  });
  app = new Hono();
  app.route(
    "/pdpp/v1",
    pdppAuthRoutes({
      logger,
      store,
      tokens,
      lifecycle,
      sessions: new AuthorizationSessionStore(),
      issuer: "https://ps.example",
      resolveDeclaration: (id) => (id === SOURCE_ID ? snapshot : null),
      inventoryFor: () => ({
        eligibleFor: (s) => (s === "top_artists" ? [INSTANCE] : []),
      }),
      currentSubjectId: (c: Context) =>
        c.req.header("authorization") ? OWNER : null,
      registeredClient: (id) =>
        id === CLIENT ? { client_id: id, redirect_uris: [REDIRECT] } : null,
    }),
  );
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "pdpp-wp6-routes-"));
  dbPath = join(dir, "auth.db");
  queryLimit = undefined;
  build();
});

afterEach(() => {
  store.close();
  rmSync(dir, { recursive: true, force: true });
});

function ownerToken(): string {
  return tokens.issueOwnerToken({ subjectId: OWNER, sourceId: SOURCE_ID })
    .access_token;
}
const auth = (token: string) => ({ authorization: `Bearer ${token}` });

function postJson(path: string, payload: unknown, token = ownerToken()) {
  return app.request(path, {
    method: "POST",
    headers: { "content-type": "application/json", ...auth(token) },
    body: JSON.stringify(payload),
  });
}

function postForm(
  path: string,
  fields: Record<string, string> | URLSearchParams,
  headers: Record<string, string> = {},
) {
  return app.request(path, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      ...headers,
    },
    body: (fields instanceof URLSearchParams
      ? fields
      : new URLSearchParams(fields)
    ).toString(),
  });
}

function authorizeBody(details: unknown[]) {
  return {
    client_id: CLIENT,
    redirect_uri: REDIRECT,
    state: "xyz",
    code_challenge: CHALLENGE,
    code_challenge_method: "S256",
    client_display: { name: "Concert Finder" },
    authorization_details: details,
  };
}

const dataDetail = {
  type: PDPP_DATA_ACCESS_TYPE,
  source: { id: SOURCE_ID },
  purpose_code: "https://pdpp.dev/purpose/personalization",
  access_mode: "continuous",
  streams: [{ name: "top_artists", fields: ["*"] }],
};

async function issueGrant() {
  const token = ownerToken();
  const created = await postJson(
    "/pdpp/v1/authorize",
    authorizeBody([dataDetail]),
    token,
  );
  const { session_id } = (await created.json()) as { session_id: string };
  const reviewed = await app.request(
    `/pdpp/v1/authorize/${session_id}/review`,
    { headers: auth(token) },
  );
  const { review } = (await reviewed.json()) as {
    review: { review_digest: string; held_data?: unknown };
  };
  const approved = await postJson(
    `/pdpp/v1/authorize/${session_id}/approve`,
    { review_digest: review.review_digest },
    token,
  );
  expect(approved.status).toBe(200);
  const { redirect_uri, grant_id } = (await approved.json()) as {
    redirect_uri: string;
    grant_id: string;
  };
  const code = new URL(redirect_uri).searchParams.get("code")!;
  const redeemed = await postForm("/pdpp/v1/token", {
    grant_type: "authorization_code",
    code,
    client_id: CLIENT,
    redirect_uri: REDIRECT,
    code_verifier: VERIFIER,
  });
  expect(redeemed.status).toBe(200);
  const issued = (await redeemed.json()) as {
    access_token: string;
    refresh_token: string;
  };
  return { grantId: grant_id, ...issued, review };
}

async function lifecycleQuery(
  fields: Record<string, string> | URLSearchParams,
) {
  const res = await postForm("/pdpp/v1/grant-lifecycle", fields);
  return {
    res,
    body: (await res.json()) as Record<string, unknown> & {
      grants?: Array<Record<string, unknown>>;
    },
  };
}

describe("AS items 33, 39 — discovery", () => {
  it("advertises pdpp_grant_lifecycle_endpoint and the grant-lifecycle type", async () => {
    const res = await app.request(
      "/pdpp/v1/.well-known/oauth-authorization-server",
    );
    const metadata = (await res.json()) as Record<string, unknown>;
    expect(metadata.pdpp_grant_lifecycle_endpoint).toBe(
      "https://ps.example/pdpp/v1/grant-lifecycle",
    );
    expect(metadata.authorization_details_types_supported).toContain(
      PDPP_GRANT_LIFECYCLE_TYPE,
    );
  });
});

describe("AS item 45 — final review shows what happens to held data", () => {
  it("carries the held-data and onward-disclosure statements", async () => {
    const { review } = await issueGrant();
    const held = (
      review as {
        held_data: { after_grant_ends: string[]; onward_disclosure: string };
      }
    ).held_data;
    const text = held.after_grant_ends.join(" ");
    expect(text).toMatch(
      /keep using the data it received for the approved purpose, unless you ask for deletion/,
    );
    expect(text).toMatch(/no retention limit/);
    expect(text).toMatch(
      /A try is not an answer, and there is no maximum delivery delay/,
    );
    expect(text).toMatch(/not running does not check/);
    expect(text).toMatch(
      /binds the app at once as an instruction, but it is not instant physical deletion/,
    );
    expect(held.onward_disclosure).toMatch(/independent recipient/);
    expect(held.onward_disclosure).toMatch(/cannot technically prevent/);
  });
});

describe("AS item 39 — the lifecycle endpoint on the wire", () => {
  it("answers 200 JSON with no-store, and refuses JSON bodies", async () => {
    const g = await issueGrant();
    const { res, body } = await lifecycleQuery({
      grant_id: g.grantId,
      token: g.access_token,
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(res.headers.get("pragma")).toBe("no-cache");
    expect(res.headers.get("content-type")).toMatch(/application\/json/);
    expect(body.grants).toEqual([
      expect.objectContaining({
        grant_id: g.grantId,
        read_state: "active",
        held_data: "permitted",
      }),
    ]);
    const json = await app.request("/pdpp/v1/grant-lifecycle", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ grant_id: g.grantId, token: g.access_token }),
    });
    expect(json.status).toBe(400);
  });

  it("401 invalid_token for an unknown token; 400 for both report and disposition", async () => {
    const g = await issueGrant();
    const bad = await lifecycleQuery({
      grant_id: g.grantId,
      token: "pdpp_at_nope",
    });
    expect(bad.res.status).toBe(401);
    expect(bad.body.error).toBe("invalid_token");
    expect(bad.res.headers.get("www-authenticate")).toMatch(/invalid_token/);
    const both = await lifecycleQuery({
      grant_id: g.grantId,
      token: g.access_token,
      report: "received",
      pdpp_disposition: "delete",
    });
    expect(both.res.status).toBe(400);
    expect(both.body.error).toBe("invalid_request");
  });

  it("C1a: 429 with Retry-After past the per-grant allowance", async () => {
    store.close();
    queryLimit = 1;
    build();
    const g = await issueGrant();
    expect(
      (await lifecycleQuery({ grant_id: g.grantId, token: g.access_token })).res
        .status,
    ).toBe(200);
    const limited = await lifecycleQuery({
      grant_id: g.grantId,
      token: g.access_token,
    });
    expect(limited.res.status).toBe(429);
    expect(Number(limited.res.headers.get("retry-after"))).toBeGreaterThan(0);
  });

  it("P4/P5 over RFC 7009: a refresh-family revocation with pdpp_disposition=delete answers erase", async () => {
    const g = await issueGrant();
    const revoked = await postForm("/pdpp/v1/token/revoke", {
      token: g.refresh_token,
      token_type_hint: "refresh_token",
      client_id: CLIENT,
      pdpp_disposition: "delete",
    });
    expect(revoked.status).toBe(200);
    const { body } = await lifecycleQuery({
      grant_id: g.grantId,
      token: g.refresh_token,
      token_type_hint: "refresh_token",
    });
    expect(body.grants![0]).toMatchObject({
      read_state: "revoked",
      held_data: "erase",
    });
  });
});

describe("AS item 41 — owner ending routes require an explicit disposition", () => {
  it("POST /revoke without a disposition is rejected and ends nothing", async () => {
    const g = await issueGrant();
    const res = await postForm(
      "/pdpp/v1/revoke",
      { grant_id: g.grantId },
      auth(ownerToken()),
    );
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({
      error: "invalid_request",
      error_code: "disposition_required",
      missing: [g.grantId],
    });
    expect(tokens.resolveToken(g.access_token).active).toBe(true);
    const bad = await postForm(
      "/pdpp/v1/revoke",
      { grant_id: g.grantId, disposition: "maybe" },
      auth(ownerToken()),
    );
    expect(bad.status).toBe(400);
  });

  it("POST /revoke with delete revokes, records an instruction, and stays back-compatible", async () => {
    const g = await issueGrant();
    const res = await postForm(
      "/pdpp/v1/revoke",
      { grant_id: g.grantId, disposition: "delete" },
      auth(ownerToken()),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, any>;
    expect(body).toMatchObject({
      grant_id: g.grantId,
      status: "revoked",
      result: { complete: true },
    });
    expect(body.lifecycle.erasure.latest_stage).toBe("requested");
    expect(body.lifecycle.erasure.deletion_due_by).toBeUndefined();
    const q = await lifecycleQuery({
      grant_id: g.grantId,
      token: g.access_token,
    });
    expect(q.body.grants![0]).toMatchObject({ held_data: "erase" });
  });

  it("disconnect: GET lists the affected set; POST without dispositions is rejected; one choice may apply to all", async () => {
    const a = await issueGrant();
    const b = await issueGrant();
    const token = ownerToken();
    const listed = await app.request(
      `/pdpp/v1/owner/grants/affected?action=disconnect_client&client_id=${CLIENT}`,
      { headers: auth(token) },
    );
    expect(listed.status).toBe(200);
    const set = (await listed.json()) as {
      grants: Array<{ grant_id: string; preselected: null; options: unknown }>;
      will_end: string[];
    };
    expect(set.grants.map((g) => g.grant_id).sort()).toEqual(
      [a.grantId, b.grantId].sort(),
    );
    expect(set.grants.every((g) => g.preselected === null)).toBe(true);
    expect(set.will_end.sort()).toEqual([a.grantId, b.grantId].sort());

    const none = await postJson(
      "/pdpp/v1/owner/grants/end",
      { action: "disconnect_client", client_id: CLIENT },
      token,
    );
    expect(none.status).toBe(400);
    expect(
      ((await none.json()) as { missing: string[] }).missing.sort(),
    ).toEqual([a.grantId, b.grantId].sort());

    const done = await postJson(
      "/pdpp/v1/owner/grants/end",
      { action: "disconnect_client", client_id: CLIENT, disposition: "keep" },
      token,
    );
    expect(done.status).toBe(200);
    const q = await lifecycleQuery({
      grant_id: a.grantId,
      token: a.access_token,
    });
    expect(q.body.grants![0]).toMatchObject({
      read_state: "revoked",
      held_data: "permitted",
    });
  });

  it("owner erasure: an advance election keeps the grant active; an immediate one ends it", async () => {
    const g = await issueGrant();
    const token = ownerToken();
    const adv = await postJson(
      "/pdpp/v1/owner/grants/erasure",
      { grant_id: g.grantId, advance: true },
      token,
    );
    expect(adv.status).toBe(200);
    expect(tokens.resolveToken(g.access_token).active).toBe(true);
    const now = await postJson(
      "/pdpp/v1/owner/grants/erasure",
      { grant_id: g.grantId },
      token,
    );
    expect(now.status).toBe(200);
    expect(tokens.resolveToken(g.access_token).active).toBe(false);
  });

  it("GET /grants shows each grant's lifecycle and the history state", async () => {
    const g = await issueGrant();
    await postForm(
      "/pdpp/v1/revoke",
      { grant_id: g.grantId, disposition: "delete" },
      auth(ownerToken()),
    );
    await lifecycleQuery({ grant_id: g.grantId, token: g.access_token });
    const res = await app.request("/pdpp/v1/grants", {
      headers: auth(ownerToken()),
    });
    const body = (await res.json()) as {
      grants: Array<Record<string, any>>;
      history: { current: boolean };
    };
    expect(body.history.current).toBe(true);
    const listed = body.grants.find((x) => x.grant_id === g.grantId)!;
    expect(listed.status).toBe("revoked");
    expect(listed.lifecycle).toMatchObject({
      read_state: "revoked",
      disposition: "delete",
      erasure: { latest_stage: "sent" },
    });
    expect(listed.lifecycle.erasure.summary).toMatch(/no receipt reported/);
    expect(listed.lifecycle.erasure.deletion_due_by).toBeUndefined();
  });
});

describe("AS item 46 — decommission and token disabling over HTTP", () => {
  it("lists stages and requires a disposition for every offered grant", async () => {
    const a = await issueGrant();
    const b = await issueGrant();
    const token = ownerToken();
    await postForm(
      "/pdpp/v1/revoke",
      { grant_id: a.grantId, disposition: "delete" },
      auth(token),
    );
    const view = await app.request("/pdpp/v1/owner/decommission", {
      headers: auth(token),
    });
    const listed = (await view.json()) as {
      grants: Array<{ grant_id: string; stage: string; warning?: string }>;
    };
    expect(listed.grants.find((g) => g.grant_id === a.grantId)).toMatchObject({
      stage: "recorded",
    });
    expect(
      listed.grants.find((g) => g.grant_id === a.grantId)!.warning,
    ).toMatch(/cannot learn of it/);
    expect(listed.grants.find((g) => g.grant_id === b.grantId)).toMatchObject({
      stage: "offered",
    });
    const rejected = await postJson(
      "/pdpp/v1/owner/decommission/confirm",
      {},
      token,
    );
    expect(rejected.status).toBe(400);
    const ok = await postJson(
      "/pdpp/v1/owner/decommission/confirm",
      { dispositions: { [b.grantId]: "keep" } },
      token,
    );
    expect(ok.status).toBe(200);
    expect(
      ((await ok.json()) as { confirmed_at?: string }).confirmed_at,
    ).toBeDefined();
  });

  it("D3: disabling a client's tokens for lifecycle use gives invalid_token and leaves reads alone", async () => {
    const g = await issueGrant();
    const res = await postJson("/pdpp/v1/owner/lifecycle/disable-tokens", {
      client_id: CLIENT,
      grant_ids: [g.grantId],
    });
    expect(res.status).toBe(200);
    expect(
      ((await res.json()) as { disabled: number }).disabled,
    ).toBeGreaterThanOrEqual(2);
    expect(
      (await lifecycleQuery({ grant_id: g.grantId, token: g.access_token })).res
        .status,
    ).toBe(401);
    expect(tokens.resolveToken(g.access_token).active).toBe(true);
  });
});

describe("AS item 47 / D3 — lifecycle recovery over HTTP", () => {
  async function recover(grantIds: string[]) {
    const token = ownerToken();
    const created = await postJson(
      "/pdpp/v1/authorize",
      authorizeBody([{ type: PDPP_GRANT_LIFECYCLE_TYPE, grant_ids: grantIds }]),
      token,
    );
    expect(created.status).toBe(201);
    const { session_id } = (await created.json()) as { session_id: string };
    const reviewed = await app.request(
      `/pdpp/v1/authorize/${session_id}/review`,
      { headers: auth(token) },
    );
    expect(reviewed.status).toBe(200);
    const { recovery } = (await reviewed.json()) as {
      recovery: { review_digest: string; statement: string; grants: unknown[] };
    };
    const approved = await postJson(
      `/pdpp/v1/authorize/${session_id}/approve`,
      { review_digest: recovery.review_digest },
      token,
    );
    expect(approved.status).toBe(200);
    const code = new URL(
      ((await approved.json()) as { redirect_uri: string }).redirect_uri,
    ).searchParams.get("code")!;
    const redeemed = await postForm("/pdpp/v1/token", {
      grant_type: "authorization_code",
      code,
      client_id: CLIENT,
      redirect_uri: REDIRECT,
      code_verifier: VERIFIER,
    });
    return {
      recovery,
      redeemed,
      body: (await redeemed.json()) as Record<string, unknown>,
    };
  }

  it("issues a lifecycle-only token with no refresh token that the RS path and introspection reject", async () => {
    const g = await issueGrant();
    await postForm(
      "/pdpp/v1/revoke",
      { grant_id: g.grantId, disposition: "delete" },
      auth(ownerToken()),
    );
    const { recovery, redeemed, body } = await recover([g.grantId]);
    expect(recovery.statement).toMatch(/no access to read your data/);
    expect(recovery.grants).toHaveLength(1);
    expect(redeemed.status).toBe(200);
    expect(body.refresh_token).toBeUndefined();
    expect(body.grant_id).toBeUndefined();
    expect(body.authorization_details).toEqual([
      { type: PDPP_GRANT_LIFECYCLE_TYPE, grant_ids: [g.grantId] },
    ]);
    const lt = body.access_token as string;
    const introspected = await postForm(
      "/pdpp/v1/introspect",
      { token: lt },
      auth(ownerToken()),
    );
    expect(await introspected.json()).toEqual({ active: false });
    expect(tokens.resolveToken(lt).active).toBe(false);
    const q = await lifecycleQuery({ grant_id: g.grantId, token: lt });
    const erasure = (
      q.body.grants![0] as { erasure: { instruction_id: string } }
    ).erasure;
    const w = await lifecycleQuery({
      grant_id: g.grantId,
      token: lt,
      report: "completed",
      instruction_id: erasure.instruction_id,
      reported_at: new Date(Date.now() - 1000).toISOString(),
    });
    expect(w.body.grants![0]).toMatchObject({ held_data: "erase" });
  });

  it("rejects a mixed request, an extra member, and a grant that cannot be recovered", async () => {
    const g = await issueGrant();
    const mixed = await postJson(
      "/pdpp/v1/authorize",
      authorizeBody([
        { type: PDPP_GRANT_LIFECYCLE_TYPE, grant_ids: [g.grantId] },
        dataDetail,
      ]),
    );
    expect(mixed.status).toBe(400);
    expect(((await mixed.json()) as { error: string }).error).toBe(
      "invalid_authorization_details",
    );
    const extra = await postJson(
      "/pdpp/v1/authorize",
      authorizeBody([
        {
          type: PDPP_GRANT_LIFECYCLE_TYPE,
          grant_ids: [g.grantId],
          streams: [],
        },
      ]),
    );
    expect(extra.status).toBe(400);
    const unknown = await postJson(
      "/pdpp/v1/authorize",
      authorizeBody([
        {
          type: PDPP_GRANT_LIFECYCLE_TYPE,
          grant_ids: [g.grantId, "grt_other"],
        },
      ]),
    );
    expect(unknown.status).toBe(400);
    expect(
      ((await unknown.json()) as { error: string; error_description: string })
        .error_description,
    ).not.toContain("grt_other");
  });
});

describe("AS item 44 / D4 — routes while the history is not current", () => {
  function restoreOlderDatabase(backupPath: string) {
    store.close();
    for (const s of ["-wal", "-shm"])
      if (existsSync(dbPath + s)) rmSync(dbPath + s);
    copyFileSync(backupPath, dbPath);
    build();
  }

  it("fails closed on token paths, accepts owner revocations as pending, and re-establishes with dispositions", async () => {
    const g = await issueGrant();
    const h = await issueGrant(); // still active when the history is re-established
    (store as unknown as { db: { pragma(s: string): void } }).db.pragma(
      "wal_checkpoint(TRUNCATE)",
    );
    const backupPath = join(dir, "old.db");
    copyFileSync(dbPath, backupPath);
    await issueGrant(); // events after the backup
    restoreOlderDatabase(backupPath);

    const refreshed = await postForm("/pdpp/v1/token", {
      grant_type: "refresh_token",
      refresh_token: g.refresh_token,
    });
    expect(refreshed.status).toBe(503);
    expect(refreshed.headers.get("retry-after")).toBeTruthy();
    const q = await lifecycleQuery({
      grant_id: g.grantId,
      token: g.access_token,
    });
    expect(q.res.status).toBe(503);
    expect(q.res.headers.get("retry-after")).toBeTruthy();
    expect(q.body.error).toBe("temporarily_unavailable");
    const introspected = await postForm(
      "/pdpp/v1/introspect",
      { token: g.access_token },
      auth(ownerToken()),
    );
    expect(await introspected.json()).toEqual({ active: false });

    // Owner revocation is accepted, recorded and shown pending.
    const revoked = await postForm(
      "/pdpp/v1/revoke",
      { grant_id: g.grantId, disposition: "delete" },
      auth(ownerToken()),
    );
    expect(revoked.status).toBe(202);
    expect(
      (
        (await revoked.json()) as {
          result: { grants: unknown[]; statement: string };
        }
      ).result,
    ).toMatchObject({
      grants: [
        { grant_id: g.grantId, state: "pending", disposition: "delete" },
      ],
      statement: expect.stringMatching(/recorded and pending/),
    });
    const listed = (await (
      await app.request("/pdpp/v1/grants", { headers: auth(ownerToken()) })
    ).json()) as {
      history: {
        current: boolean;
        pending_actions: unknown[];
        statement: string;
      };
    };
    expect(listed.history.current).toBe(false);
    expect(listed.history.pending_actions).toHaveLength(1);

    const status = (await (
      await app.request("/pdpp/v1/owner/lifecycle/history", {
        headers: auth(ownerToken()),
      })
    ).json()) as {
      current: boolean;
      reason: string;
      reestablish_ends: Array<{ grant_id: string }>;
    };
    expect(status).toMatchObject({
      current: false,
      reason: "history_behind_anchor",
    });
    expect(status.reestablish_ends.map((x) => x.grant_id)).toEqual([h.grantId]);
    // F7: a token scoped to another source sees none of these grants.
    const otherSource = tokens.issueOwnerToken({
      subjectId: OWNER,
      sourceId: "https://registry.pdpp.dev/connectors/other",
    }).access_token;
    const scoped = (await (
      await app.request("/pdpp/v1/owner/lifecycle/history", {
        headers: auth(otherSource),
      })
    ).json()) as { reestablish_ends: unknown[] };
    expect(scoped.reestablish_ends).toEqual([]);

    const missing = await postJson("/pdpp/v1/owner/lifecycle/reestablish", {});
    expect(missing.status).toBe(400);
    expect(((await missing.json()) as { missing: string[] }).missing).toEqual([
      h.grantId,
    ]);
    const ok = await postJson("/pdpp/v1/owner/lifecycle/reestablish", {
      disposition: "keep",
    });
    expect(ok.status).toBe(200);
    const after = await lifecycleQuery({
      grant_id: g.grantId,
      token: g.access_token,
    });
    expect(after.body.grants![0]).toMatchObject({
      read_state: "revoked",
      held_data: "erase",
    });
    const kept = await lifecycleQuery({
      grant_id: h.grantId,
      token: h.access_token,
    });
    expect(kept.body.grants![0]).toMatchObject({
      read_state: "revoked",
      held_data: "permitted",
    });
    expect(tokens.resolveToken(h.access_token).active).toBe(false);
  });
});

describe("whole-server owner actions take the wallet proof when it is wired", () => {
  it("refuses a source-scoped owner token on reestablish and decommission confirm", async () => {
    const guarded = new Hono();
    guarded.route(
      "/pdpp/v1",
      pdppAuthRoutes({
        logger,
        store,
        tokens,
        sessions: new AuthorizationSessionStore(),
        issuer: "https://ps.example",
        resolveDeclaration: () => null,
        inventoryFor: () => ({ eligibleFor: () => [] }),
        currentSubjectId: () => OWNER,
        ownerAuth: {
          serverOrigin: "https://ps.example",
          serverOwner: "0x1111111111111111111111111111111111111111",
        },
      }),
    );
    for (const path of [
      "/pdpp/v1/owner/lifecycle/reestablish",
      "/pdpp/v1/owner/decommission/confirm",
    ]) {
      const res = await guarded.request(path, {
        method: "POST",
        headers: { "content-type": "application/json", ...auth(ownerToken()) },
        body: JSON.stringify({ disposition: "keep" }),
      });
      expect(res.status).toBe(401);
    }
  });
});

describe("R1 — owner read routes while evidence is owed", () => {
  it("refuses GET /grants with 503 and reports /revoke as pending until the evidence is written", async () => {
    store.close();
    let fail = false;
    store = openPdppAuthStore(dbPath, {
      anchorIo: {
        read: defaultAnchorIo.read,
        writeDurably(path, content) {
          if (fail) throw new Error("injected");
          defaultAnchorIo.writeDurably(path, content);
        },
      },
    });
    tokens = new PdppTokenService(store);
    const lifecycle = new GrantLifecycleService(store);
    app = new Hono();
    app.route(
      "/pdpp/v1",
      pdppAuthRoutes({
        logger,
        store,
        tokens,
        lifecycle,
        sessions: new AuthorizationSessionStore(),
        issuer: "https://ps.example",
        resolveDeclaration: (id) => (id === SOURCE_ID ? snapshot : null),
        inventoryFor: () => ({
          eligibleFor: (s) => (s === "top_artists" ? [INSTANCE] : []),
        }),
        currentSubjectId: (c: Context) =>
          c.req.header("authorization") ? OWNER : null,
        registeredClient: (id) =>
          id === CLIENT ? { client_id: id, redirect_uris: [REDIRECT] } : null,
      }),
    );
    const g = await issueGrant();
    const token = ownerToken();
    fail = true;
    const revoked = await postForm(
      "/pdpp/v1/revoke",
      { grant_id: g.grantId, disposition: "delete" },
      auth(token),
    );
    expect(revoked.status).toBe(503);
    expect(((await revoked.json()) as { status: string }).status).toBe(
      "pending",
    );
    const listed = await app.request("/pdpp/v1/grants", {
      headers: auth(token),
    });
    expect(listed.status).toBe(503);
    fail = false;
    const ok = await app.request("/pdpp/v1/grants", { headers: auth(token) });
    expect(ok.status).toBe(200);
    const body = (await ok.json()) as {
      grants: Array<{
        grant_id: string;
        lifecycle: { evidence: string; read_state: string };
      }>;
    };
    expect(
      body.grants.find((x) => x.grant_id === g.grantId)!.lifecycle,
    ).toMatchObject({ evidence: "recorded", read_state: "revoked" });
  });
});
