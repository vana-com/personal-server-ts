/**
 * AS item 29 (spec-core L1427-L1435, L2002-L2014): pairwise instance handles.
 *
 * Two clients of one owner, granted the same instance, each receive their own
 * random handle. The handle is what the client sees everywhere on the client
 * RS surface (grant document, record and tombstone `instance_id`, blob
 * `fetch_url`), and the only name the RS accepts from that client
 * (`instance_id` on a single-record get or a blob read, `instance_ids` in a
 * later authorization request). Owner surfaces keep stored ids. The RS-only
 * introspection carries `pdpp_instance_bindings`.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Hono, type Context } from "hono";
import pino from "pino";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  AuthorizationSessionStore,
  computeS256Challenge,
  openPdppAuthStore,
  PDPP_DATA_ACCESS_TYPE,
  PdppTokenService,
  type DeclarationSnapshot,
  type PdppAuthStore,
} from "@opendatalabs/personal-server-ts-core/pdpp";
import {
  createMemoryRecordStore,
  createStreamDeclarationRegistry,
  type PdppRecordStore,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { fixedOwnedAccountStorageMode as explicitLegacyStorageMode } from "@opendatalabs/personal-server-ts-core/test-utils";
import type { PdppAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import { pdppAuthRoutes } from "./pdpp-auth.js";
import { pdppRecordsRoutes, type PdppChainEnforcementPort } from "./pdpp-records.js";
import { pdppBlobsRoutes } from "./pdpp-blobs.js";

const logger = pino({ level: "silent" });
const OWNER = "user_owner";
const CLIENT_A = "app_a";
const CLIENT_B = "app_b";
const REDIRECT = "https://app.example.com/callback";
const SOURCE_ID = "https://registry.pdpp.dev/connectors/photos";
const INSTANCE = "photos-account-1";
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

const snapshot: DeclarationSnapshot = {
  source_id: SOURCE_ID,
  source_kind: "connector",
  version: "v1",
  digest: "d".repeat(64),
  streams: [
    {
      name: "media",
      fields: ["id", "title", "blob_ref"],
      required_fields: ["id"],
      primary_key: ["id"],
    },
  ],
};

let dir: string;
let store: PdppAuthStore;
let tokens: PdppTokenService;
let records: PdppRecordStore;
let app: Hono;
let chainDecision: Awaited<ReturnType<PdppChainEnforcementPort["authorize"]>>;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "pdpp-as29-handles-"));
  store = openPdppAuthStore(join(dir, "auth.db"));
  tokens = new PdppTokenService(store);
  records = createMemoryRecordStore();
  records.putBlobMeta({
    blobId: "blob_1",
    mimeType: "image/jpeg",
    sizeBytes: 3,
    sha256: "abc",
  });
  records.ingestBatch(
    ["m1", "m2", "m3"].map((key, i) => ({
      instance: INSTANCE,
      stream: "media",
      key,
      data: {
        id: key,
        title: `t${i}`,
        ...(key === "m1" && { blob_ref: { blob_id: "blob_1" } }),
      },
      emitted_at: `2026-04-0${i + 1}T00:00:00.000Z`,
    })),
    () => "append_only",
    () => ["id"],
  );
  const auth: PdppAuthorizationService = {
    async resolveToken(token) {
      const context = tokens.resolveToken(token);
      return context.active
        ? { ...context, active: true, subjectId: context.subjectId ?? "" }
        : { active: false, inactiveReason: context.inactiveReason };
    },
  };
  const declarations = createStreamDeclarationRegistry([
    {
      name: "media",
      semantics: "append_only",
      primaryKey: ["id"],
      cursorField: "emitted_at",
      requiredFields: ["id"],
      declaredFields: ["id", "title", "blob_ref"],
    },
  ]);
  chainDecision = { ok: true };
  const chainEnforcement: PdppChainEnforcementPort = {
    authorize: async () => chainDecision,
  };
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
        id === CLIENT_A || id === CLIENT_B
          ? { client_id: id, redirect_uris: [REDIRECT] }
          : null,
    }),
  );
  app.route(
    "/v1/blobs",
    pdppBlobsRoutes({
      store: records,
      auth,
      declarations,
      readBlobBytes: async () => new Uint8Array([1, 2, 3]),
      chainEnforcement,
    }),
  );
  app.route(
    "/v1",
    pdppRecordsRoutes({
      accountStorageMode: explicitLegacyStorageMode("unswitched"),
      store: records,
      auth,
      declarations,
      chainEnforcement,
    }),
  );
});

afterEach(() => {
  records.close();
  store.close();
  rmSync(dir, { recursive: true, force: true });
});

function ownerToken(): string {
  return tokens.issueOwnerToken({ subjectId: OWNER, sourceId: SOURCE_ID })
    .access_token;
}

/** Approve and redeem; returns the client token and its grant document. */
async function grantFor(clientId: string, instanceIds?: string[]) {
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
      code_challenge: computeS256Challenge(VERIFIER),
      code_challenge_method: "S256",
      authorization_details: [
        {
          type: PDPP_DATA_ACCESS_TYPE,
          source: { id: SOURCE_ID },
          purpose_code: "https://pdpp.dev/purpose/personalization",
          access_mode: "continuous",
          streams: [
            {
              name: "media",
              fields: ["*"],
              ...(instanceIds && { instance_ids: instanceIds }),
            },
          ],
        },
      ],
    }),
  });
  const { session_id } = (await created.json()) as { session_id: string };
  const reviewed = await app.request(
    `/pdpp/v1/authorize/${session_id}/review`,
    { headers },
  );
  const reviewBody = (await reviewed.json()) as {
    review?: { review_digest: string; data: { streams: Array<{ instance_ids: string[] }> } };
  };
  const approved = await app.request(
    `/pdpp/v1/authorize/${session_id}/approve`,
    {
      method: "POST",
      headers,
      body: JSON.stringify({
        review_digest: reviewBody.review?.review_digest ?? "",
      }),
    },
  );
  if (approved.status !== 200)
    return { status: approved.status, review: reviewBody.review } as const;
  const { redirect_uri } = (await approved.json()) as { redirect_uri: string };
  const redeemed = await app.request("/pdpp/v1/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: new URL(redirect_uri).searchParams.get("code")!,
      client_id: clientId,
      redirect_uri: REDIRECT,
      code_verifier: VERIFIER,
    }),
  });
  const json = (await redeemed.json()) as {
    access_token: string;
    refresh_token: string;
    authorization_details: Array<{
      grant: { grant_id: string; streams: Array<{ instance_ids: string[] }> };
    }>;
  };
  const grant = json.authorization_details[0].grant;
  return {
    status: 200,
    token: json.access_token,
    refreshToken: json.refresh_token,
    grant,
    handle: grant.streams[0].instance_ids[0],
    review: reviewBody.review,
  } as const;
}

function get(path: string, token: string) {
  return app.request(path, { headers: { authorization: `Bearer ${token}` } });
}

describe("AS item 29: pairwise instance handles", () => {
  it("two clients of one owner cannot match handles", async () => {
    const a = await grantFor(CLIENT_A);
    const b = await grantFor(CLIENT_B);
    expect(a.handle).toMatch(/^pwi_[A-Za-z0-9_-]{43}$/);
    expect(b.handle).toMatch(/^pwi_[A-Za-z0-9_-]{43}$/);
    expect(a.handle).not.toBe(b.handle);
    for (const h of [a.handle, b.handle]) expect(h).not.toContain(INSTANCE);

    // Each sees only its own handle on every served record.
    const listA = (await (
      await get("/v1/streams/media/records", a.token!)
    ).json()) as { data: Array<{ instance_id: string }> };
    const listB = (await (
      await get("/v1/streams/media/records", b.token!)
    ).json()) as { data: Array<{ instance_id: string }> };
    expect(new Set(listA.data.map((r) => r.instance_id))).toEqual(
      new Set([a.handle]),
    );
    expect(new Set(listB.data.map((r) => r.instance_id))).toEqual(
      new Set([b.handle]),
    );
    expect(JSON.stringify(listA)).not.toContain(INSTANCE);
    expect(JSON.stringify(listA)).not.toContain(b.handle!);
  });

  it("keeps one client's handle stable across grants and token refresh", async () => {
    const first = await grantFor(CLIENT_A);
    const second = await grantFor(CLIENT_A);
    expect(second.grant!.grant_id).not.toBe(first.grant!.grant_id);
    expect(second.handle).toBe(first.handle);
    const refreshed = (await (
      await app.request("/pdpp/v1/token", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token: first.refreshToken!,
        }),
      })
    ).json()) as { authorization_details: unknown };
    expect(JSON.stringify(refreshed.authorization_details)).toContain(
      first.handle!,
    );
    expect(JSON.stringify(refreshed.authorization_details)).not.toContain(
      INSTANCE,
    );
  });

  it("resolves the single-record instance_id through the client's own handle only", async () => {
    const a = await grantFor(CLIENT_A);
    const b = await grantFor(CLIENT_B);
    const own = await get(
      `/v1/streams/media/records/m2?instance_id=${encodeURIComponent(a.handle!)}`,
      a.token!,
    );
    expect(own.status).toBe(200);
    expect(((await own.json()) as { instance_id: string }).instance_id).toBe(
      a.handle,
    );
    for (const other of [b.handle!, INSTANCE]) {
      const res = await get(
        `/v1/streams/media/records/m2?instance_id=${encodeURIComponent(other)}`,
        a.token!,
      );
      expect(res.status).toBe(404);
    }
  });

  it("round-trips page cursors and changes_since tokens with the handle on every page", async () => {
    const a = await grantFor(CLIENT_A);
    const seen: string[] = [];
    let path = "/v1/streams/media/records?limit=1";
    for (let i = 0; i < 5; i++) {
      const page = (await (await get(path, a.token!)).json()) as {
        data: Array<{ id: string; instance_id: string }>;
        next_cursor?: string;
      };
      for (const r of page.data) {
        expect(r.instance_id).toBe(a.handle);
        seen.push(r.id);
      }
      if (!page.next_cursor) break;
      path = `/v1/streams/media/records?limit=1&cursor=${encodeURIComponent(page.next_cursor)}`;
    }
    expect(seen.sort()).toEqual(["m1", "m2", "m3"]);

    const sync = (await (
      await get("/v1/streams/media/records?changes_since=beginning", a.token!)
    ).json()) as {
      data: Array<{ instance_id: string }>;
      next_changes_since: string;
    };
    expect(sync.data.every((r) => r.instance_id === a.handle)).toBe(true);
    records.ingestBatch(
      [
        {
          instance: INSTANCE,
          stream: "media",
          key: "m4",
          data: { id: "m4", title: "t4" },
          emitted_at: "2026-04-09T00:00:00.000Z",
        },
      ],
      () => "append_only",
      () => ["id"],
    );
    const next = (await (
      await get(
        `/v1/streams/media/records?changes_since=${encodeURIComponent(sync.next_changes_since)}`,
        a.token!,
      )
    ).json()) as { data: Array<{ id: string; instance_id: string }> };
    expect(next.data.map((r) => [r.id, r.instance_id])).toEqual([
      ["m4", a.handle],
    ]);
    // A cursor sealed for one client's grant does not open for another's.
    const b = await grantFor(CLIENT_B);
    const crossed = await get(
      `/v1/streams/media/records?changes_since=${encodeURIComponent(sync.next_changes_since)}`,
      b.token!,
    );
    expect(crossed.status).toBe(400);
  });

  it("puts the handle in blob fetch_url and serves the blob only under the client's handle", async () => {
    const a = await grantFor(CLIENT_A);
    const b = await grantFor(CLIENT_B);
    const rec = (await (
      await get(
        `/v1/streams/media/records/m1?instance_id=${encodeURIComponent(a.handle!)}`,
        a.token!,
      )
    ).json()) as { data: { blob_ref: { fetch_url: string } } };
    const url = new URL(rec.data.blob_ref.fetch_url);
    expect(url.searchParams.get("instance_id")).toBe(a.handle);
    expect(
      (await get(`/v1/blobs/blob_1${url.search}`, a.token!)).status,
    ).toBe(200);
    for (const other of [b.handle!, INSTANCE]) {
      const res = await get(
        `/v1/blobs/blob_1?instance_id=${encodeURIComponent(other)}`,
        a.token!,
      );
      expect(res.status).toBe(404);
    }
  });

  it("returns the bindings only to the RS, and owner views keep stored ids", async () => {
    const a = await grantFor(CLIENT_A);
    const introspected = (await (
      await app.request("/pdpp/v1/introspect", {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          authorization: `Bearer ${ownerToken()}`,
        },
        body: new URLSearchParams({ token: a.token! }),
      })
    ).json()) as Record<string, unknown>;
    expect(introspected.pdpp_instance_bindings).toEqual([
      {
        source_id: SOURCE_ID,
        stream: "media",
        instance_id: a.handle,
        rs_instance: INSTANCE,
      },
    ]);
    expect(JSON.stringify(introspected.authorization_details)).toContain(
      a.handle!,
    );
    // The client's own token response never carries the bindings.
    expect(JSON.stringify(a.grant)).not.toContain("rs_instance");

    const owner = (await (
      await get("/pdpp/v1/grants", ownerToken())
    ).json()) as { grants: Array<{ streams: unknown }> };
    expect(JSON.stringify(owner.grants)).not.toContain("pwi_");
    // The owner's consent review shows the owner's own handle.
    expect(a.review!.data.streams[0].instance_ids).toEqual([INSTANCE]);
  });

  it("accepts a client's own handle in a later request and never another client's", async () => {
    const a = await grantFor(CLIENT_A);
    const b = await grantFor(CLIENT_B);
    const again = await grantFor(CLIENT_A, [a.handle!]);
    expect(again.status).toBe(200);
    expect(again.handle).toBe(a.handle);
    expect(again.review!.data.streams[0].instance_ids).toEqual([INSTANCE]);
    const foreign = await grantFor(CLIENT_A, [b.handle!]);
    expect(foreign.status).not.toBe(200);
  });

  it("records the assignment before the grant that discloses it (L1824)", async () => {
    await grantFor(CLIENT_A);
    const Database = (await import("better-sqlite3")).default;
    const db = new Database(join(dir, "auth.db"), { readonly: true });
    const kinds = (
      db.prepare("SELECT kind FROM pdpp_history_log ORDER BY seq").all() as Array<{
        kind: string;
      }>
    ).map((r) => r.kind);
    db.close();
    expect(kinds.indexOf("pairwise_instance_assigned")).toBeGreaterThanOrEqual(0);
    expect(kinds.indexOf("pairwise_instance_assigned")).toBeLessThan(
      kinds.indexOf("grant_issued"),
    );
  });
});

describe("design 2 chain gate on /v1/blobs (Vana-6.1)", () => {
  it("denies a client blob read the chain gate refuses, like a record read", async () => {
    const a = await grantFor(CLIENT_A);
    const path = `/v1/blobs/blob_1?instance_id=${encodeURIComponent(a.handle!)}`;
    expect((await get(path, a.token!)).status).toBe(200);

    chainDecision = { ok: false, retryable: false, reason: "entry removed" };
    const denied = await get(path, a.token!);
    expect(denied.status).toBe(401);
    expect(((await denied.json()) as { error: { code: string } }).error.code).toBe(
      "grant_revoked",
    );
    expect(
      (await get("/v1/streams/media/records", a.token!)).status,
    ).toBe(denied.status);

    chainDecision = { ok: false, retryable: true, reason: "gateway down" };
    const retry = await get(path, a.token!);
    expect(retry.status).toBe(500);
    expect(retry.headers.get("retry-after")).toBe("5");
  });
});
