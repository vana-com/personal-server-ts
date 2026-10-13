/**
 * Latest legacy reads of connector scopes come from the canonical rows.
 *
 * Every request goes through a real `createServer` app: real config, real
 * declaration files, the real SQLite record store, real P7 replaces, real
 * legacy files written through POST /v1/data, and the legacy read auth
 * (owner control-plane token, and a builder's Web3Signed legacy grant).
 *
 * The legacy file of a bound scope is never served as its latest body. A
 * canonical read that cannot be served is a typed refusal, not the file.
 */

import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type {
  Builder,
  GatewayClient,
  GatewayGrantResponse,
} from "@opendatalabs/vana-sdk/node";
import { recoverServerOwner } from "@opendatalabs/vana-sdk/node";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import {
  buildWeb3SignedHeader,
  createTestWallet,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import { createServer, type ServerContext } from "./bootstrap.js";
import { registerTestConnection } from "./pdpp/test-connections.js";

const KNOWN_SIG =
  "0xedbb7743cce459345238442dcfb291f234a321d253485eaa58251aa0f28ea8f1410ab988bae2657b689cd24417b41e315efc22ba333024f4a6269c424ded8d361b";
const CONTROL_PLANE_TOKEN = "canonical-read-journey-control-plane";
const OURA = "https://registry.pdpp.dev/sources/oura";
const SECOND_ACCOUNT = "conn_123e4567-e89b-42d3-a456-426614174000";
const GRANT_ID = "grant-legacy-oura";
const BUILDER_ID = "builder-legacy-oura";
const builder = createTestWallet(0);

const ACTIVITY_FIELDS = [
  "id",
  "day",
  "score",
  "active_calories",
  "total_calories",
  "steps",
  "equivalent_walking_distance",
  "high_activity_time",
  "medium_activity_time",
  "low_activity_time",
  "sedentary_time",
  "resting_time",
  "inactivity_alerts",
  "contributors",
];
const READINESS_FIELDS = [
  "id",
  "day",
  "score",
  "temperature_deviation",
  "temperature_trend_deviation",
  "contributors",
];
const OURA_DECLARATION = JSON.stringify({
  source_id: OURA,
  source_kind: "connector",
  version: "1",
  streams: [
    {
      name: "activity",
      fields: ACTIVITY_FIELDS,
      required_fields: ["id"],
      primary_key: ["id"],
    },
    {
      name: "readiness",
      fields: READINESS_FIELDS,
      required_fields: ["id"],
      primary_key: ["id"],
    },
  ],
});

let tempDir: string;
let ctx: ServerContext | undefined;
let owner: string;
let accountOne: string;

function grant(): GatewayGrantResponse {
  return {
    id: GRANT_ID,
    grantorAddress: owner,
    granteeId: BUILDER_ID,
    scopes: ["oura.*"],
    status: "confirmed",
    addedAt: "2026-01-21T10:00:00.000Z",
    expiresAt: null,
    expired: false,
    revokedAt: null,
    revocationSignature: null,
    paymentStatus: "paid",
    paidAt: null,
    paidBy: null,
    grantVersion: "1",
    settleTxHash: null,
    settleSubmittedAt: null,
    revocationTxHash: null,
    fee: {
      asset: "0x0000000000000000000000000000000000000000",
      registrationFee: "0",
      dataAccessFee: "0",
      totalDue: "0",
    },
  };
}

async function boot(methodId = "oura") {
  const dir = join(tempDir, "declarations");
  await mkdir(dir, { recursive: true });
  const path = join(dir, "oura.json");
  await writeFile(path, OURA_DECLARATION, "utf-8");
  const gateway = {
    getBuilder: vi.fn().mockResolvedValue({
      id: BUILDER_ID,
      ownerAddress: owner,
      granteeAddress: builder.address,
      publicKey: "0x04key",
      appUrl: "https://app.example.com",
      addedAt: "2026-01-21T10:00:00.000Z",
    } satisfies Builder),
    getGrant: vi.fn().mockResolvedValue(grant()),
  } as unknown as GatewayClient;
  return createServer(
    ServerConfigSchema.parse({
      tunnel: { enabled: false },
      pdpp: {
        enabled: true,
        declarationPaths: [path],
        methods: [{ method_id: methodId, declaration_path: path }],
      },
    }),
    {
      serverDir: tempDir,
      dataDir: join(tempDir, "data"),
      gatewayClient: gateway,
    },
  );
}

async function ownerPdppToken(instanceId?: string): Promise<string> {
  if (!instanceId) {
    return registerTestConnection(ctx!.app, ctx!.devToken, owner, OURA);
  }
  const response = await ctx!.app.request("/pdpp/v1/owner/token", {
    method: "POST",
    headers: {
      authorization: `Bearer ${ctx!.devToken}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ source_id: OURA, instance_id: instanceId }),
  });
  expect(response.status).toBe(200);
  return ((await response.json()) as { access_token: string }).access_token;
}

async function registerSecondAccount(token: string) {
  const response = await ctx!.app.request(
    `/pdpp/connections/${SECOND_ACCOUNT}`,
    {
      method: "PUT",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        source_id: OURA,
        method_id: "oura",
        label: "Second ring",
      }),
    },
  );
  expect(response.status).toBe(200);
}

/** P7 full replace of one stream, with the producer's collection time. */
async function replace(
  token: string,
  stream: string,
  rows: Record<string, unknown>[],
  sourceCollectedAt: string | undefined,
  instance = accountOne,
) {
  const response = await ctx!.app.request(
    `/v1/streams/${stream}/records/replace?method=oura&binding_generation=1`,
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        instance,
        emitted_at: "2026-09-10T12:00:00Z",
        ...(sourceCollectedAt
          ? { source_collected_at: sourceCollectedAt }
          : {}),
        records: rows.map((data) => ({
          key: String(data.id),
          data,
          emitted_at: "2026-09-10T07:00:00Z",
        })),
      }),
    },
  );
  expect(response.status).toBe(200);
}

/** A legacy file written the way older collectors write one. */
async function legacyWrite(scope: string, data: Record<string, unknown>) {
  const response = await ctx!.app.request(`/v1/data/${scope}`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${ctx!.devToken}`,
      "content-type": "application/json",
    },
    body: JSON.stringify(data),
  });
  expect(response.status).toBe(201);
}

async function ownerGet(path: string) {
  const response = await ctx!.app.request(path, {
    headers: { authorization: `Bearer ${CONTROL_PLANE_TOKEN}` },
  });
  return {
    status: response.status,
    etag: response.headers.get("etag"),
    text: await response.text(),
  };
}

async function builderGet(scope: string) {
  const response = await ctx!.app.request(`/v1/data/${scope}`, {
    headers: {
      authorization: await buildWeb3SignedHeader({
        wallet: builder,
        aud: ctx!.config.server.origin,
        method: "GET",
        uri: `/v1/data/${scope}`,
        grantId: GRANT_ID,
      }),
    },
  });
  return { status: response.status, text: await response.text() };
}

const day = (id: string, date: string, score = 80) => ({
  id,
  day: date,
  score,
  steps: 1000,
  contributors: {},
});

const STALE = { days: [{ id: "stale-legacy", day: "2026-01-01", score: 1 }] };

function ids(text: string): string[] {
  const body = JSON.parse(text) as { data: { days: { id: string }[] } };
  return body.data.days.map((entry) => entry.id);
}

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), "pdpp-canonical-read-"));
  vi.stubEnv("VANA_MASTER_KEY_SIGNATURE", KNOWN_SIG);
  vi.stubEnv("PS_ACCESS_TOKEN", CONTROL_PLANE_TOKEN);
  owner = (await recoverServerOwner(KNOWN_SIG)).toLowerCase();
  accountOne = `oura:${owner}`;
  ctx = await boot();
});

afterEach(async () => {
  await ctx?.cleanup();
  ctx = undefined;
  await rm(tempDir, { recursive: true, force: true });
  vi.unstubAllEnvs();
});

describe("GET /v1/data/:scope for a bound connector scope", () => {
  it("serves the canonical rows, not a stale legacy file, to a legacy grant and to the owner", async () => {
    await legacyWrite("oura.activity", STALE);
    const token = await ownerPdppToken();
    await replace(
      token,
      "activity",
      [day("a2", "2026-09-02"), day("a1", "2026-09-01")],
      "2026-09-10T06:00:00Z",
    );

    const asBuilder = await builderGet("oura.activity");
    expect(asBuilder.status).toBe(200);
    expect(ids(asBuilder.text)).toEqual(["a1", "a2"]);
    expect(asBuilder.text).not.toContain("stale-legacy");

    const asOwner = await ownerGet("/v1/data/oura.activity");
    expect(asOwner.status).toBe(200);
    expect(JSON.parse(asOwner.text)).toEqual({
      version: "1.0",
      scope: "oura.activity",
      collectedAt: "2026-09-10T06:00:00.000Z",
      data: {
        days: [
          {
            id: "a1",
            day: "2026-09-01",
            score: 80,
            steps: 1000,
            contributors: {},
          },
          {
            id: "a2",
            day: "2026-09-02",
            score: 80,
            steps: 1000,
            contributors: {},
          },
        ],
      },
    });
    expect(asOwner.etag).toMatch(/^"v1:[0-9a-f]{64}"$/);
  });

  it("reflects a later repair and keeps the revision stable while nothing changes", async () => {
    await legacyWrite("oura.activity", STALE);
    const token = await ownerPdppToken();
    await replace(
      token,
      "activity",
      [day("a1", "2026-09-01", 10)],
      "2026-09-10T06:00:00Z",
    );
    const first = await ownerGet("/v1/data/oura.activity");
    const again = await ownerGet("/v1/data/oura.activity");
    expect(again.etag).toBe(first.etag);
    expect(again.text).toBe(first.text);

    await replace(
      token,
      "activity",
      [day("a1", "2026-09-01", 90), day("a3", "2026-09-03")],
      "2026-09-11T06:00:00Z",
    );
    const repaired = await ownerGet("/v1/data/oura.activity");
    expect(repaired.status).toBe(200);
    expect(repaired.etag).not.toBe(first.etag);
    const body = JSON.parse(repaired.text) as {
      collectedAt: string;
      data: { days: { id: string; score: number }[] };
    };
    expect(body.collectedAt).toBe("2026-09-11T06:00:00.000Z");
    expect(body.data.days.map((d) => [d.id, d.score])).toEqual([
      ["a1", 90],
      ["a3", 80],
    ]);
  });

  it("serves a known-empty stream as empty and refuses an uncollected one even when its legacy file exists", async () => {
    await legacyWrite("oura.activity", STALE);
    await legacyWrite("oura.readiness", {
      readiness: [{ id: "stale-legacy", day: "2026-01-01", score: 1 }],
    });
    const token = await ownerPdppToken();
    await replace(token, "activity", [], "2026-09-10T06:00:00Z");

    const empty = await ownerGet("/v1/data/oura.activity");
    expect(empty.status).toBe(200);
    expect(JSON.parse(empty.text)).toMatchObject({
      collectedAt: "2026-09-10T06:00:00.000Z",
      data: { days: [] },
    });

    // Nothing live anywhere on the connection yet.
    const nothingSynced = await ownerGet("/v1/data/oura.readiness");
    expect(nothingSynced.status).toBe(503);
    expect(JSON.parse(nothingSynced.text)).toMatchObject({
      error: "CANONICAL_VIEW_UNAVAILABLE",
      reason: "no_synced_data",
    });
    expect(nothingSynced.text).not.toContain("stale-legacy");

    // A sibling stream's rows are not evidence that readiness is empty.
    await replace(
      token,
      "activity",
      [day("a1", "2026-09-01")],
      "2026-09-11T06:00:00Z",
    );
    const uncollected = await ownerGet("/v1/data/oura.readiness");
    expect(uncollected.status).toBe(503);
    expect(JSON.parse(uncollected.text)).toMatchObject({
      error: "CANONICAL_VIEW_UNAVAILABLE",
      reason: "stream_completion_unknown",
      streams: ["readiness"],
    });
    expect(uncollected.text).not.toContain("stale-legacy");
  });

  it("refuses two accounts with no trusted choice and leaks neither", async () => {
    await legacyWrite("oura.activity", STALE);
    const token = await ownerPdppToken();
    await replace(
      token,
      "activity",
      [day("one", "2026-09-01")],
      "2026-09-10T06:00:00Z",
    );
    await registerSecondAccount(token);
    const second = await ownerPdppToken(SECOND_ACCOUNT);
    await replace(
      second,
      "activity",
      [day("two", "2026-09-02")],
      "2026-09-10T06:00:00Z",
      SECOND_ACCOUNT,
    );

    for (const read of [
      await ownerGet("/v1/data/oura.activity"),
      await builderGet("oura.activity"),
    ]) {
      expect(read.status).toBe(409);
      expect(JSON.parse(read.text)).toMatchObject({
        error: "CANONICAL_VIEW_UNAVAILABLE",
        reason: "ambiguous_connection",
      });
      for (const leaked of ["stale-legacy", '"one"', '"two"', SECOND_ACCOUNT]) {
        expect(read.text).not.toContain(leaked);
      }
    }
    // A query parameter cannot pick an account.
    const picked = await ownerGet(
      `/v1/data/oura.activity?connection_id=${SECOND_ACCOUNT}&instance=${SECOND_ACCOUNT}`,
    );
    expect(picked.status).toBe(409);
  });

  it("does not let the legacy file mask a deleted connection", async () => {
    await legacyWrite("oura.activity", STALE);
    const token = await ownerPdppToken();
    await replace(
      token,
      "activity",
      [day("a1", "2026-09-01")],
      "2026-09-10T06:00:00Z",
    );
    const deleted = await ctx!.app.request(
      `/pdpp/connections/${encodeURIComponent(accountOne)}`,
      { method: "DELETE", headers: { authorization: `Bearer ${token}` } },
    );
    expect(deleted.status).toBe(200);

    const read = await ownerGet("/v1/data/oura.activity");
    expect(read.status).toBe(503);
    expect(JSON.parse(read.text)).toMatchObject({
      error: "CANONICAL_VIEW_UNAVAILABLE",
      reason: "no_connection",
    });
    expect(read.text).not.toContain("stale-legacy");
  });

  it("refuses when the connection's method is not configured on this boot", async () => {
    await legacyWrite("oura.activity", STALE);
    const token = await ownerPdppToken();
    await replace(
      token,
      "activity",
      [day("a1", "2026-09-01")],
      "2026-09-10T06:00:00Z",
    );
    await ctx!.cleanup();
    ctx = await boot("oura-v2");

    const read = await ownerGet("/v1/data/oura.activity");
    expect(read.status).toBe(503);
    expect(JSON.parse(read.text)).toMatchObject({
      error: "CANONICAL_VIEW_UNAVAILABLE",
      reason: "connection_unavailable",
      detail: "method_mismatch",
    });
    expect(read.text).not.toContain("stale-legacy");
  });

  it("refuses an unbound scope in a bound connector namespace instead of serving its file", async () => {
    await legacyWrite("oura.personal_info", { email: "stale@example.com" });
    const token = await ownerPdppToken();
    await replace(
      token,
      "activity",
      [day("a1", "2026-09-01")],
      "2026-09-10T06:00:00Z",
    );
    const read = await ownerGet("/v1/data/oura.personal_info");
    expect(read.status).toBe(503);
    expect(JSON.parse(read.text)).toMatchObject({
      error: "CANONICAL_VIEW_UNAVAILABLE",
      reason: "unbound_scope",
    });
    expect(read.text).not.toContain("stale@example.com");
  });

  it("refuses a body the projector could only deliver with rows left out", async () => {
    await legacyWrite("oura.activity", STALE);
    const token = await ownerPdppToken();
    await replace(
      token,
      "activity",
      [day("a1", "2026-09-01"), day("a2", "not-a-day")],
      "2026-09-10T06:00:00Z",
    );
    const read = await builderGet("oura.activity");
    expect(read.status).toBe(503);
    expect(JSON.parse(read.text)).toMatchObject({
      error: "CANONICAL_VIEW_UNAVAILABLE",
      status: "incomplete",
      reason: "canonical_view_incomplete",
    });
    expect(read.text).not.toContain("stale-legacy");
    expect(read.text).not.toContain('"a1"');
  });

  it("returns every row of a body larger than one store page", async () => {
    const token = await ownerPdppToken();
    const rows = Array.from({ length: 1203 }, (_, i) =>
      day(`d${String(i).padStart(5, "0")}`, "2026-09-01", i % 100),
    );
    await replace(token, "activity", rows, "2026-09-10T06:00:00Z");
    const read = await ownerGet("/v1/data/oura.activity");
    expect(read.status).toBe(200);
    expect(ids(read.text)).toEqual(rows.map((row) => row.id));
  });
});

describe("paths the canonical view leaves to existing storage", () => {
  it("keeps serving the legacy file while the source holds no canonical data", async () => {
    // Boot registered account one; nothing was ever collected into it.
    await legacyWrite("oura.activity", STALE);
    const read = await ownerGet("/v1/data/oura.activity");
    expect(read.status).toBe(200);
    expect(ids(read.text)).toEqual(["stale-legacy"]);
  });

  it("serves an explicitly requested historical version and manual scopes from storage", async () => {
    await legacyWrite("oura.activity", STALE);
    await legacyWrite("notes.manual", { text: "kept" });
    const token = await ownerPdppToken();
    await replace(
      token,
      "activity",
      [day("a1", "2026-09-01")],
      "2026-09-10T06:00:00Z",
    );

    const versions = await ownerGet("/v1/data/oura.activity/versions");
    expect(versions.status).toBe(200);
    const listed = JSON.parse(versions.text) as {
      versions: { collectedAt: string }[];
    };
    expect(listed.versions).toHaveLength(1);
    const at = listed.versions[0]!.collectedAt;
    const historical = await ownerGet(
      `/v1/data/oura.activity?at=${encodeURIComponent(at)}`,
    );
    expect(historical.status).toBe(200);
    expect(ids(historical.text)).toEqual(["stale-legacy"]);

    const manual = await ownerGet("/v1/data/notes.manual");
    expect(manual.status).toBe(200);
    expect(JSON.parse(manual.text)).toMatchObject({ data: { text: "kept" } });

    const latest = await ownerGet("/v1/data/oura.activity");
    expect(ids(latest.text)).toEqual(["a1"]);
  });
});

describe("GET /v1/data listing", () => {
  it("lists a bound scope with canonical freshness, never the legacy head's", async () => {
    await legacyWrite("oura.activity", STALE);
    await legacyWrite("notes.manual", { text: "kept" });
    const token = await ownerPdppToken();
    await replace(
      token,
      "activity",
      [day("a1", "2026-09-01")],
      "2026-09-10T06:00:00Z",
    );
    const listing = await ownerGet("/v1/data");
    expect(listing.status).toBe(200);
    const body = JSON.parse(listing.text) as {
      scopes: {
        scope: string;
        latestCollectedAt: string;
        sizeBytes?: number;
        dataStatus?: string;
      }[];
      total: number;
    };
    const activity = body.scopes.find((s) => s.scope === "oura.activity");
    expect(activity).toMatchObject({
      latestCollectedAt: "2026-09-10T06:00:00.000Z",
    });
    expect(activity?.sizeBytes).toBeUndefined();
    expect(activity?.dataStatus).toBeUndefined();
    expect(body.scopes.map((s) => s.scope).sort()).toEqual([
      "notes.manual",
      "oura.activity",
    ]);
    expect(body.total).toBe(2);
  });

  it("does not list a bound scope whose latest read would be refused", async () => {
    await legacyWrite("oura.activity", STALE);
    await legacyWrite("oura.readiness", { readiness: [] });
    const token = await ownerPdppToken();
    await replace(
      token,
      "activity",
      [day("a1", "2026-09-01")],
      "2026-09-10T06:00:00Z",
    );
    const listing = await ownerGet("/v1/data");
    const body = JSON.parse(listing.text) as {
      scopes: { scope: string }[];
      total: number;
    };
    expect(body.scopes.map((s) => s.scope)).toEqual(["oura.activity"]);
    expect(body.total).toBe(1);
  });
});
