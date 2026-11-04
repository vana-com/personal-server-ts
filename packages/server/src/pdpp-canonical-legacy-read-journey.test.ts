/**
 * Latest legacy reads of connector scopes come from the canonical rows.
 *
 * Every request goes through a real `createServer` app: real config, real
 * declaration files, the real SQLite record store, real P7 replaces, real
 * legacy files written through POST /v1/data, and the legacy read auth
 * (owner control-plane token, and a builder's Web3Signed legacy grant).
 *
 * A stored legacy head remains latest until a fresh complete import replaces
 * it wholesale or its canonical projection covers it. A regression against a covered head refuses; a newer legacy head is
 * checked again and may explicitly return to the file.
 */

import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { pathToFileURL } from "node:url";
import { tmpdir } from "node:os";
import Database from "better-sqlite3";
import type {
  Builder,
  GatewayClient,
  GatewayGrantResponse,
} from "@opendatalabs/vana-sdk/node";
import { recoverServerOwner } from "@opendatalabs/vana-sdk/node";
import {
  escrowPaymentDomain,
  GENERIC_PAYMENT_TYPES,
} from "@opendatalabs/vana-sdk/browser";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  encodePaymentHeader,
  nextPaymentNonce,
} from "@opendatalabs/personal-server-ts-core/payment";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import {
  buildWeb3SignedHeader,
  createTestWallet,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import {
  createServer,
  type CreateServerOptions,
  type ServerContext,
} from "./bootstrap.js";
import { registerTestConnection } from "./pdpp/test-connections.js";

import * as deletedScopePolicy from "@opendatalabs/personal-server-ts-core/sync/deleted-scope-policy";

const KNOWN_SIG =
  "0xedbb7743cce459345238442dcfb291f234a321d253485eaa58251aa0f28ea8f1410ab988bae2657b689cd24417b41e315efc22ba333024f4a6269c424ded8d361b";
const CONTROL_PLANE_TOKEN = "canonical-read-journey-control-plane";
const OURA = "https://registry.pdpp.dev/sources/oura";
const SECOND_ACCOUNT = "conn_123e4567-e89b-42d3-a456-426614174000";
// X402 pays against the grant id as an opId, so it must be bytes32.
const GRANT_ID = `0x${"11".repeat(32)}`;
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
    revocationSubmittedAt: null,
    fee: {
      asset: "0x0000000000000000000000000000000000000000",
      registrationFee: "0",
      dataAccessFee: "0",
      totalDue: "0",
    },
  };
}

interface BootOptions {
  declaration?: string;
  payment?: boolean;
  dataPointFeed?: CreateServerOptions["dataPointFeed"];
  pdppEnabled?: boolean;
  syncEnabled?: boolean;
}

async function boot(
  methodId = "oura",
  {
    declaration = OURA_DECLARATION,
    payment = false,
    dataPointFeed,
    pdppEnabled = true,
    syncEnabled = false,
  }: BootOptions = {},
) {
  const dir = join(tempDir, "declarations");
  await mkdir(dir, { recursive: true });
  const path = join(dir, "declaration.json");
  await writeFile(path, declaration, "utf-8");
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
    getServer: vi.fn().mockResolvedValue(null),
  } as unknown as GatewayClient;
  return createServer(
    ServerConfigSchema.parse({
      tunnel: { enabled: false },
      sync: { enabled: syncEnabled },
      payment: { enabled: payment },
      pdpp: {
        enabled: pdppEnabled,
        declarationPaths: [path],
        methods: [{ method_id: methodId, declaration_path: path }],
      },
    }),
    {
      serverDir: tempDir,
      dataDir: join(tempDir, "data"),
      gatewayClient: gateway,
      ...(dataPointFeed ? { dataPointFeed } : {}),
    },
  );
}

async function ownerPdppToken(instanceId?: string): Promise<string> {
  if (!instanceId) {
    return registerTestConnection(ctx!.app, ctx!.devToken!, owner, OURA);
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
  generation = 1,
) {
  const response = await ctx!.app.request(
    `/v1/streams/${stream}/records/replace?method=oura&binding_generation=${generation}`,
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
  expect(response.status, await response.clone().text()).toBe(200);
}

async function upsert(token: string, data: Record<string, unknown>) {
  const response = await ctx!.app.request(
    "/v1/streams/activity/records/ingest?method=oura&binding_generation=1",
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        instance: accountOne,
        key: String(data.id),
        data,
        emitted_at: "2026-09-10T07:00:00Z",
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
    dataSource: response.headers.get("X-Vana-Data-Source"),
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
const COVERED_A1 = { days: [day("a1", "2026-09-01")] };

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

function expectCompletedReplacement(scope: string): void {
  const db = new Database(join(tempDir, "index.db"), {
    readonly: true,
    fileMustExist: true,
  });
  try {
    const head = ctx!.indexManager.findLatestByScope(scope)!;
    const row = db
      .prepare(
        "SELECT replacement_cursor FROM legacy_scope_takeovers WHERE scope = ? AND superseded_path = ?",
      )
      .get(scope, head.path) as { replacement_cursor: string } | undefined;
    expect(row?.replacement_cursor).toEqual(expect.any(String));
    expect(row!.replacement_cursor.length).toBeGreaterThan(0);
  } finally {
    db.close();
  }
}

describe("GET /v1/data/:scope for a bound connector scope", () => {
  it("accepts mutable value drift from a newer canonical collection", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      vi.setSystemTime(new Date("2026-03-01T00:00:00Z"));
      await legacyWrite("oura.activity", {
        days: [day("a1", "2026-09-01", 80)],
      });
      vi.setSystemTime(new Date("2026-10-14T00:00:00Z"));
      const token = await ownerPdppToken();
      await replace(
        token,
        "activity",
        [day("a1", "2026-09-01", 95)],
        "2026-09-10T06:00:00Z",
      );
      const read = await ownerGet("/v1/data/oura.activity");
      expect(read.dataSource).toBe("canonical");
      expect(JSON.parse(read.text).data.days[0].score).toBe(95);
      expect(
        JSON.parse((await ownerGet("/v1/data/oura.activity/takeover")).text)
          .verdicts,
      ).toEqual([]);
      expectCompletedReplacement("oura.activity");
    } finally {
      vi.useRealTimers();
    }
  });

  it("accepts a missing legacy entity only with a newer completion proof", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      vi.setSystemTime(new Date("2026-03-01T00:00:00Z"));
      await legacyWrite("oura.activity", {
        days: [day("deleted", "2026-02-01")],
      });
      vi.setSystemTime(new Date("2026-10-14T00:00:00Z"));
      const token = await ownerPdppToken();
      await upsert(token, day("a1", "2026-09-01"));
      expect((await ownerGet("/v1/data/oura.activity")).dataSource).toBe(
        "legacy",
      );
      const historicalVerdicts = JSON.parse(
        (await ownerGet("/v1/data/oura.activity/takeover")).text,
      ).verdicts;
      await replace(
        token,
        "activity",
        [day("a1", "2026-09-01")],
        "2026-09-10T06:00:00Z",
      );
      const read = await ownerGet("/v1/data/oura.activity");
      expect(read.dataSource).toBe("canonical");
      expect(ids(read.text)).toEqual(["a1"]);
      expect(
        JSON.parse((await ownerGet("/v1/data/oura.activity/takeover")).text)
          .verdicts,
      ).toEqual(historicalVerdicts);
      expectCompletedReplacement("oura.activity");
    } finally {
      vi.useRealTimers();
    }
  });

  it("switches an unproven upsert to canonical when it covers the latest legacy body", async () => {
    await legacyWrite("oura.activity", { days: [day("a1", "2026-09-01")] });
    const token = await ownerPdppToken();
    await upsert(token, day("a1", "2026-09-01"));
    const read = await ownerGet("/v1/data/oura.activity");
    expect(read.status).toBe(200);
    expect(read.dataSource).toBe("canonical");
    expect(ids(read.text)).toEqual(["a1"]);
  });

  it("rechecks a newer legacy version and records either continued coverage or file fallback", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      vi.setSystemTime(new Date("2026-10-14T22:00:00Z"));
      await legacyWrite("oura.activity", { days: [day("a1", "2026-09-01")] });
      const token = await ownerPdppToken();
      await replace(
        token,
        "activity",
        [day("a1", "2026-09-01"), day("a2", "2026-09-02")],
        "2026-09-10T06:00:00Z",
      );
      expect((await ownerGet("/v1/data/oura.activity")).dataSource).toBe(
        "canonical",
      );

      vi.setSystemTime(new Date("2026-10-14T22:00:01Z"));
      await legacyWrite("oura.activity", { days: [day("a1", "2026-09-01")] });
      expect((await ownerGet("/v1/data/oura.activity")).dataSource).toBe(
        "canonical",
      );

      vi.setSystemTime(new Date("2026-10-14T22:00:02Z"));
      await legacyWrite("oura.activity", {
        days: [day("a1", "2026-09-01"), day("missing", "2026-09-03")],
      });
      const fallback = await ownerGet("/v1/data/oura.activity");
      expect(fallback.dataSource).toBe("legacy");
      expect(ids(fallback.text)).toEqual(["a1", "missing"]);
      const verdict = await ownerGet("/v1/data/oura.activity/takeover");
      expect(verdict.status).toBe(200);
      expect(JSON.parse(verdict.text).verdicts).toMatchObject([
        {
          verdict: "not_covered",
          reason: { reason: "missing_entity", missingEntityCount: 1 },
        },
      ]);
    } finally {
      vi.useRealTimers();
    }
  }, 20000);

  it("lets the owner reset takeover without deleting canonical rows", async () => {
    await legacyWrite("oura.activity", { days: [day("a1", "2026-09-01")] });
    const token = await ownerPdppToken();
    await replace(
      token,
      "activity",
      [day("a1", "2026-09-01")],
      "2026-09-10T06:00:00Z",
    );
    expect((await ownerGet("/v1/data/oura.activity")).dataSource).toBe(
      "canonical",
    );
    const reset = await ctx!.app.request("/v1/data/oura.activity/takeover", {
      method: "DELETE",
      headers: { authorization: `Bearer ${CONTROL_PLANE_TOKEN}` },
    });
    expect(reset.status).toBe(200);
    expect((await ownerGet("/v1/data/oura.activity")).dataSource).toBe(
      "legacy",
    );
    expect(
      JSON.parse((await ownerGet("/v1/data/oura.activity/takeover")).text),
    ).toMatchObject({ reset: true, verdicts: [] });
    const records = await ctx!.app.request("/v1/streams/activity/records", {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(records.status).toBe(200);
    expect(await records.text()).toContain("a1");
  });

  it("keeps a mismatched legacy field and exposes only its path in the verdict", async () => {
    await legacyWrite("oura.activity", {
      days: [day("private-a1", "2026-09-01", 81)],
    });
    const token = await ownerPdppToken();
    await replace(
      token,
      "activity",
      [day("private-a1", "2026-09-01", 80)],
      "2026-09-10T06:00:00Z",
    );
    expect((await ownerGet("/v1/data/oura.activity")).dataSource).toBe(
      "legacy",
    );
    const diagnostics = (await ownerGet("/v1/data/oura.activity/takeover"))
      .text;
    expect(JSON.parse(diagnostics).verdicts).toMatchObject([
      {
        verdict: "not_covered",
        reason: {
          reason: "field_mismatch",
          mismatchedFieldPaths: ["$.days[0].score"],
        },
      },
    ]);
    expect(diagnostics).not.toContain("private-a1");
  });

  it("keeps existing rows on an unproven upsert and deletes only on proven replace", async () => {
    await legacyWrite("oura.activity", { days: [day("a1", "2026-09-01")] });
    const token = await ownerPdppToken();
    await replace(
      token,
      "activity",
      [day("a1", "2026-09-01")],
      "2026-09-10T06:00:00Z",
    );
    expect((await ownerGet("/v1/data/oura.activity")).dataSource).toBe(
      "canonical",
    );
    await upsert(token, day("a2", "2026-09-02"));
    const afterUpsert = await ownerGet("/v1/data/oura.activity");
    expect(afterUpsert.dataSource).toBe("canonical");
    expect(ids(afterUpsert.text)).toEqual(["a1", "a2"]);

    await replace(
      token,
      "activity",
      [day("a2", "2026-09-02")],
      "2026-09-11T06:00:00Z",
    );
    const native = await ctx!.app.request("/v1/streams/activity/records", {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(native.status).toBe(200);
    const nativeText = await native.text();
    expect(nativeText).toContain("a2");
    expect(nativeText).not.toContain('"a1"');
    const read = await ownerGet("/v1/data/oura.activity");
    expect(read.status).toBe(503);
    expect(read.text).not.toContain("stale-legacy");
  });
  it.each(["writer lock", "persistent insert trigger"])(
    "retains a failed deletion observation through offline reads and file re-add (%s)",
    async (failureMode) => {
      let remote: "deleted" | "offline" | "live" = "deleted";
      const getDataPoint = vi.fn(
        async ({
          ownerAddress,
          scope,
        }: {
          ownerAddress: string;
          scope: string;
        }) => {
          if (remote === "offline") throw new Error("gateway offline");
          return {
            id: "synthetic-point",
            ownerAddress,
            scope,
            dataHash: `0x${(remote === "deleted" ? "00" : "11").repeat(32)}`,
            metadataHash: `0x${(remote === "deleted" ? "00" : "11").repeat(32)}`,
            expectedVersion: remote === "deleted" ? "1" : "2",
            addedAt: "2026-09-01T00:00:00Z",
            deletedAt: remote === "deleted" ? "2026-09-11T00:00:00Z" : null,
          };
        },
      );
      await ctx!.cleanup();
      ctx = await boot("oura", {
        dataPointFeed: {
          getDataPoint,
          listDataPointsByOwner: async () => ({ dataPoints: [], cursor: null }),
        },
      });
      const token = await ownerPdppToken();
      await replace(
        token,
        "activity",
        [day("before-deletion", "2026-09-10")],
        "2026-09-10T06:00:00Z",
      );
      const nativeRows = async () => {
        const response = await ctx!.app.request(
          "/v1/streams/activity/records",
          {
            headers: { authorization: `Bearer ${token}` },
          },
        );
        expect(response.status).toBe(200);
        return response.json();
      };
      const before = await nativeRows();
      const blocker = new Database(join(tempDir, "index.db"));
      vi.useFakeTimers({ toFake: ["Date"] });
      try {
        if (failureMode === "writer lock") blocker.exec("BEGIN IMMEDIATE");
        else
          blocker.exec(
            `CREATE TRIGGER fail_history BEFORE INSERT ON vana_scope_deletion_history BEGIN SELECT RAISE(ABORT, 'synthetic metadata failure'); END;`,
          );
        const first = await ownerGet("/v1/data/oura.activity");
        expect(first.status).toBe(500);
        expect(first.text).not.toContain("before-deletion");
        expect(getDataPoint).toHaveBeenCalledTimes(1);
        if (blocker.inTransaction) blocker.exec("ROLLBACK");
        remote = "offline";
        const assertRefused = async () => {
          const ownerRead = await ownerGet("/v1/data/oura.activity");
          const builderRead = await builderGet("oura.activity");
          expect(ownerRead.status).toBe(410);
          expect(builderRead.status).toBe(410);
          expect(ownerRead.text).not.toContain("before-deletion");
          expect(builderRead.text).not.toContain("before-deletion");
          const listing = await ownerGet("/v1/data");
          expect(listing.status).toBe(200);
          expect(JSON.parse(listing.text)).toMatchObject({
            scopes: [],
            total: 0,
          });
        };
        await assertRefused();
        await legacyWrite("oura.activity", {
          days: [day("readded-file", "2026-09-15")],
        });
        const entry = ctx!.indexManager.findLatestByScope("oura.activity")!;
        expect(entry.afterTombstoneVersion).toBe(1);
        const historyPath = `/v1/data/oura.activity?at=${encodeURIComponent(entry.collectedAt)}`;
        const historical = await ownerGet(historyPath);
        expect(historical.status).toBe(200);
        expect(ids(historical.text)).toEqual(["readded-file"]);
        await assertRefused();

        remote = "live";
        vi.setSystemTime(Date.now() + 120_001);
        await assertRefused();
        expect(getDataPoint).toHaveBeenCalledTimes(2);
        expect((await ownerGet(historyPath)).status).toBe(200);
        expect(await nativeRows()).toEqual(before);
        // The trigger variant remains unavailable throughout. Refusal is
        // still authoritative even though no history write has succeeded.
        expect(
          blocker
            .prepare("SELECT count(*) AS n FROM vana_scope_deletion_history")
            .get(),
        ).toEqual({ n: 0 });
      } finally {
        vi.useRealTimers();
        if (blocker.inTransaction) blocker.exec("ROLLBACK");
        blocker.close();
      }
    },
    15_000,
  );

  it.each(["1", "0", "9007199254740992"])(
    "does not let a file-only re-add resurrect deleted canonical data or discovery (tombstone %s)",
    async (tombstoneVersion) => {
      vi.stubEnv("PS_SCOPE_DELETION_MIGRATION_DRY_RUN", "true");
      let deleted = false;
      let registeredFile = false;
      let offline = false;
      const dataPointFeed: NonNullable<CreateServerOptions["dataPointFeed"]> = {
        listDataPointsByOwner: async () => ({ dataPoints: [], cursor: null }),
        getDataPoint: async ({ ownerAddress, scope }) => {
          if (offline) throw new Error("gateway offline");
          return deleted
            ? {
                id: "synthetic-point",
                ownerAddress,
                scope,
                dataHash: `0x${(registeredFile ? "11" : "00").repeat(32)}`,
                metadataHash: `0x${(registeredFile ? "11" : "00").repeat(32)}`,
                expectedVersion: registeredFile
                  ? tombstoneVersion === "9007199254740992"
                    ? "9007199254740993"
                    : "2"
                  : tombstoneVersion,
                addedAt: "2026-09-01T00:00:00Z",
                deletedAt: registeredFile ? null : "2026-09-11T00:00:00Z",
              }
            : null;
        },
      };
      await ctx!.cleanup();
      ctx = await boot("oura", { dataPointFeed });
      let token = await ownerPdppToken();
      await replace(
        token,
        "activity",
        [day("before-deletion", "2026-09-10")],
        "2026-09-10T06:00:00Z",
      );
      const nativeRows = async () => {
        const response = await ctx!.app.request(
          "/v1/streams/activity/records",
          {
            headers: { authorization: `Bearer ${token}` },
          },
        );
        expect(response.status).toBe(200);
        return response.json();
      };
      const before = await nativeRows();
      // Simulate pre-upgrade history newer than this stale gateway observation.
      // An equal known version now intentionally retries erasure (covered separately).
      // This journey retains its old-history and file-only re-add assertions.
      const historyDb = new Database(join(tempDir, "index.db"));
      try {
        historyDb
          .prepare(
            `INSERT INTO vana_scope_deletion_history (owner_address, scope, deleted_at, tombstone_version) VALUES (?, ?, ?, ?)`,
          )
          .run(
            owner,
            "oura.activity",
            "2026-09-11T00:00:00Z",
            tombstoneVersion === "0"
              ? "0"
              : String(BigInt(tombstoneVersion) + 1n),
          );
      } finally {
        historyDb.close();
      }
      deleted = true;
      expect((await ownerGet("/v1/data/oura.activity")).status).toBe(410);

      await legacyWrite("oura.activity", {
        days: [day("readded-file", "2026-09-15")],
      });
      const entry = ctx!.indexManager.findLatestByScope("oura.activity")!;
      expect(entry.afterTombstoneVersion).toBe(
        tombstoneVersion === "1" ? 1 : null,
      );
      expect(await nativeRows()).toEqual(before);

      const ownerRead = await ownerGet("/v1/data/oura.activity");
      const builderRead = await builderGet("oura.activity");
      expect.soft(ownerRead.status).toBe(410);
      expect.soft(builderRead.status).toBe(410);
      expect.soft(ownerRead.text).not.toContain("before-deletion");
      expect.soft(builderRead.text).not.toContain("before-deletion");
      const listing = await ownerGet("/v1/data");
      expect(listing.status).toBe(200);
      expect
        .soft(JSON.parse(listing.text))
        .toMatchObject({ scopes: [], total: 0 });

      const history = await ownerGet(
        `/v1/data/oura.activity?at=${encodeURIComponent(entry.collectedAt)}`,
      );
      // Unknown/unsafe tombstones cannot authorize even the file's re-add
      // until the registry actually reports that file live.
      expect(history.status).toBe(tombstoneVersion === "1" ? 200 : 410);
      if (history.status === 200)
        expect(ids(history.text)).toEqual(["readded-file"]);

      // Registering the file and restarting also gives no causal evidence
      // that the old canonical records were re-added.
      registeredFile = true;
      await ctx!.cleanup();
      ctx = await boot("oura", { dataPointFeed });
      token = await ownerPdppToken();
      expect(
        ctx.indexManager.findLatestByScope("oura.activity")
          ?.afterTombstoneVersion,
      ).toBe(tombstoneVersion === "1" ? 1 : null);
      expect(await nativeRows()).toEqual(before);
      const afterRestart = await ownerGet("/v1/data/oura.activity");
      const builderAfterRestart = await builderGet("oura.activity");
      expect.soft(afterRestart.status).toBe(410);
      expect.soft(builderAfterRestart.status).toBe(410);
      expect.soft(afterRestart.text).not.toContain("before-deletion");
      expect.soft(builderAfterRestart.text).not.toContain("before-deletion");
      const listingAfterRestart = await ownerGet("/v1/data");
      expect
        .soft(JSON.parse(listingAfterRestart.text))
        .toMatchObject({ scopes: [], total: 0 });
      const historyAfterRestart = await ownerGet(
        `/v1/data/oura.activity?at=${encodeURIComponent(entry.collectedAt)}`,
      );
      expect(historyAfterRestart.status).toBe(200);
      expect(ids(historyAfterRestart.text)).toEqual(["readded-file"]);

      offline = true;
      await ctx!.cleanup();
      ctx = await boot("oura", { dataPointFeed });
      expect((await ownerGet("/v1/data/oura.activity")).status).toBe(410);
      expect((await builderGet("oura.activity")).status).toBe(410);
      expect(JSON.parse((await ownerGet("/v1/data")).text)).toMatchObject({
        scopes: [],
        total: 0,
      });
      expect(
        (
          await ownerGet(
            `/v1/data/oura.activity?at=${encodeURIComponent(entry.collectedAt)}`,
          )
        ).status,
      ).toBe(200);
    },
  );

  it("retains a deletion observed with PDPP disabled and no canonical rows without sticking ordinary files deleted", async () => {
    let deleted = true;
    const dataPointFeed: NonNullable<CreateServerOptions["dataPointFeed"]> = {
      listDataPointsByOwner: async () => ({ dataPoints: [], cursor: null }),
      getDataPoint: async ({ ownerAddress, scope }) => ({
        id: "synthetic-point",
        ownerAddress,
        scope,
        dataHash: `0x${(deleted ? "00" : "11").repeat(32)}`,
        metadataHash: `0x${(deleted ? "00" : "11").repeat(32)}`,
        expectedVersion: deleted ? "1" : "2",
        addedAt: "2026-09-01T00:00:00Z",
        deletedAt: deleted ? "2026-09-11T00:00:00Z" : null,
      }),
    };
    await ctx!.cleanup();
    ctx = await boot("oura", { dataPointFeed, pdppEnabled: false });
    expect((await ownerGet("/v1/data/oura.activity")).status).toBe(410);
    expect((await ownerGet("/v1/data/notes.manual")).status).toBe(410);
    await legacyWrite("oura.activity", STALE);
    await legacyWrite("notes.manual", { text: "readded" });
    // No canonical rows yet: the causally marked file remains readable.
    expect((await ownerGet("/v1/data/oura.activity")).status).toBe(200);
    expect((await ownerGet("/v1/data/notes.manual")).status).toBe(200);

    deleted = false;
    await ctx!.cleanup();
    ctx = await boot("oura", { dataPointFeed });
    expect((await ownerGet("/v1/data/oura.activity")).status).toBe(200);
    await legacyWrite("oura.readiness", { readiness: [] });
    const token = await ownerPdppToken();
    const bindingDb = new Database(join(tempDir, "index.db"), {
      readonly: true,
    });
    const binding = bindingDb
      .prepare(
        "SELECT generation FROM pdpp_instance_binding WHERE instance = ?",
      )
      .get(accountOne) as { generation: number };
    bindingDb.close();
    await replace(
      token,
      "activity",
      [day("fresh-collection", "2026-09-10")],
      "2026-09-10T06:00:00Z",
      accountOne,
      binding.generation,
    );
    expect((await ownerGet("/v1/data/oura.activity")).status).toBe(200);
    expect((await builderGet("oura.activity")).status).toBe(200);
    expect((await ownerGet("/v1/data/notes.manual")).status).toBe(200);
    expect((await ownerGet("/v1/data/oura.readiness")).status).toBe(200);
    expect(
      JSON.parse((await ownerGet("/v1/data")).text).scopes.map(
        (row: { scope: string }) => row.scope,
      ),
    ).toEqual(["notes.manual", "oura.activity", "oura.readiness"]);
  });

  it("requires a gateway re-add under erase-and-stop policy for reads and listing, even after reset", async () => {
    const actualPolicy = deletedScopePolicy.deletedScopeNeedsGatewayReadd;
    const override = vi
      .spyOn(deletedScopePolicy, "deletedScopeNeedsGatewayReadd")
      .mockImplementation(() => actualPolicy("erase-and-stop"));
    vi.useFakeTimers({ toFake: ["Date"] });
    let state: "deleted" | "missing" | "live" = "deleted";
    let gatewayVersion = "1";
    const scope = "oura.activity";
    const dataPointFeed: NonNullable<CreateServerOptions["dataPointFeed"]> = {
      listDataPointsByOwner: async () => ({ dataPoints: [], cursor: null }),
      getDataPoint: async ({ ownerAddress, scope: requested }) =>
        requested !== scope || state === "missing"
          ? null
          : {
              id: "policy-point",
              ownerAddress,
              scope,
              dataHash: `0x${(state === "deleted" ? "00" : "11").repeat(32)}`,
              metadataHash: `0x${(state === "deleted" ? "00" : "11").repeat(32)}`,
              expectedVersion: gatewayVersion,
              addedAt: "2026-09-01T00:00:00Z",
              deletedAt: state === "deleted" ? "2026-09-11T00:00:00Z" : null,
            },
    };
    try {
      await ctx!.cleanup();
      ctx = await boot("oura", { dataPointFeed });
      const token = await ownerPdppToken();
      expect((await ownerGet(`/v1/data/${scope}`)).status).toBe(410);
      const bindingDb = new Database(join(tempDir, "index.db"), {
        readonly: true,
      });
      const { generation } = bindingDb
        .prepare(
          "SELECT generation FROM pdpp_instance_binding WHERE instance = ?",
        )
        .get(accountOne) as { generation: number };
      bindingDb.close();
      await replace(
        token,
        "activity",
        [day("recollected", "2026-09-15")],
        "2026-09-15T06:00:00Z",
        accountOne,
        generation,
      );
      const assertHidden = async () => {
        expect((await ownerGet(`/v1/data/${scope}`)).status).toBe(410);
        expect((await builderGet(scope)).status).toBe(410);
        const listing = await ownerGet("/v1/data");
        expect(listing.status).toBe(200);
        expect(
          JSON.parse(listing.text).scopes.map(
            (row: { scope: string }) => row.scope,
          ),
        ).not.toContain(scope);
      };
      await assertHidden();
      const reset = await ctx!.app.request(
        `/pdpp/instances/${encodeURIComponent(accountOne)}/reset`,
        {
          method: "POST",
          headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json",
          },
          body: JSON.stringify({
            expected_method: "oura",
            expected_generation: generation,
            next_method: "oura",
          }),
        },
      );
      expect(reset.status).toBe(200);
      await replace(
        token,
        "activity",
        [day("after-reset", "2026-09-15")],
        "2026-09-15T06:00:00Z",
        accountOne,
        generation + 1,
      );
      await assertHidden();
      state = "missing";
      vi.setSystemTime(Date.now() + 120_001);
      await assertHidden();
      state = "live";
      vi.setSystemTime(Date.now() + 120_001);
      await assertHidden(); // A live response at the deleted version is not a re-add.
      gatewayVersion = "2";
      vi.setSystemTime(Date.now() + 120_001);
      expect((await ownerGet(`/v1/data/${scope}`)).status).toBe(200);
      expect((await builderGet(scope)).status).toBe(200);
      const listed = JSON.parse((await ownerGet("/v1/data")).text).scopes.map(
        (row: { scope: string }) => row.scope,
      );
      expect(listed).toContain(scope);
      expect(override).toHaveBeenCalled();
    } finally {
      override.mockRestore();
      vi.useRealTimers();
    }
  });

  it("serves canonical rows to a legacy grant and the owner after coverage", async () => {
    await legacyWrite("oura.activity", COVERED_A1);
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

  it("gives the owner the stored file with ?view=stored, not the canonical view, and refuses it to a grantee", async () => {
    await legacyWrite("oura.activity", COVERED_A1);
    const token = await ownerPdppToken();
    await replace(
      token,
      "activity",
      [day("a2", "2026-09-02"), day("a1", "2026-09-01")],
      "2026-09-10T06:00:00Z",
    );
    const canonical = await ownerGet("/v1/data/oura.activity");
    expect(canonical.dataSource).toBe("canonical");
    expect(ids(canonical.text)).toEqual(["a1", "a2"]);

    const stored = await ownerGet("/v1/data/oura.activity?view=stored");
    expect(stored.status).toBe(200);
    expect(stored.dataSource).toBe("legacy");
    expect(ids(stored.text)).toEqual(["a1"]);

    const asBuilder = await ctx!.app.request(
      "/v1/data/oura.activity?view=stored",
      {
        headers: {
          authorization: await buildWeb3SignedHeader({
            wallet: builder,
            aud: ctx!.config.server.origin,
            method: "GET",
            uri: "/v1/data/oura.activity",
            grantId: GRANT_ID,
          }),
        },
      },
    );
    expect(asBuilder.status).toBe(403);
  });

  it("reflects a later repair and keeps the revision stable while nothing changes", async () => {
    await legacyWrite("oura.activity", { days: [day("a1", "2026-09-01", 10)] });
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
      [day("a1", "2026-09-01", 10), day("a3", "2026-09-03")],
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
      ["a1", 10],
      ["a3", 80],
    ]);
  });

  it("serves a covered empty stream and refuses a later loss of legacy data", async () => {
    await legacyWrite("oura.activity", { days: [] });
    await legacyWrite("oura.readiness", {
      days: [{ id: "r1", day: "2026-09-01", score: 70 }],
    });
    const token = await ownerPdppToken();
    await replace(token, "activity", [], "2026-09-10T06:00:00Z");

    const empty = await ownerGet("/v1/data/oura.activity");
    expect(empty.status).toBe(200);
    expect(JSON.parse(empty.text)).toMatchObject({
      collectedAt: "2026-09-10T06:00:00.000Z",
      data: { days: [] },
    });

    // Readiness was never collected canonically: its file is still the
    // only copy, so the scope stays the file's. A sibling stream's rows
    // do not make it canonical.
    const uncollected = await ownerGet("/v1/data/oura.readiness");
    expect(uncollected.status).toBe(200);
    expect(uncollected.text).toContain('"r1"');

    // After a complete canonical read records takeover, an unproven empty
    // stream must refuse rather than resurrect the superseded legacy file.
    await replace(
      token,
      "activity",
      [day("a1", "2026-09-01")],
      "2026-09-11T06:00:00Z",
    );
    await replace(
      token,
      "readiness",
      [{ id: "r1", day: "2026-09-01", score: 70 }],
      "2026-09-11T06:00:00Z",
    );
    const takenOver = await ownerGet("/v1/data/oura.readiness");
    expect(takenOver.dataSource).toBe("canonical");
    expect(ids(takenOver.text)).toEqual(["r1"]);
    const deleted = await ctx!.app.request("/v1/streams/readiness/records/r1", {
      method: "DELETE",
      headers: { authorization: `Bearer ${token}` },
    });
    expect(deleted.status).toBe(204);
    const unproven = await ownerGet("/v1/data/oura.readiness");
    expect(unproven.status).toBe(503);
    expect(JSON.parse(unproven.text)).toMatchObject({
      error: "CANONICAL_VIEW_UNAVAILABLE",
      reason: "canonical_view_incomplete",
    });
    expect(unproven.text).not.toContain('"r1"');
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
      detail: "method_not_configured",
    });
    expect(read.text).not.toContain("stale-legacy");
  });

  it("keeps the legacy file until a complete canonical projection succeeds", async () => {
    await legacyWrite("oura.activity", STALE);
    const token = await ownerPdppToken();
    await replace(
      token,
      "activity",
      [day("a1", "2026-09-01"), day("a2", "not-a-day")],
      "2026-09-10T06:00:00Z",
    );
    const read = await builderGet("oura.activity");
    expect(read.status).toBe(200);
    expect(ids(read.text)).toEqual(["stale-legacy"]);
  });

  it("serves the indexed legacy file when blob materialization is unsupported before takeover", async () => {
    await legacyWrite("oura.activity", STALE);
    const legacyHead = {
      ...ctx!.indexManager.findLatestByScope("oura.activity")!,
    };
    const legacyBytes = await readFile(join(tempDir, "data", legacyHead.path));
    const token = await ownerPdppToken();
    await replace(
      token,
      "activity",
      [day("a1", "2026-09-01")],
      "2026-09-10T06:00:00Z",
    );

    const recordDb = new Database(join(tempDir, "index.db"));
    try {
      const row = recordDb
        .prepare(
          "SELECT data FROM pdpp_records WHERE instance = ? AND stream = ? AND record_key = ?",
        )
        .get(accountOne, "activity", "a1") as { data: string };
      const data = JSON.parse(row.data) as Record<string, unknown>;
      data.blob_ref = {};
      recordDb
        .prepare(
          "UPDATE pdpp_records SET data = ? WHERE instance = ? AND stream = ? AND record_key = ?",
        )
        .run(JSON.stringify(data), accountOne, "activity", "a1");
      expect(
        recordDb.prepare("SELECT * FROM legacy_scope_takeovers").all(),
      ).toEqual([]);
    } finally {
      recordDb.close();
    }

    const read = await ownerGet("/v1/data/oura.activity");
    expect(read.status).toBe(200);
    expect(read.dataSource).toBe("legacy");
    expect(ids(read.text)).toEqual(["stale-legacy"]);
    expect(ctx!.indexManager.findLatestByScope("oura.activity")).toEqual(
      legacyHead,
    );
    expect(await readFile(join(tempDir, "data", legacyHead.path))).toEqual(
      legacyBytes,
    );
    const ledgerDb = new Database(join(tempDir, "index.db"), {
      readonly: true,
      fileMustExist: true,
    });
    try {
      expect(
        ledgerDb.prepare("SELECT * FROM legacy_scope_takeovers").all(),
      ).toEqual([]);
    } finally {
      ledgerDb.close();
    }
  });

  it("does not resurrect the legacy file after a complete canonical takeover", async () => {
    await legacyWrite("oura.activity", COVERED_A1);
    const token = await ownerPdppToken();
    await replace(
      token,
      "activity",
      [day("a1", "2026-09-01")],
      "2026-09-10T06:00:00Z",
    );
    expect(ids((await ownerGet("/v1/data/oura.activity")).text)).toEqual([
      "a1",
    ]);

    await replace(
      token,
      "activity",
      [day("a2", "not-a-day")],
      "2026-09-11T06:00:00Z",
    );
    const read = await ownerGet("/v1/data/oura.activity");
    expect(read.status).toBe(503);
    expect(JSON.parse(read.text)).toMatchObject({
      error: "CANONICAL_VIEW_UNAVAILABLE",
      status: "incomplete",
      reason: "all_rows_rejected",
    });
    expect(read.text).not.toContain("stale-legacy");
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
    await legacyWrite("oura.activity", COVERED_A1);
    const legacyEntryBefore = {
      ...ctx!.indexManager.findLatestByScope("oura.activity")!,
    };
    const legacyBytesBefore = await readFile(
      join(tempDir, "data", legacyEntryBefore.path),
    );
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

    const latest = await ownerGet("/v1/data/oura.activity");
    expect(latest.dataSource).toBe("canonical");
    expect(ids(latest.text)).toEqual(["a1"]);

    const historical = await ownerGet(
      `/v1/data/oura.activity?at=${encodeURIComponent(at)}`,
    );
    expect(historical.status).toBe(200);
    expect(historical.dataSource).toBe("legacy");
    expect(ids(historical.text)).toEqual(["a1"]);

    const manual = await ownerGet("/v1/data/notes.manual");
    expect(manual.status).toBe(200);
    expect(JSON.parse(manual.text)).toMatchObject({ data: { text: "kept" } });

    expect(
      await readFile(join(tempDir, "data", legacyEntryBefore.path)),
    ).toEqual(legacyBytesBefore);
    expect(ctx!.indexManager.findLatestByScope("oura.activity")).toEqual(
      legacyEntryBefore,
    );

    const ledgerDb = new Database(join(tempDir, "index.db"), {
      readonly: true,
      fileMustExist: true,
    });
    try {
      expect(
        ledgerDb
          .prepare(
            `SELECT scope, superseded_version, superseded_cas_revision,
                    superseded_collected_at, superseded_path, taken_over_at
               FROM legacy_scope_takeovers`,
          )
          .all(),
      ).toEqual([
        expect.objectContaining({
          scope: "oura.activity",
          superseded_version: legacyEntryBefore.version,
          superseded_cas_revision: legacyEntryBefore.casRevision,
          superseded_collected_at: legacyEntryBefore.collectedAt,
          superseded_path: legacyEntryBefore.path,
          taken_over_at: expect.any(String),
        }),
      ]);
    } finally {
      ledgerDb.close();
    }
  });
});

describe("GET /v1/data listing", () => {
  it("lists a bound scope with canonical freshness, never the legacy head's", async () => {
    await legacyWrite("oura.activity", COVERED_A1);
    await legacyWrite("notes.manual", { text: "kept" });
    const token = await ownerPdppToken();
    await replace(
      token,
      "activity",
      [day("a1", "2026-09-01")],
      "2026-09-10T06:00:00Z",
    );
    const legacyHead = ctx!.indexManager.findLatestByScope("oura.activity")!;
    const beforeTakeover = await ownerGet("/v1/data");
    const beforeBody = JSON.parse(beforeTakeover.text) as {
      scopes: { scope: string; latestCollectedAt: string }[];
    };
    expect(
      beforeBody.scopes.find((scope) => scope.scope === "oura.activity")
        ?.latestCollectedAt,
    ).toBe(legacyHead.collectedAt);

    const latest = await ownerGet("/v1/data/oura.activity");
    expect(latest.dataSource).toBe("canonical");

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
    await legacyWrite("notes.manual", { text: "kept" });
    const token = await ownerPdppToken();
    await replace(
      token,
      "activity",
      [day("a1", "2026-09-01")],
      "2026-09-10T06:00:00Z",
    );
    await registerSecondAccount(token);
    const second = await ownerPdppToken(SECOND_ACCOUNT);
    await replace(
      second,
      "readiness",
      [{ id: "r1", day: "2026-09-01", score: 70 }],
      "2026-09-10T06:00:00Z",
      SECOND_ACCOUNT,
    );
    // Two accounts hold data: both bound scopes would be refused as
    // ambiguous, so neither is listed. The manual scope still is.
    const listing = await ownerGet("/v1/data");
    const body = JSON.parse(listing.text) as {
      scopes: { scope: string }[];
      total: number;
    };
    expect(body.scopes.map((s) => s.scope)).toEqual(["notes.manual"]);
    expect(body.total).toBe(1);
  });

  it("lists a scope served only from canonical rows, without a legacy write", async () => {
    const token = await ownerPdppToken();
    await replace(
      token,
      "activity",
      [day("a1", "2026-09-01")],
      "2026-09-10T06:00:00Z",
    );
    expect(ctx!.indexManager.listDistinctScopes().scopes).toEqual([]);

    const listing = await ownerGet("/v1/data");
    expect(listing.status).toBe(200);
    expect(JSON.parse(listing.text)).toEqual({
      scopes: [
        {
          scope: "oura.activity",
          latestCollectedAt: "2026-09-10T06:00:00.000Z",
          versionCount: 0,
        },
      ],
      total: 1,
      limit: 20,
      offset: 0,
    });
    // The listing still creates no legacy entry.
    expect(ctx!.indexManager.listDistinctScopes().scopes).toEqual([]);
  });

  it("lists to a grantee only the scopes its grant covers, canonical-only ones included", async () => {
    await legacyWrite("notes.manual", { text: "kept" });
    const token = await ownerPdppToken();
    await replace(
      token,
      "activity",
      [day("a1", "2026-09-01")],
      "2026-09-10T06:00:00Z",
    );
    const signedGet = async (uri: string) =>
      ctx!.app.request(uri, {
        headers: {
          authorization: await buildWeb3SignedHeader({
            wallet: builder,
            aud: ctx!.config.server.origin,
            method: "GET",
            uri,
            grantId: GRANT_ID,
          }),
        },
      });

    const listing = await signedGet("/v1/data");
    expect(listing.status).toBe(200);
    const body = (await listing.json()) as { scopes: { scope: string }[] };
    expect(body.scopes.map((entry) => entry.scope)).toEqual(["oura.activity"]);

    // The grant covers oura.*, so another scope's version history is refused.
    expect((await signedGet("/v1/data/notes.manual/versions")).status).toBe(
      403,
    );
  });

  it("merges canonical-only and stored scopes in one ordered, paged listing", async () => {
    await legacyWrite("notes.manual", { text: "kept" });
    await legacyWrite("oura.readiness", { readiness: [] });
    const token = await ownerPdppToken();
    await replace(
      token,
      "activity",
      [day("a1", "2026-09-01")],
      "2026-09-10T06:00:00Z",
    );
    const scopesOf = async (query: string) => {
      const body = JSON.parse((await ownerGet(`/v1/data${query}`)).text) as {
        scopes: { scope: string }[];
        total: number;
      };
      return { scopes: body.scopes.map((s) => s.scope), total: body.total };
    };
    // oura.readiness has no canonical data: it stays its file's.
    expect(await scopesOf("")).toEqual({
      scopes: ["notes.manual", "oura.activity", "oura.readiness"],
      total: 3,
    });
    expect(await scopesOf("?limit=1&offset=1")).toEqual({
      scopes: ["oura.activity"],
      total: 3,
    });
    expect(await scopesOf("?scopePrefix=oura.")).toEqual({
      scopes: ["oura.activity", "oura.readiness"],
      total: 2,
    });
    expect(await scopesOf("?scopePrefix=notes.")).toEqual({
      scopes: ["notes.manual"],
      total: 1,
    });
  });
});

describe("scopes the canonical view does not convert", () => {
  it("keeps unbound scopes of a collected namespace on their files", async () => {
    await legacyWrite("oura.personal_info", { email: "kept@example.com" });
    await legacyWrite("oura.manual", { text: "owner-note" });
    await legacyWrite("oura.readiness", STALE);
    const token = await ownerPdppToken();
    await replace(
      token,
      "activity",
      [day("a1", "2026-09-01")],
      "2026-09-10T06:00:00Z",
    );

    const personal = await ownerGet("/v1/data/oura.personal_info");
    expect(personal.status).toBe(200);
    expect(JSON.parse(personal.text)).toMatchObject({
      data: { email: "kept@example.com" },
    });
    const manual = await ownerGet("/v1/data/oura.manual");
    expect(manual.status).toBe(200);
    expect(JSON.parse(manual.text)).toMatchObject({
      data: { text: "owner-note" },
    });
    // A bound scope the connection holds no data for is not converted
    // either: its file is still the only copy.
    const readiness = await ownerGet("/v1/data/oura.readiness");
    expect(readiness.status).toBe(200);
    expect(ids(readiness.text)).toEqual(["stale-legacy"]);
  });

  it("keeps an unbound scope on its file after a never-used connection is deleted", async () => {
    await legacyWrite("oura.manual", { text: "owner-note" });
    const token = await ownerPdppToken();
    const deleted = await ctx!.app.request(
      `/pdpp/connections/${encodeURIComponent(accountOne)}`,
      { method: "DELETE", headers: { authorization: `Bearer ${token}` } },
    );
    expect(deleted.status).toBe(200);

    const manual = await ownerGet("/v1/data/oura.manual");
    expect(manual.status).toBe(200);
    expect(JSON.parse(manual.text)).toMatchObject({
      data: { text: "owner-note" },
    });
  });
});

describe("selectors, payment, restart and deletion around a canonical scope", () => {
  async function collectActivity() {
    const token = await ownerPdppToken();
    await replace(
      token,
      "activity",
      [day("a1", "2026-09-01")],
      "2026-09-10T06:00:00Z",
    );
    return token;
  }

  it.each(["at=", "fileId=", "at=&fileId="])(
    "treats an empty selector (%s) as the latest read",
    async (query) => {
      await legacyWrite("oura.activity", COVERED_A1);
      await collectActivity();
      const read = await ownerGet(`/v1/data/oura.activity?${query}`);
      expect(read.status).toBe(200);
      expect(ids(read.text)).toEqual(["a1"]);
      expect(read.etag).toBe((await ownerGet("/v1/data/oura.activity")).etag);
    },
  );

  async function signedRead(scope: string, payment?: string) {
    return ctx!.app.request(`/v1/data/${scope}`, {
      headers: {
        authorization: await buildWeb3SignedHeader({
          wallet: builder,
          aud: ctx!.config.server.origin,
          method: "GET",
          uri: `/v1/data/${scope}`,
          grantId: GRANT_ID,
        }),
        ...(payment ? { "x-payment": payment } : {}),
      },
    });
  }

  /** A well-formed, locally verifiable payment for the grant's fee. */
  async function paymentHeader(): Promise<string> {
    const { fee } = grant();
    const message = {
      payerAddress: builder.address,
      opType: "grant" as const,
      opId: GRANT_ID as `0x${string}`,
      asset: fee.asset as `0x${string}`,
      amount: BigInt(fee.totalDue),
      paymentNonce: nextPaymentNonce(),
    };
    const signature = await builder.signTypedData({
      domain: escrowPaymentDomain(ctx!.config.gateway),
      types: { GenericPayment: [...GENERIC_PAYMENT_TYPES.GenericPayment] },
      primaryType: "GenericPayment",
      message,
    });
    return encodePaymentHeader({
      x402Version: 1,
      scheme: "vana-escrow-grant",
      network: `vana:${ctx!.config.gateway.chainId}`,
      payload: {
        message: {
          ...message,
          amount: message.amount.toString(),
          paymentNonce: message.paymentNonce.toString(),
        },
        signature,
      },
    });
  }

  function stubEscrow() {
    const pay = vi.fn(
      async () =>
        new Response(JSON.stringify({ success: true }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    );
    vi.stubGlobal("fetch", pay);
    return pay;
  }

  it("refuses an ambiguous paid read before any challenge or payment", async () => {
    await ctx!.cleanup();
    ctx = await boot("oura", { payment: true });
    const token = await collectActivity();
    await registerSecondAccount(token);
    const second = await ownerPdppToken(SECOND_ACCOUNT);
    await replace(
      second,
      "activity",
      [day("two", "2026-09-02")],
      "2026-09-10T06:00:00Z",
      SECOND_ACCOUNT,
    );
    const pay = stubEscrow();
    try {
      for (const response of [
        await signedRead("oura.activity"),
        await signedRead("oura.activity", await paymentHeader()),
      ]) {
        expect(response.status).toBe(409);
        expect(response.headers.get("x-payment-response")).toBeNull();
        expect(await response.json()).toMatchObject({
          error: "CANONICAL_VIEW_UNAVAILABLE",
          reason: "ambiguous_connection",
        });
      }
      expect(pay).not.toHaveBeenCalled();
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("refuses a charged read of a canonical scope before the challenge, so no legacy version is attested", async () => {
    await ctx!.cleanup();
    ctx = await boot("oura", { payment: true });
    await legacyWrite("oura.activity", COVERED_A1);
    await legacyWrite("oura.readiness", { readiness: [] });
    for (const scope of ["oura.activity", "oura.readiness"]) {
      const entry = ctx!.indexManager.findLatestByScope(scope)!;
      ctx!.indexManager.updateDataPointId(entry.path, `0x${"22".repeat(32)}`);
    }
    await collectActivity();
    const pay = stubEscrow();
    try {
      for (const response of [
        await signedRead("oura.activity"),
        await signedRead("oura.activity", await paymentHeader()),
      ]) {
        expect(response.status).toBe(503);
        const text = await response.text();
        expect(JSON.parse(text)).toMatchObject({
          error: "CANONICAL_VIEW_UNAVAILABLE",
          reason: "paid_read_unsupported",
        });
        expect(text).not.toContain("accessRecord");
        expect(text).not.toContain('"a1"');
      }
      expect(pay).not.toHaveBeenCalled();

      // The owner is not charged and still reads the canonical body.
      const owned = await ownerGet("/v1/data/oura.activity");
      expect(owned.status).toBe(200);
      expect(ids(owned.text)).toEqual(["a1"]);

      // A scope still served from its file keeps the existing challenge,
      // bound to that file's registered version.
      const challenged = await signedRead("oura.readiness");
      expect(challenged.status).toBe(402);
      const challenge = (await challenged.json()) as {
        accepts: { accessRecord?: { dataPointId: string } }[];
      };
      expect(challenge.accepts[0]?.accessRecord?.dataPointId).toBe(
        `0x${"22".repeat(32)}`,
      );
      expect(pay).not.toHaveBeenCalled();
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("keeps refusing a canonical scope after a restart with PDPP disabled", async () => {
    await legacyWrite("oura.activity", COVERED_A1);
    await legacyWrite("oura.readiness", { readiness: [] });
    await legacyWrite("notes.manual", { text: "kept" });
    await collectActivity();
    expect((await ownerGet("/v1/data/oura.activity")).status).toBe(200);
    await ctx!.cleanup();
    ctx = await createServer(
      ServerConfigSchema.parse({
        tunnel: { enabled: false },
        pdpp: { enabled: false },
      }),
      { serverDir: tempDir, dataDir: join(tempDir, "data") },
    );

    const read = await ownerGet("/v1/data/oura.activity");
    expect(read.status).toBe(503);
    expect(JSON.parse(read.text)).toMatchObject({
      error: "CANONICAL_VIEW_UNAVAILABLE",
      reason: "connection_unavailable",
      detail: "method_not_configured",
    });
    expect(read.text).not.toContain("stale-legacy");
    // Only the owned scope is refused; the others keep their files.
    expect((await ownerGet("/v1/data/oura.readiness")).status).toBe(200);
    expect((await ownerGet("/v1/data/notes.manual")).status).toBe(200);
    const listing = JSON.parse((await ownerGet("/v1/data")).text) as {
      scopes: { scope: string }[];
    };
    expect(listing.scopes.map((s) => s.scope)).toEqual([
      "notes.manual",
      "oura.readiness",
    ]);
  });

  it.each(["between entries", "inside transaction"])(
    "keeps an unmarked scope hidden after a process kill %s and resumes on restart",
    async (mode) => {
      const token = await collectActivity();
      await replace(
        token,
        "readiness",
        [day("sibling", "2026-09-02")],
        "2026-09-10T06:00:00Z",
      );
      await ctx!.cleanup();
      ctx = undefined;
      const dbPath = join(tempDir, "index.db");
      const fixtureDb = new Database(dbPath);
      try {
        const insert = fixtureDb.prepare(
          "INSERT INTO vana_scope_deletion_history (owner_address, scope, deleted_at, tombstone_version) VALUES (?, ?, ?, ?)",
        );
        insert.run(owner, "oura.activity", "2026-09-11T00:00:00Z", "2");
        insert.run(owner, "oura.readiness", "2026-09-11T00:00:00Z", "2");
        if (mode === "inside transaction")
          fixtureDb.exec(
            "CREATE TRIGGER interrupt_scope_erase BEFORE UPDATE OF generation ON pdpp_instance_binding WHEN OLD.generation = 2 BEGIN SELECT pause_test(); END",
          );
      } finally {
        fixtureDb.close();
      }
      const base = join(process.cwd(), "packages/server/src/storage");
      const storeUrl = pathToFileURL(
        join(base, "pdpp-records-sqlite-store.ts"),
      ).href;
      const historyUrl = pathToFileURL(
        join(base, "scope-deletion-history.ts"),
      ).href;
      const script = `
        import Database from 'better-sqlite3';
        import { writeSync } from 'node:fs';
        import { createSqliteRecordStore } from ${JSON.stringify(storeUrl)};
        import { migrateScopeDeletionHistory } from ${JSON.stringify(historyUrl)};
        const db = new Database(${JSON.stringify(dbPath)});
        const pause = () => { writeSync(1, 'READY\\n'); Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0); return 0; };
        db.function('pause_test', pause);
        const store = createSqliteRecordStore(db);
        migrateScopeDeletionHistory(db, ${JSON.stringify(owner)}, store, {info(fields) { if (${JSON.stringify(mode)} === 'between entries' && fields.scope === 'oura.readiness') pause(); }, error() {}});
      `;
      const child = spawn(
        process.execPath,
        ["--import", "tsx", "--input-type=module", "--eval", script],
        { stdio: ["ignore", "pipe", "pipe"] },
      );
      let errors = "";
      child.stderr.setEncoding("utf8");
      child.stderr.on("data", (data: string) => {
        errors += data;
      });
      try {
        await new Promise<void>((resolve, reject) => {
          const timer = setTimeout(
            () => reject(new Error(`migration child did not pause: ${errors}`)),
            15_000,
          );
          child.stdout.setEncoding("utf8");
          child.stdout.on("data", (data: string) => {
            if (data.includes("READY")) {
              clearTimeout(timer);
              resolve();
            }
          });
          child.once("error", (error) => {
            clearTimeout(timer);
            reject(error);
          });
          child.once("exit", () => {
            clearTimeout(timer);
            reject(new Error(`migration child exited: ${errors}`));
          });
        });
      } finally {
        if (child.exitCode === null && child.signalCode === null) {
          const closed = once(child, "close");
          child.kill("SIGKILL");
          await closed;
        }
      }
      vi.stubEnv("PS_SCOPE_DELETION_MIGRATION_DRY_RUN", "true");
      ctx = await boot();
      expect((await ownerGet("/v1/data/oura.readiness")).status).toBe(410);
      await ctx.cleanup();
      ctx = undefined;
      const checkDb = new Database(dbPath);
      try {
        expect(
          checkDb
            .prepare(
              "SELECT scope, erase_applied FROM vana_scope_deletion_history WHERE owner_address = ? ORDER BY scope",
            )
            .all(owner),
        ).toEqual([
          { scope: "oura.activity", erase_applied: 1 },
          { scope: "oura.readiness", erase_applied: 0 },
        ]);
        expect(
          checkDb
            .prepare(
              "SELECT count(*) AS n FROM pdpp_records WHERE instance = ? AND stream = 'readiness'",
            )
            .get(accountOne),
        ).toEqual({ n: 1 });
        if (mode === "inside transaction")
          checkDb.exec("DROP TRIGGER interrupt_scope_erase");
      } finally {
        checkDb.close();
      }
      vi.stubEnv("PS_SCOPE_DELETION_MIGRATION_DRY_RUN", "false");
      ctx = await boot();
      const resumedDb = new Database(dbPath, { readonly: true });
      try {
        expect(
          resumedDb
            .prepare(
              "SELECT erase_applied FROM vana_scope_deletion_history WHERE owner_address = ? AND scope = ?",
            )
            .get(owner, "oura.readiness"),
        ).toEqual({ erase_applied: 1 });
        expect(
          resumedDb
            .prepare(
              "SELECT count(*) AS n FROM pdpp_records WHERE instance = ? AND stream = 'readiness'",
            )
            .get(accountOne),
        ).toEqual({ n: 0 });
      } finally {
        resumedDb.close();
      }
    },
    30_000,
  );

  it("keeps an interrupted migration hidden and resumes it after restart", async () => {
    const token = await collectActivity();
    await replace(
      token,
      "readiness",
      [day("sibling", "2026-09-02")],
      "2026-09-10T06:00:00Z",
    );
    const fixtureDb = new Database(join(tempDir, "index.db"));
    try {
      fixtureDb
        .prepare(
          "INSERT INTO vana_scope_deletion_history (owner_address, scope, deleted_at, tombstone_version) VALUES (?, ?, ?, ?)",
        )
        .run(owner, "oura.activity", "2026-09-11T00:00:00Z", "2");
      fixtureDb.exec(
        "CREATE TRIGGER interrupt_scope_erase BEFORE UPDATE OF generation ON pdpp_instance_binding BEGIN SELECT RAISE(ABORT, 'interrupted migration'); END",
      );
    } finally {
      fixtureDb.close();
    }
    await ctx!.cleanup();
    ctx = await boot();
    expect((await ownerGet("/v1/data/oura.activity")).status).toBe(410);
    const afterFailure = new Database(join(tempDir, "index.db"));
    try {
      expect(
        afterFailure
          .prepare(
            "SELECT erase_applied FROM vana_scope_deletion_history WHERE owner_address = ? AND scope = ?",
          )
          .get(owner, "oura.activity"),
      ).toEqual({ erase_applied: 0 });
      expect(
        afterFailure
          .prepare(
            "SELECT count(*) AS n FROM pdpp_records WHERE instance = ? AND stream = 'activity'",
          )
          .get(accountOne),
      ).toEqual({ n: 1 });
      afterFailure.exec("DROP TRIGGER interrupt_scope_erase");
    } finally {
      afterFailure.close();
    }
    await ctx.cleanup();
    ctx = await boot();
    const afterRestart = new Database(join(tempDir, "index.db"), {
      readonly: true,
    });
    try {
      expect(
        afterRestart
          .prepare(
            "SELECT erase_applied FROM vana_scope_deletion_history WHERE owner_address = ? AND scope = ?",
          )
          .get(owner, "oura.activity"),
      ).toEqual({ erase_applied: 1 });
      expect(
        afterRestart
          .prepare(
            "SELECT count(*) AS n FROM pdpp_records WHERE instance = ? AND stream = 'activity'",
          )
          .get(accountOne),
      ).toEqual({ n: 0 });
      expect(
        afterRestart
          .prepare(
            "SELECT count(*) AS n FROM pdpp_records WHERE instance = ? AND stream = 'readiness'",
          )
          .get(accountOne),
      ).toEqual({ n: 1 });
    } finally {
      afterRestart.close();
    }
  });

  it("keeps pre-upgrade unmarked deletion history hidden", async () => {
    await collectActivity();
    const db = new Database(join(tempDir, "index.db"));
    try {
      db.prepare(
        `INSERT INTO vana_scope_deletion_history (owner_address, scope, deleted_at, tombstone_version) VALUES (?, ?, ?, ?)`,
      ).run(owner, "oura.activity", "2026-09-11T00:00:00Z", "2");
    } finally {
      db.close();
    }
    const read = await ownerGet("/v1/data/oura.activity");
    expect(read.status).toBe(410);
    const listing = await ownerGet("/v1/data");
    const body = JSON.parse(listing.text) as { scopes: { scope: string }[] };
    expect(body.scopes.some((scope) => scope.scope === "oura.activity")).toBe(
      false,
    );
  });

  it("erases a newly observed deletion and keeps sibling records", async () => {
    let deleted = false;
    const dataPointFeed: NonNullable<CreateServerOptions["dataPointFeed"]> = {
      listDataPointsByOwner: async () => ({ dataPoints: [], cursor: null }),
      getDataPoint: async ({ ownerAddress, scope }) =>
        !deleted || scope !== "oura.activity"
          ? null
          : {
              id: "point",
              ownerAddress,
              scope,
              dataHash: `0x${"11".repeat(32)}`,
              metadataHash: `0x${"22".repeat(32)}`,
              expectedVersion: "2",
              addedAt: "2026-09-01T00:00:00Z",
              deletedAt: "2026-09-11T00:00:00Z",
            },
    };
    await ctx!.cleanup();
    ctx = await boot("oura", { dataPointFeed });
    const token = await collectActivity();
    await replace(
      token,
      "readiness",
      [day("sibling", "2026-09-02")],
      "2026-09-10T06:00:00Z",
    );
    deleted = true;
    const listing = await ownerGet("/v1/data");
    expect(JSON.parse(listing.text).scopes).not.toEqual(
      expect.arrayContaining([
        expect.objectContaining({ scope: "oura.activity" }),
      ]),
    );
    const read = await ownerGet("/v1/data/oura.activity");
    const db = new Database(join(tempDir, "index.db"), { readonly: true });
    try {
      expect(
        db
          .prepare(
            "SELECT erase_applied FROM vana_scope_deletion_history WHERE owner_address = ? AND scope = ?",
          )
          .get(owner, "oura.activity"),
      ).toEqual({ erase_applied: 1 });
      expect(
        db
          .prepare(
            "SELECT count(*) AS n FROM pdpp_records WHERE instance = ? AND stream = 'activity'",
          )
          .get(accountOne),
      ).toEqual({ n: 0 });
      expect(
        db
          .prepare(
            "SELECT count(*) AS n FROM pdpp_records WHERE instance = ? AND stream = 'readiness'",
          )
          .get(accountOne),
      ).toEqual({ n: 1 });
    } finally {
      db.close();
    }
    expect(read.status, read.text).toBe(410);
  });

  it("serves new canonical records after durable scope deletion", async () => {
    let deleted = false;
    const dataPointFeed: NonNullable<CreateServerOptions["dataPointFeed"]> = {
      listDataPointsByOwner: async () => ({ dataPoints: [], cursor: null }),
      getDataPoint: async ({ ownerAddress, scope }) => ({
        id: "point",
        ownerAddress,
        scope,
        dataHash: `0x${"11".repeat(32)}`,
        metadataHash: `0x${"22".repeat(32)}`,
        expectedVersion: deleted ? "2" : "1",
        addedAt: "2026-09-01T00:00:00Z",
        deletedAt: deleted ? "2026-09-11T00:00:00Z" : null,
      }),
    };
    await ctx!.cleanup();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        if (init?.method === "GET") {
          const request = new URL(url);
          return new Response(
            JSON.stringify({
              data: {
                dataPointId: request.pathname.split("/")[3],
                ownerAddress: owner,
                scope: request.searchParams.get("scope"),
                head: null,
                versions: [],
              },
              pagination: {
                limit: Number(request.searchParams.get("limit")),
                hasMore: false,
                nextAfter: null,
              },
            }),
          );
        }
        deleted = true;
        return new Response(
          JSON.stringify({
            expectedVersion: "2",
            deletedAt: "2026-09-11T00:00:00Z",
          }),
          { status: 200 },
        );
      }),
    );
    try {
      ctx = await boot("oura", { dataPointFeed, syncEnabled: true });
      expect(ctx.syncManager).not.toBeNull();
      await legacyWrite("oura.activity", COVERED_A1);
      const token = await collectActivity();
      const reset = await ctx.app.request(
        `/pdpp/instances/${encodeURIComponent(accountOne)}/reset`,
        {
          method: "POST",
          headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json",
          },
          body: JSON.stringify({
            expected_method: "oura",
            expected_generation: 1,
            next_method: "oura",
          }),
        },
      );
      expect(reset.status).toBe(200);
      const deletion = await ctx.app.request("/v1/data/oura.activity", {
        method: "DELETE",
        headers: { authorization: `Bearer ${CONTROL_PLANE_TOKEN}` },
      });
      expect(deletion.status).toBe(200);
      expect(await deletion.json()).toMatchObject({
        durable: true,
        steps: { gateway: { status: "ok" } },
      });
      const write = await ctx.app.request(
        "/v1/streams/activity/records/replace?method=oura&binding_generation=3",
        {
          method: "POST",
          headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json",
          },
          body: JSON.stringify({
            instance: accountOne,
            emitted_at: "2026-09-12T12:00:00Z",
            source_collected_at: "2026-09-12T06:00:00Z",
            records: [
              {
                key: "fresh",
                data: day("fresh", "2026-09-12"),
                emitted_at: "2026-09-12T07:00:00Z",
              },
            ],
          }),
        },
      );
      expect(write.status).toBe(200);
      const read = await ownerGet("/v1/data/oura.activity");
      expect(read.status).toBe(200);
      expect(ids(read.text)).toEqual(["fresh"]);
      const listing = await ownerGet("/v1/data");
      expect(JSON.parse(listing.text).scopes).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ scope: "oura.activity" }),
        ]),
      );
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it.each(["reset", "delete"])(
    "deletes the scope file after connection %s erases its rows",
    async (action) => {
      await legacyWrite("oura.activity", COVERED_A1);
      const file = ctx!.indexManager.findLatestByScope("oura.activity")!;
      const token = await collectActivity();
      const erasure =
        action === "reset"
          ? await ctx!.app.request(
              `/pdpp/instances/${encodeURIComponent(accountOne)}/reset`,
              {
                method: "POST",
                headers: {
                  authorization: `Bearer ${token}`,
                  "content-type": "application/json",
                },
                body: JSON.stringify({
                  expected_method: "oura",
                  expected_generation: 1,
                  next_method: "oura",
                }),
              },
            )
          : await ctx!.app.request(
              `/pdpp/connections/${encodeURIComponent(accountOne)}`,
              {
                method: "DELETE",
                headers: { authorization: `Bearer ${token}` },
              },
            );
      expect(erasure.status).toBe(200);
      const deletion = await ctx!.app.request("/v1/data/oura.activity", {
        method: "DELETE",
        headers: { authorization: `Bearer ${CONTROL_PLANE_TOKEN}` },
      });
      expect(deletion.status).toBe(200);
      expect(
        ctx!.indexManager.findLatestByScope("oura.activity"),
      ).toBeUndefined();
      await expect(
        readFile(join(tempDir, "data", file.path)),
      ).rejects.toMatchObject({ code: "ENOENT" });
      const versions = await ownerGet("/v1/data/oura.activity/versions");
      expect([200, 410]).toContain(versions.status);
      if (versions.status === 200)
        expect(JSON.parse(versions.text).versions).toEqual([]);

      if (action === "reset") {
        const write = await ctx!.app.request(
          "/v1/streams/activity/records/replace?method=oura&binding_generation=2",
          {
            method: "POST",
            headers: {
              authorization: `Bearer ${token}`,
              "content-type": "application/json",
            },
            body: JSON.stringify({
              instance: accountOne,
              emitted_at: "2026-09-11T12:00:00Z",
              source_collected_at: "2026-09-11T06:00:00Z",
              records: [
                {
                  key: "a2",
                  data: day("a2", "2026-09-02"),
                  emitted_at: "2026-09-11T07:00:00Z",
                },
              ],
            }),
          },
        );
        expect(write.status).toBe(200);
        const read = await ownerGet("/v1/data/oura.activity");
        expect(read.status).toBe(200);
        expect(ids(read.text)).toEqual(["a2"]);
        expect(
          (
            await ctx!.app.request("/v1/data/oura.activity", {
              method: "DELETE",
              headers: { authorization: `Bearer ${CONTROL_PLANE_TOKEN}` },
            })
          ).status,
        ).toBe(409);
      }
    },
  );

  it("keeps the scope file when another connection still holds rows", async () => {
    await legacyWrite("oura.activity", COVERED_A1);
    const token = await collectActivity();
    await registerSecondAccount(token);
    const secondToken = await ownerPdppToken(SECOND_ACCOUNT);
    await replace(
      secondToken,
      "activity",
      [day("b1", "2026-09-02")],
      "2026-09-10T06:00:00Z",
      SECOND_ACCOUNT,
    );
    const reset = await ctx!.app.request(
      `/pdpp/instances/${encodeURIComponent(accountOne)}/reset`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          expected_method: "oura",
          expected_generation: 1,
          next_method: "oura",
        }),
      },
    );
    expect(reset.status).toBe(200);
    const deletion = await ctx!.app.request("/v1/data/oura.activity", {
      method: "DELETE",
      headers: { authorization: `Bearer ${CONTROL_PLANE_TOKEN}` },
    });
    expect(deletion.status).toBe(409);
    expect(ctx!.indexManager.findLatestByScope("oura.activity")).toBeDefined();
  });

  it("refuses a local DELETE of a canonical scope and changes nothing", async () => {
    await legacyWrite("oura.activity", COVERED_A1);
    await legacyWrite("notes.manual", { text: "kept" });
    await collectActivity();
    const before = ctx!.indexManager.findLatestByScope("oura.activity");
    expect(before).toBeDefined();

    const deletion = await ctx!.app.request("/v1/data/oura.activity", {
      method: "DELETE",
      headers: { authorization: `Bearer ${CONTROL_PLANE_TOKEN}` },
    });
    expect(deletion.status).toBe(409);
    expect(await deletion.json()).toMatchObject({
      error: "CANONICAL_DELETE_UNSUPPORTED",
      scope: "oura.activity",
      message:
        'Scope "oura.activity" has connector records that this route cannot delete. Nothing was deleted. Reset or delete the connection to erase its records, then delete the scope.',
    });
    // Nothing was deleted, and nothing claims it was: the legacy history
    // and the canonical latest body are both as before.
    expect(ctx!.indexManager.findLatestByScope("oura.activity")).toEqual(
      before,
    );
    const latest = await ownerGet("/v1/data/oura.activity");
    expect(latest.status).toBe(200);
    expect(ids(latest.text)).toEqual(["a1"]);

    // A scope the view does not own is still deleted as before.
    const manual = await ctx!.app.request("/v1/data/notes.manual", {
      method: "DELETE",
      headers: { authorization: `Bearer ${CONTROL_PLANE_TOKEN}` },
    });
    expect(manual.status).toBe(200);
    expect((await ownerGet("/v1/data/notes.manual")).status).toBe(404);
  });
});

describe("configured methods that share one public source", () => {
  // The github-browser method collects source `github`, as Desktop's
  // pdpp-methods.json admits it. Profile fields as in the github-browser
  // 0.2.30 manifest; this is a routing check, not provider parity with the
  // 0.2.15 artifact Desktop pins.
  const GITHUB = "https://registry.pdpp.dev/sources/github";
  const GITHUB_PROFILE_FIELDS = [
    "id",
    "username",
    "fullName",
    "bio",
    "company",
    "location",
    "website",
    "avatarUrl",
    "followers",
    "following",
    "repositoryCount",
    "profileUrl",
    "pinnedRepositories",
    "organizations",
    "achievements",
    "contributionsLastYear",
  ];

  it("serves github.profile through the github-browser projection on source github", async () => {
    await ctx!.cleanup();
    ctx = await boot("github-browser", {
      declaration: JSON.stringify({
        source_id: GITHUB,
        source_kind: "connector",
        version: "1",
        streams: [
          {
            name: "profile",
            fields: GITHUB_PROFILE_FIELDS,
            required_fields: ["id", "username", "profileUrl"],
            primary_key: ["id"],
          },
        ],
      }),
    });
    await legacyWrite("github.profile", { username: "current-user" });
    const token = await registerTestConnection(
      ctx.app,
      ctx.devToken!,
      owner,
      GITHUB,
      "github-browser",
    );
    const write = await ctx.app.request(
      "/v1/streams/profile/records/replace?method=github-browser&binding_generation=1",
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          instance: `github:${owner}`,
          emitted_at: "2026-09-10T12:00:00Z",
          source_collected_at: "2026-09-10T06:00:00Z",
          records: [
            {
              key: "profile",
              data: {
                id: "profile",
                username: "current-user",
                profileUrl: "https://github.com/current-user",
              },
              emitted_at: "2026-09-10T07:00:00Z",
            },
          ],
        }),
      },
    );
    expect(write.status).toBe(200);

    const read = await ownerGet("/v1/data/github.profile");
    expect(read.status).toBe(200);
    const body = JSON.parse(read.text) as { data: Record<string, unknown> };
    expect(body.data).toMatchObject({
      username: "current-user",
      profileUrl: "https://github.com/current-user",
    });
    // The browser profile drops the PDPP runtime key from the legacy body.
    expect(body.data).not.toHaveProperty("id");
    expect(read.dataSource).toBe("canonical");
  });

  it("serves an Oura scope from an oura-browser connection on source oura", async () => {
    // The default boot registered account one with method oura; start over.
    // Registration accepts one configured method per source, so this boot
    // configures oura-browser alone for source oura.
    await ctx!.cleanup();
    await rm(tempDir, { recursive: true, force: true });
    await mkdir(tempDir);
    ctx = await boot("oura-browser");
    await legacyWrite("oura.activity", {
      days: [{ id: "b1", day: "2026-09-01", score: 80 }],
    });
    const token = await registerTestConnection(
      ctx.app,
      ctx.devToken!,
      owner,
      OURA,
      "oura-browser",
    );
    const write = await ctx.app.request(
      "/v1/streams/activity/records/replace?method=oura-browser&binding_generation=1",
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          instance: accountOne,
          emitted_at: "2026-09-10T12:00:00Z",
          source_collected_at: "2026-09-10T06:00:00Z",
          records: [
            {
              key: "b1",
              data: day("b1", "2026-09-01"),
              emitted_at: "2026-09-10T07:00:00Z",
            },
          ],
        }),
      },
    );
    expect(write.status).toBe(200);
    const read = await ownerGet("/v1/data/oura.activity");
    expect(read.status).toBe(200);
    expect(ids(read.text)).toEqual(["b1"]);
  });
});

// These are fixture regression checks, not new captures from the named apps.
// The route must keep the same body when ownership moves off the legacy file.
describe.each([
  "linkedin.connections",
  "github.repositories",
  "github.starred",
  "github.profile",
  "spotify.playlists",
  "spotify.savedTracks",
  "linkedin.profile",
  "spotify.profile",
  "instagram.profile",
])("owner coverage decision for %s", (scope) => {
  it.each([false, true])(
    "serves canonical only when its PDPP read covers the old file (complete=%s)",
    async (complete) => {
      const fixture: {
        profileKey?: string;
        streams: Record<string, Record<string, unknown>[]>;
        legacyBody: Record<string, unknown>;
      } =
        scope === "spotify.savedTracks"
          ? {
              streams: {
                saved_tracks: [
                  {
                    id: "track-a",
                    name: "Song",
                    artist_names: [],
                    album_name: "Album",
                    album_artist_names: [],
                    uri: "spotify:track:track-a",
                  },
                ],
              },
              legacyBody: {
                savedTracks: [
                  {
                    name: "Song",
                    artists: [],
                    album: { name: "Album", artists: [] },
                    uri: "spotify:track:track-a",
                    added_at: "",
                    duration_ms: 0,
                    explicit: false,
                  },
                ],
                total: 1,
              },
            }
          : JSON.parse(
              await readFile(
                new URL(
                  `../../core/src/legacy-projection/__fixtures__/parity/${scope}.json`,
                  import.meta.url,
                ),
                "utf8",
              ),
            );
      const canonicalBody = structuredClone(fixture.legacyBody);
      if (scope === "spotify.playlists") {
        // No old track entities need an identity. The newer complete read can
        // add real tracks, including local tracks and nonempty artist lists.
        for (const playlist of fixture.legacyBody.playlists as {
          tracks: unknown[];
          tracks_total: number;
        }[]) {
          playlist.tracks = [];
          playlist.tracks_total = 0;
        }
      }
      const method = fixture.profileKey ?? scope.split(".")[0]!;
      const source = `https://registry.pdpp.dev/sources/${method}`;
      // A profile fixture may include other scopes' input streams.
      const streams = scope.endsWith("profile")
        ? { profile: fixture.streams.profile! }
        : fixture.streams;
      const declaration = JSON.stringify({
        source_id: source,
        source_kind: "connector",
        version: "1",
        streams: Object.entries(streams).map(([name, rows]) => ({
          name,
          fields: [...new Set(rows.flatMap((row) => Object.keys(row)))],
          required_fields: ["id"],
          primary_key: ["id"],
        })),
      });
      await ctx!.cleanup();
      ctx = await boot(method, { declaration });
      // Store the old file before registering the canonical owner.
      vi.useFakeTimers({ toFake: ["Date"] });
      try {
        vi.setSystemTime(new Date("2026-10-09T00:00:00.000Z"));
        await legacyWrite(scope, fixture.legacyBody);
      } finally {
        vi.useRealTimers();
      }
      const token = await registerTestConnection(
        ctx.app,
        ctx.devToken!,
        owner,
        source,
        method,
      );
      const instance = `${method}:${owner}`;
      for (const [stream, rows] of Object.entries(streams)) {
        const response = await ctx.app.request(
          `/v1/streams/${stream}/records/replace?method=${method}&binding_generation=1`,
          {
            method: "POST",
            headers: {
              authorization: `Bearer ${token}`,
              "content-type": "application/json",
            },
            body: JSON.stringify({
              instance,
              emitted_at: "2026-10-21T00:00:00.000Z",
              ...(complete
                ? { source_collected_at: "2026-10-21T00:00:00.000Z" }
                : {}),
              records: (complete ? rows : []).map((data) => ({
                key: String(data.id),
                data,
                emitted_at: "2026-10-21T00:00:00.000Z",
              })),
            }),
          },
        );
        expect(response.status, await response.text()).toBe(200);
      }
      const read = await ownerGet(`/v1/data/${scope}`);
      expect(read.status).toBe(200);
      // Fresh complete imports replace the whole dataset, including bodies
      // whose old entities have no comparable key. Incomplete imports do not.
      const canonical = complete;
      expect(read.dataSource).toBe(canonical ? "canonical" : "legacy");
      expect(JSON.parse(read.text).data).toEqual(
        canonical ? canonicalBody : fixture.legacyBody,
      );
      if (canonical) expectCompletedReplacement(scope);
    },
  );
});
