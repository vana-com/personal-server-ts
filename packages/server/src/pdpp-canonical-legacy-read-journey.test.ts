/**
 * Latest legacy reads of connector scopes come from the canonical rows.
 *
 * Every request goes through a real `createServer` app: real config, real
 * declaration files, the real SQLite record store, real P7 replaces, real
 * legacy files written through POST /v1/data, and the legacy read auth
 * (owner control-plane token, and a builder's Web3Signed legacy grant).
 *
 * A stored legacy head remains latest until a complete canonical projection
 * with matching completion receipts records takeover. After takeover, a
 * canonical read that cannot be served is a typed refusal, not the file.
 */

import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
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
}

async function boot(
  methodId = "oura",
  {
    declaration = OURA_DECLARATION,
    payment = false,
    dataPointFeed,
    pdppEnabled = true,
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
  } as unknown as GatewayClient;
  return createServer(
    ServerConfigSchema.parse({
      tunnel: { enabled: false },
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
    await replace(
      token,
      "activity",
      [day("canonical-without-readd", "2026-09-10")],
      "2026-09-10T06:00:00Z",
    );
    expect((await ownerGet("/v1/data/oura.activity")).status).toBe(410);
    expect((await builderGet("oura.activity")).status).toBe(410);
    expect((await ownerGet("/v1/data/notes.manual")).status).toBe(200);
    expect((await ownerGet("/v1/data/oura.readiness")).status).toBe(200);
    expect(
      JSON.parse((await ownerGet("/v1/data")).text).scopes.map(
        (row: { scope: string }) => row.scope,
      ),
    ).toEqual(["notes.manual", "oura.readiness"]);
  });

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

  it("serves a known-empty stream as empty, and refuses a collected stream whose rows cannot be proven current", async () => {
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

    // Readiness was never collected canonically: its file is still the
    // only copy, so the scope stays the file's. A sibling stream's rows
    // do not make it canonical.
    const uncollected = await ownerGet("/v1/data/oura.readiness");
    expect(uncollected.status).toBe(200);
    expect(uncollected.text).toContain("stale-legacy");

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
      reason: "stream_completion_unknown",
      streams: ["readiness"],
    });
    expect(unproven.text).not.toContain("stale-legacy");
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
    await legacyWrite("oura.activity", STALE);
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
    await legacyWrite("oura.activity", STALE);
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
    expect(ids(historical.text)).toEqual(["stale-legacy"]);

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
    await legacyWrite("oura.activity", STALE);
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
      await legacyWrite("oura.activity", STALE);
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
      types: GENERIC_PAYMENT_TYPES,
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
    await legacyWrite("oura.activity", STALE);
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
        expect(text).not.toContain("stale-legacy");
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
    await legacyWrite("oura.activity", STALE);
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

  it("refuses a local DELETE of a canonical scope and changes nothing", async () => {
    await legacyWrite("oura.activity", STALE);
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
    await legacyWrite("github.profile", { username: "stale-legacy" });
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
    expect(read.text).not.toContain("stale-legacy");
  });

  it("serves an Oura scope from an oura-browser connection on source oura", async () => {
    // The default boot registered account one with method oura; start over.
    // Registration accepts one configured method per source, so this boot
    // configures oura-browser alone for source oura.
    await ctx!.cleanup();
    await rm(tempDir, { recursive: true, force: true });
    await mkdir(tempDir);
    ctx = await boot("oura-browser");
    await legacyWrite("oura.activity", STALE);
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
