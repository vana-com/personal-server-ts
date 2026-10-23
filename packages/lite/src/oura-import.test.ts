import ouraProfileProvenance from "../../core/src/legacy-projection/declarations/oura-browser.provenance.json";
import { createScopeDeletionTracker } from "@opendatalabs/personal-server-ts-core/sync";
import { describe, expect, it, vi } from "vitest";
import { createDataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import {
  createMemoryPsLiteStorage,
  createMemoryPsLiteAccessLogStore,
  createMemoryPsLiteTokenStore,
  createMemoryPsLitePersistence,
} from "./test-support/memory.js";
import { createPersistentPsLiteStorage } from "./storage.js";
import {
  createBearerTokenPsLiteAuth,
  createPsLiteRuntime,
  importOuraBrowserRecords,
  type OuraBrowserImportInput,
} from "./index.js";

const oldTime = "2026-10-14T00:00:00.000Z";
const newTime = "2026-10-15T00:00:00.000Z";
const streams = ["sleep", "readiness", "activity"] as const;
function input(
  collectedAt = newTime,
  day = "2026-10-13",
): OuraBrowserImportInput {
  return {
    selection: { streams: streams.map((name) => ({ name })) },
    collectedAt,
    records: streams.map((stream) => ({
      stream,
      data: {
        id: `${stream}-1`,
        day,
        score: 80,
        ...(stream === "sleep"
          ? { record_type: "daily_score", sleep_score: 80 }
          : {}),
      },
    })),
    completion: {
      streams: streams.map((stream) => ({
        stream,
        status: "complete",
        recordCount: 1,
      })),
    },
  };
}
async function setup(
  extraDay = false,
  storage = createMemoryPsLiteStorage(),
  runtimeOptions: Partial<Parameters<typeof createPsLiteRuntime>[0]> = {},
) {
  const envelope = createDataFileEnvelope("oura.activity", oldTime, {
    days: [
      { id: "activity-1", day: "2026-10-13", score: 60 },
      ...(extraDay
        ? [{ id: "activity-older", day: "2025-01-01", score: 50 }]
        : []),
    ],
  });
  const write = await storage.writeEnvelope(envelope);
  await storage.insertEntry({
    fileId: "legacy",
    path: write.relativePath,
    scope: envelope.scope,
    collectedAt: oldTime,
    sizeBytes: write.sizeBytes,
  });
  return { storage, ...runtimeFor(storage, runtimeOptions) };
}

function runtimeFor(
  storage: ReturnType<typeof createMemoryPsLiteStorage>,
  runtimeOptions: Partial<Parameters<typeof createPsLiteRuntime>[0]> = {},
) {
  const accessLogs = createMemoryPsLiteAccessLogStore();
  const runtime = createPsLiteRuntime({
    storage,
    active: true,
    accessLogReader: accessLogs,
    accessLogWriter: accessLogs,
    tokenStore: createMemoryPsLiteTokenStore(),
    saveConfig: async () => {},
    auth: createBearerTokenPsLiteAuth({
      ownerToken: "owner",
      builderToken: "builder",
    }),
    ...runtimeOptions,
  });
  const post = (body: unknown, token = "owner") =>
    runtime.fetch(
      new Request("https://ps.test/v1/import/oura-browser", {
        method: "POST",
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify(body),
      }),
    );
  return { post, runtime };
}

describe("Lite Oura browser takeover", () => {
  it("refuses a restricted all-stream batch even when it covers every retained ID", async () => {
    const { storage, post } = await setup();
    const body = input();
    body.selection = {
      streams: streams.map((name) => ({
        name,
        time_range: { since: "2026-10-13", until: "2026-10-14" },
      })),
    };
    const before = storage.findEntry({ scope: "oura.activity" });
    const response = await post(body);
    expect(response.status).toBe(409);
    expect(await response.json()).toMatchObject({
      reason: "selection_not_eligible",
    });
    expect(storage.findEntry({ scope: "oura.activity" })).toEqual(before);
    const missing = {
      ...input(),
      selection: undefined,
      artifactBoundNativeCompletion: true,
    };
    expect((await post(missing)).status).toBe(409);
    expect(storage.findEntry({ scope: "oura.activity" })).toEqual(before);
  });
  it("refuses incomplete evidence through the public helper before replacing a legacy head", async () => {
    const { storage } = await setup();
    const body = input();
    body.completion.streams.pop();
    expect(await importOuraBrowserRecords(storage, body)).toMatchObject({
      ok: false,
    });
    expect(storage.countVersions("oura.activity")).toBe(1);
  });
  it.each([
    null,
    {},
    { ...input(), complete: false },
    { ...input(), collectedAt: "2026-02-30T00:00:00.000Z" },
    { complete: false },
    { ...input(), completion: null },
    {
      ...input(),
      completion: {
        streams: input().completion.streams.map((s) => ({
          ...s,
          recordCount: 2,
        })),
      },
    },
    {
      ...input(),
      completion: {
        streams: input().completion.streams.map((s) => ({
          ...s,
          status: "partial",
        })),
      },
    },
  ])("fails closed on malformed/missing completion %j", async (body) => {
    const { storage, post } = await setup();
    expect((await post(body)).status).toBe(409);
    expect(storage.countVersions("oura.activity")).toBe(1);
    expect(storage.countVersions("oura.sleep")).toBe(0);
  });
  it("requires owner auth on the real runtime route", async () => {
    const { storage, post } = await setup();
    expect((await post(input(), "builder")).status).toBe(401);
    expect((await post(input(), "unknown")).status).toBe(401);
    expect(storage.countVersions("oura.activity")).toBe(1);
  });
  it("accepts a fresh complete smaller dataset without deleting the historical file", async () => {
    const { storage, post } = await setup(true);
    const response = await post(input());
    expect(response.status).toBe(200);
    expect((await response.json()).receipts).toHaveLength(3);
    expect(storage.countVersions("oura.activity")).toBe(2);
    expect(storage.countVersions("oura.sleep")).toBe(1);
    expect(storage.countVersions("oura.readiness")).toBe(1);
    expect(
      (await storage.readEnvelope("oura.activity", oldTime)).data,
    ).toMatchObject({ days: [{ id: "activity-1" }, { id: "activity-older" }] });
  });
  it("admits legitimate refreshed values, retains legacy, and replays without another version", async () => {
    const { storage, post } = await setup();
    expect((await post(input())).status).toBe(200);
    expect(storage.countVersions("oura.activity")).toBe(2);
    expect(
      (await storage.readEnvelope("oura.activity", oldTime)).data,
    ).toMatchObject({ days: [{ score: 60 }] });
    const head = storage.findEntry({ scope: "oura.activity" })!;
    expect(
      (await storage.readEnvelope("oura.activity", head.collectedAt)).data,
    ).toMatchObject({ days: [{ score: 80 }] });
    expect((await post(input())).status).toBe(200);
    expect(storage.countVersions("oura.activity")).toBe(2);
  });
  it("requires same-time parity and rejects stale collections", async () => {
    const { storage, post } = await setup();
    expect(await (await post(input(oldTime))).json()).toMatchObject({
      reason: "field_mismatch",
    });
    expect(
      await (await post(input("2026-10-13T00:00:00.000Z"))).json(),
    ).toMatchObject({ reason: "stale_collection" });
    expect(storage.countVersions("oura.sleep")).toBe(0);
  });
  it("appends same-time parity without overwriting the old file", async () => {
    const { storage, post } = await setup();
    const body = input(oldTime);
    body.records[2]!.data.score = 60;
    expect((await post(body)).status).toBe(200);
    expect(storage.countVersions("oura.activity")).toBe(2);
    expect(storage.findEntry({ scope: "oura.activity" })!.collectedAt).toBe(
      "2026-10-14T00:00:00.001Z",
    );
    expect((await post(body)).status).toBe(200);
    expect(storage.countVersions("oura.activity")).toBe(2);
  });
  it("admits a new owner without confirmation", async () => {
    const storage = createMemoryPsLiteStorage();
    expect(await importOuraBrowserRecords(storage, input())).toMatchObject({
      ok: true,
    });
    for (const stream of streams)
      expect(storage.countVersions(`oura.${stream}`)).toBe(1);
  });
  it("refuses dropped rows and duplicate identities without any writes", async () => {
    const { storage, post } = await setup();
    const body = input();
    body.records[1]!.data.day = "invalid";
    expect(await (await post(body)).json()).toMatchObject({
      reason: "projection_incomplete",
    });
    const duplicate = input();
    duplicate.records.push(duplicate.records[0]!);
    duplicate.completion.streams[0]!.recordCount = 2;
    expect(await (await post(duplicate)).json()).toMatchObject({
      reason: "duplicate_record",
    });
    expect(storage.countVersions("oura.sleep")).toBe(0);
  });

  it("keeps appended and legacy files across persistent Lite reloads and serves all three owner/builder reads", async () => {
    const persistence = createMemoryPsLitePersistence();
    const storage = await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      persistence,
    );
    const { post, runtime } = await setup(false, storage);
    expect((await post(input())).status).toBe(200);
    for (const stream of streams) {
      for (const token of ["owner", "builder"]) {
        const response = await runtime.fetch(
          new Request(
            `https://ps.test/v1/data/oura.${stream}?grantId=openpet`,
            {
              headers: { authorization: `Bearer ${token}` },
            },
          ),
        );
        expect(response.status).toBe(200);
        const envelope = await response.json();
        const rows =
          stream === "sleep" ? envelope.data.dailyScores : envelope.data.days;
        expect(rows[0].score).toBe(80);
      }
    }
    const reloaded = await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      persistence,
    );
    expect(reloaded.countVersions("oura.activity")).toBe(2);
    expect(
      (await reloaded.readEnvelope("oura.activity", oldTime)).data,
    ).toMatchObject({ days: [{ score: 60 }] });
    expect(await importOuraBrowserRecords(reloaded, input())).toMatchObject({
      ok: true,
    });
    expect(reloaded.countVersions("oura.activity")).toBe(2);
  });

  it("replaces rather than unions complete disjoint batches across reloads", async () => {
    const persistence = createMemoryPsLitePersistence();
    const storage = await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      persistence,
    );
    const { post } = await setup(true, storage);
    const first = await post(input());
    expect(await first.json()).toMatchObject({ ok: true });
    expect(storage.countVersions("oura.activity")).toBe(2);
    expect(storage.countVersions("oura.sleep")).toBe(1);
    const reloaded = await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      persistence,
    );
    const accessLogs = createMemoryPsLiteAccessLogStore();
    const runtime = createPsLiteRuntime({
      storage: reloaded,
      active: true,
      auth: createBearerTokenPsLiteAuth({
        ownerToken: "owner",
        builderToken: "builder",
      }),
      accessLogReader: accessLogs,
      accessLogWriter: accessLogs,
      tokenStore: createMemoryPsLiteTokenStore(),
      saveConfig: async () => {},
    });
    const olderWindow = input("2026-10-16T00:00:00.000Z");
    for (const record of olderWindow.records) {
      record.data.id = `${record.stream}-older`;
      record.data.day = "2025-01-01";
    }
    const response = await runtime.fetch(
      new Request("https://ps.test/v1/import/oura-browser", {
        method: "POST",
        headers: {
          authorization: "Bearer owner",
          "content-type": "application/json",
        },
        body: JSON.stringify(olderWindow),
      }),
    );
    expect(await response.json()).toMatchObject({ ok: true });
    expect(reloaded.countVersions("oura.activity")).toBe(3);
    expect(reloaded.countVersions("oura.sleep")).toBe(2);
    const disjointHead = reloaded.findEntry({ scope: "oura.activity" })!;
    expect(
      (await reloaded.readEnvelope("oura.activity", disjointHead.collectedAt))
        .data,
    ).toMatchObject({ days: [{ id: "activity-older" }] });
    const disjointData = (
      await reloaded.readEnvelope("oura.activity", disjointHead.collectedAt)
    ).data as { days: unknown[] };
    expect(disjointData.days).toHaveLength(1);
    const covering = input("2026-10-17T00:00:00.000Z");
    covering.records.push(...olderWindow.records);
    for (const proof of covering.completion.streams) proof.recordCount = 2;
    const covered = await runtime.fetch(
      new Request("https://ps.test/v1/import/oura-browser", {
        method: "POST",
        headers: {
          authorization: "Bearer owner",
          "content-type": "application/json",
        },
        body: JSON.stringify(covering),
      }),
    );
    expect(await covered.json()).toMatchObject({ ok: true });
    const head = reloaded.findEntry({ scope: "oura.activity" })!;
    const data = (
      await reloaded.readEnvelope("oura.activity", head.collectedAt)
    ).data as { days: { id: string }[] };
    expect(data.days.map((day) => day.id)).toEqual([
      "activity-1",
      "activity-older",
    ]);
    expect(
      (await reloaded.readEnvelope("oura.activity", oldTime)).data,
    ).toMatchObject({ days: [{ score: 60 }, { score: 50 }] });
    expect(
      reloaded
        .listScopes({})
        .scopes.map((entry) => entry.scope)
        .sort(),
    ).toEqual(streams.map((stream) => `oura.${stream}`).sort());
  });

  it("uses ordinary ingest provenance, tombstone ordering, derivative invalidation and sync notifications", async () => {
    const tracker = createScopeDeletionTracker({
      serverOwner: "0x0000000000000000000000000000000000000001",
    });
    tracker.markDeleted("oura.activity", {
      deletedAt: "2026-10-14T01:00:00.000Z",
      version: "7",
    });
    const trigger = vi.fn().mockResolvedValue(undefined);
    const markSourceChanged = vi.fn();
    const { storage, post, runtime } = await setup(
      false,
      createMemoryPsLiteStorage(),
      {
        scopeDeletions: tracker,
        syncManager: { trigger, getStatus: vi.fn() },
        derivatives: {
          store: {} as never,
          scheduler: { markSourceChanged } as never,
        },
      },
    );
    const imported = await post(input());
    expect(imported.status).toBe(200);
    const success = await imported.json();
    for (const stream of streams) {
      const scope = `oura.${stream}`;
      const head = storage.findEntry({ scope })!;
      const envelope = (await storage.readEnvelope(
        scope,
        head.collectedAt,
      )) as unknown as Record<string, unknown>;
      expect
        .soft(
          success.receipts?.find(
            (receipt: { scope: string }) => receipt.scope === scope,
          ),
        )
        .toEqual({
          scope,
          collectedAt: head.collectedAt,
          plaintextBytes: new TextEncoder().encode(JSON.stringify(envelope))
            .byteLength,
        });
      expect.soft(envelope.producer).toBe("pdpp-import-projection");
      expect.soft(envelope.producer_provenance).toMatchObject({
        method: "oura-browser",
        sourceCollectedAt: newTime,
        declaration_digest:
          ouraProfileProvenance.outputs["collection-profile.json"],
      });
      expect
        .soft(envelope.producer_provenance)
        .toEqual(JSON.parse(head.producerProvenance!));
      expect
        .soft(markSourceChanged)
        .toHaveBeenCalledWith(scope, { lineageSources: undefined });
    }
    expect
      .soft(
        storage.findEntry({ scope: "oura.activity" })!.afterTombstoneVersion,
      )
      .toBe(7);
    expect.soft(trigger).toHaveBeenCalledTimes(3);
    const read = await runtime.fetch(
      new Request("https://ps.test/v1/data/oura.activity", {
        headers: { authorization: "Bearer owner" },
      }),
    );
    expect.soft(read.status).toBe(200);
  });

  it.each(["oura", "oura-browser"])(
    "compares an existing stored %s PDPP head through its served projection",
    async (connector) => {
      const { storage, post } = await setup();
      await storage.writeEnvelope(
        createDataFileEnvelope("oura.activity", oldTime, {
          records: [
            {
              id: "activity-1",
              day: "2026-10-13",
              score: 60,
              $pdpp: {
                sourceId: `https://registry.pdpp.dev/sources/${connector}`,
              },
            },
          ],
        }),
      );
      const result = await post(input());
      expect(result.status, await result.clone().text()).toBe(200);
    },
  );

  it("authenticates requirements and fails closed on malformed retained dates, with null only for no history", async () => {
    const { storage, runtime } = await setup();
    const get = (token = "owner") =>
      runtime.fetch(
        new Request("https://ps.test/v1/import/oura-browser/requirements", {
          headers: { authorization: `Bearer ${token}` },
        }),
      );
    expect((await get("builder")).status).toBe(401);
    expect((await get("unknown")).status).toBe(401);
    await storage.writeEnvelope(
      createDataFileEnvelope("oura.activity", oldTime, {
        days: [{ day: "2026-02-30" }],
      }),
    );
    const malformed = await get();
    expect(malformed.status).toBe(409);
    expect(await malformed.json()).toMatchObject({
      error: "OURA_HISTORY_INVALID",
    });
    await storage.deleteScope("oura.activity");
    const empty = await get();
    expect(empty.headers.get("cache-control")).toBe("no-store");
    expect(await empty.json()).toEqual({
      ok: true,
      contract: "oura-legacy-takeover-v1",
      takeoverSelection: "unrestricted-three-streams-v1",
      since: null,
    });
  });

  it("reports the existing oldest day without requiring old identities in a fresh import", async () => {
    const { storage, runtime, post } = await setup(true);
    const requirements = () =>
      runtime.fetch(
        new Request("https://ps.test/v1/import/oura-browser/requirements", {
          headers: { authorization: "Bearer owner" },
        }),
      );
    const required = await requirements();
    expect(required.status).toBe(200);
    expect(await required.json()).toEqual({
      ok: true,
      contract: "oura-legacy-takeover-v1",
      takeoverSelection: "unrestricted-three-streams-v1",
      since: "2025-01-01",
    });
    expect((await post(input())).status).toBe(200);
    const covering = input("2026-10-16T00:00:00.000Z");
    covering.records.push({
      stream: "activity",
      data: { id: "activity-older", day: "2025-01-01", score: 50 },
    });
    covering.completion.streams[2]!.recordCount = 2;
    expect((await post(covering)).status).toBe(200);
    expect(await (await requirements()).json()).toMatchObject({
      since: "2025-01-01",
    });
    const refresh = structuredClone(covering);
    refresh.collectedAt = "2026-10-17T00:00:00.000Z";
    refresh.records[2]!.data.score = 81;
    expect((await post(refresh)).status).toBe(200);
    expect(
      (await storage.readEnvelope("oura.activity", oldTime)).data,
    ).toMatchObject({ days: [{ score: 60 }, { score: 50 }] });
  });
});

describe("fresh complete Oura replacement", () => {
  it.each(["fewer", "disjoint", "empty"] as const)(
    "replaces current data with %s records and retains historical versions across restart",
    async (variant) => {
      const persistence = createMemoryPsLitePersistence();
      const storage = await createPersistentPsLiteStorage(
        { kind: "indexeddb" },
        persistence,
      );
      const { post, runtime } = await setup(true, storage);
      const body = input();
      if (variant === "disjoint") {
        for (const record of body.records)
          record.data.id = record.stream + "-fresh";
      }
      if (variant === "empty") {
        body.records = [];
        for (const proof of body.completion.streams) proof.recordCount = 0;
      }
      const response = await post(body);
      expect(response.status, await response.clone().text()).toBe(200);
      const result = await response.json();
      expect(
        result.receipts
          .map((receipt: { scope: string }) => receipt.scope)
          .sort(),
      ).toEqual(streams.map((stream) => "oura." + stream).sort());
      for (const stream of streams) {
        const read = await runtime.fetch(
          new Request("https://ps.test/v1/data/oura." + stream, {
            headers: { authorization: "Bearer owner" },
          }),
        );
        expect(read.status).toBe(200);
        const envelope = await read.json();
        const rows =
          stream === "sleep" ? envelope.data.dailyScores : envelope.data.days;
        expect(rows.map((row: { id: string }) => row.id)).toEqual(
          variant === "empty"
            ? []
            : [stream + (variant === "disjoint" ? "-fresh" : "-1")],
        );
      }
      const reloaded = await createPersistentPsLiteStorage(
        { kind: "indexeddb" },
        persistence,
      );
      expect(
        (await reloaded.readEnvelope("oura.activity", oldTime)).data,
      ).toMatchObject({
        days: [
          { id: "activity-1", score: 60 },
          { id: "activity-older", score: 50 },
        ],
      });
      for (const stream of streams) {
        const head = reloaded.findEntry({ scope: "oura." + stream });
        expect(head).toBeDefined();
        const envelope = await reloaded.readEnvelope(
          "oura." + stream,
          head!.collectedAt,
        );
        const data = envelope.data as {
          dailyScores?: { id: string }[];
          days?: { id: string }[];
        };
        const rows = stream === "sleep" ? data.dailyScores : data.days;
        expect(rows?.map((row) => row.id)).toEqual(
          variant === "empty"
            ? []
            : [stream + (variant === "disjoint" ? "-fresh" : "-1")],
        );
      }
    },
  );
});

/** January history is the required boundary: a later since-only window would drop it. */
async function seedJanuaryHistory(
  storage: ReturnType<typeof createMemoryPsLiteStorage>,
) {
  const legacy = {
    "oura.sleep": {
      dailyScores: [{ id: "sleep-january", day: "2026-01-01", score: 70 }],
    },
    "oura.readiness": {
      days: [{ id: "readiness-january", day: "2026-01-01", score: 70 }],
    },
    "oura.activity": {
      days: [{ id: "activity-january", day: "2026-01-01", score: 70 }],
    },
  };
  for (const [scope, data] of Object.entries(legacy)) {
    const write = await storage.writeEnvelope(
      createDataFileEnvelope(scope, oldTime, data),
    );
    await storage.insertEntry({
      fileId: `legacy-${scope}`,
      path: write.relativePath,
      scope,
      collectedAt: oldTime,
      sizeBytes: write.sizeBytes,
    });
  }
}

function sinceOnly(
  body: OuraBrowserImportInput,
  since: string,
): OuraBrowserImportInput {
  return {
    ...body,
    selection: {
      streams: streams.map((name) => ({ name, time_range: { since } })),
    },
  };
}

function emptied(body: OuraBrowserImportInput): OuraBrowserImportInput {
  return {
    ...body,
    records: [],
    completion: {
      streams: body.completion.streams.map((proof) => ({
        ...proof,
        recordCount: 0,
      })),
    },
  };
}

async function requiredSince(runtime: ReturnType<typeof createPsLiteRuntime>) {
  const response = await runtime.fetch(
    new Request("https://ps.test/v1/import/oura-browser/requirements", {
      headers: { authorization: "Bearer owner" },
    }),
  );
  expect(response.status).toBe(200);
  return (await response.json()).since as string | null;
}

/** Heads, version counts, and owner and builder reads: what a refusal must leave untouched. */
async function stateOf(
  storage: ReturnType<typeof createMemoryPsLiteStorage>,
  runtime: ReturnType<typeof createPsLiteRuntime>,
) {
  const served = [];
  for (const stream of streams) {
    for (const token of ["owner", "builder"]) {
      const response = await runtime.fetch(
        new Request(`https://ps.test/v1/data/oura.${stream}?grantId=openpet`, {
          headers: { authorization: `Bearer ${token}` },
        }),
      );
      served.push({ status: response.status, body: await response.json() });
    }
  }
  return {
    heads: streams.map((stream) =>
      storage.findEntry({ scope: `oura.${stream}` }),
    ),
    versions: streams.map((stream) => storage.countVersions(`oura.${stream}`)),
    served,
  };
}

describe("Oura required history boundary", () => {
  it.each([
    ["nonempty", sinceOnly(input(), "2026-10-01")],
    ["empty", sinceOnly(emptied(input()), "2026-10-01")],
  ])(
    "refuses a since-only October %s batch over January history before any write",
    async (_name, body) => {
      const storage = createMemoryPsLiteStorage();
      await seedJanuaryHistory(storage);
      const { post, runtime } = runtimeFor(storage);
      expect(await requiredSince(runtime)).toBe("2026-01-01");
      const before = await stateOf(storage, runtime);
      expect(before.served.map((read) => read.status)).toEqual(
        Array(6).fill(200),
      );
      const response = await post(body);
      expect(response.status).toBe(409);
      expect(await response.json()).toEqual({
        ok: false,
        reason: "selection_narrower_than_history",
      });
      expect(await stateOf(storage, runtime)).toEqual(before);
    },
  );

  it("runs no commit, sync trigger, derivative hook or receipt for a refused October batch", async () => {
    const storage = createMemoryPsLiteStorage();
    await seedJanuaryHistory(storage);
    const beforeCommit = vi.fn().mockResolvedValue(undefined);
    const trigger = vi.fn().mockResolvedValue(undefined);
    const onDataWritten = vi.fn();
    const result = await importOuraBrowserRecords(
      storage,
      sinceOnly(input(), "2026-10-01"),
      {
        beforeCommit,
        onDataWritten,
        syncManager: { trigger, getStatus: vi.fn() } as never,
      },
    );
    expect(result).toEqual({
      ok: false,
      reason: "selection_narrower_than_history",
    });
    expect(beforeCommit).not.toHaveBeenCalled();
    expect(onDataWritten).not.toHaveBeenCalled();
    expect(trigger).not.toHaveBeenCalled();
    expect(storage.countVersions("oura.activity")).toBe(1);
  });

  it("reads January history under the lock, so a window prepared before it became current is refused", async () => {
    const storage = createMemoryPsLiteStorage();
    const { post, runtime } = runtimeFor(storage);
    expect(await requiredSince(runtime)).toBeNull();
    const prepared = sinceOnly(input("2026-10-16T00:00:00.000Z"), "2026-10-01");
    const january = input("2026-10-15T00:00:00.000Z", "2026-01-01");
    expect((await post(january)).status).toBe(200);
    expect(await requiredSince(runtime)).toBe("2026-01-01");
    const before = await stateOf(storage, runtime);
    const response = await post(prepared);
    expect(response.status).toBe(409);
    expect(await response.json()).toEqual({
      ok: false,
      reason: "selection_narrower_than_history",
    });
    expect(await stateOf(storage, runtime)).toEqual(before);
  });

  it("admits a since-only October batch when no January history exists", async () => {
    const storage = createMemoryPsLiteStorage();
    const { post, runtime } = runtimeFor(storage);
    expect(await requiredSince(runtime)).toBeNull();
    const response = await post(sinceOnly(input(), "2026-10-01"));
    expect(response.status, await response.clone().text()).toBe(200);
  });

  it("admits a since-only batch that starts exactly at the required January boundary", async () => {
    const storage = createMemoryPsLiteStorage();
    await seedJanuaryHistory(storage);
    const { post } = runtimeFor(storage);
    const response = await post(sinceOnly(input(), "2026-01-01"));
    expect(response.status, await response.clone().text()).toBe(200);
  });

  it.each([
    ["nonempty", input()],
    ["empty", emptied(input())],
  ])(
    "keeps eligible complete unrestricted %s replacement over January history",
    async (_name, body) => {
      const storage = createMemoryPsLiteStorage();
      await seedJanuaryHistory(storage);
      const { post } = runtimeFor(storage);
      const response = await post(body);
      expect(response.status, await response.clone().text()).toBe(200);
      expect(storage.countVersions("oura.activity")).toBe(2);
      const januaryFile = await storage.readEnvelope("oura.activity", oldTime);
      expect(januaryFile.data).toMatchObject({
        days: [{ id: "activity-january" }],
      });
    },
  );

  it("refuses an artifact-bound batch whose START is unproven while January history is current", async () => {
    const storage = createMemoryPsLiteStorage();
    await seedJanuaryHistory(storage);
    const beforeCommit = vi.fn().mockResolvedValue(undefined);
    const unproven = {
      ...input("2026-10-16T00:00:00.000Z"),
      selection: undefined,
    };
    expect(
      await importOuraBrowserRecords(storage, unproven, {
        artifactBoundNativeCompletion: true,
        beforeCommit,
      }),
    ).toEqual({ ok: false, reason: "native_start_unproven" });
    // A native batch that carries its START selection is checked like any takeover.
    expect(
      await importOuraBrowserRecords(
        storage,
        sinceOnly(input("2026-10-16T00:00:00.000Z"), "2026-10-01"),
        { artifactBoundNativeCompletion: true, beforeCommit },
      ),
    ).toEqual({ ok: false, reason: "selection_narrower_than_history" });
    expect(beforeCommit).not.toHaveBeenCalled();
    expect(storage.countVersions("oura.activity")).toBe(1);
  });

  it("admits an artifact-bound batch when no January history exists", async () => {
    const storage = createMemoryPsLiteStorage();
    expect(
      await importOuraBrowserRecords(
        storage,
        { ...input(), selection: undefined },
        { artifactBoundNativeCompletion: true },
      ),
    ).toMatchObject({ ok: true });
  });
});
