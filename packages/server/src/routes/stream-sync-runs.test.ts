/**
 * Run intake over HTTP (contract v2 §2): the route over the real adapter and
 * the real SQLite intake/apply/publish owners and exclusive-version registry. Status codes are §2.6.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { Hono } from "hono";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import { ProtocolError } from "@opendatalabs/personal-server-ts-core/errors";
import {
  createLocalSync,
  openLocalDb,
  connectionQueue,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
import {
  createMemoryStreamSyncRegistry,
  validateRawEnd,
  createMemoryStreamSyncBlobs,
  type IntakeDeclarations,
  RunIntakeError,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import { canonicalJson } from "@opendatalabs/personal-server-ts-stream-sync";
import { endRequest } from "@opendatalabs/personal-server-ts-core/test-utils";
import { openBetterSqlite3 } from "../localdb/better-sqlite3-driver.js";
import {
  MAX_BATCH_REQUEST_BYTES,
  streamSyncRunsRoutes,
} from "./stream-sync-runs.js";

const TOKEN = "runs-route-test-token";
const DECLARATIONS: Omit<IntakeDeclarations, "connector"> = {
  version: "1.0.0",
  streams: [{ name: "items", semantics: "mutable_state", primaryKey: ["id"] }],
};
const T0 = Date.UTC(2026, 10, 1);

const OWNER = `0x${"12".repeat(20)}` as const;
const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});
let nextConnector = 0;
const declarations = new Map<string, IntakeDeclarations>();
const freshConnector = (_label: string) => `fixture-${++nextConnector}`;
const artifactFor = (
  connector: string,
  shape: Omit<IntakeDeclarations, "connector">,
) => {
  const digest = `fixture-${connector}`;
  declarations.set(digest, { connector, ...shape });
  return digest;
};
async function build(
  device: string,
  shared?: {
    registry: ReturnType<typeof createMemoryStreamSyncRegistry>;
    blobs: ReturnType<typeof createMemoryStreamSyncBlobs>;
  },
) {
  const registry = shared?.registry ?? createMemoryStreamSyncRegistry(),
    blobs = shared?.blobs ?? createMemoryStreamSyncBlobs();
  const open = async (name: string) => {
    const db = await openLocalDb(openBetterSqlite3(":memory:"), {
      owner: OWNER,
      network: "test",
      deviceId: name,
    });
    drivers.push(db);
    const sync = createLocalSync(
      {
        db,
        queue: connectionQueue(),
        ownerAddress: OWNER,
        registry,
        blobs,
        keys: {
          namespaceHmac: async () => new Uint8Array(32),
          encrypt: async (_s, b) => b,
          encryptPart: async (_s, b) => b,
          decrypt: async (_s, b) => b,
        },
        signer: { signAddData: async () => "0x00" },
        logger: { info: vi.fn(), warn: vi.fn() },
        now: () => T0,
        newOp: () => crypto.randomUUID(),
      },
      {
        resolveArtifact: (d) => declarations.get(d) ?? null,
      },
    );
    return { sync, db };
  };
  const { sync, db } = await open(device);
  const intake = sync.intake;
  const read = async (connector: string) => {
    const { sync: peer } = await open(device + "-peer");
    await peer.apply();
    const rows = new Map<string, unknown>();
    for await (const record of peer.query.streamRecords(
      `pdpp.${connector}~`,
      "items",
    ))
      rows.set(record.recordKey, JSON.parse(record.body));
    return rows;
  };
  const outer = new Hono();
  outer.route(
    "/v1/stream-sync/runs",
    streamSyncRunsRoutes({
      serverOrigin: "http://127.0.0.1",
      serverOwner: OWNER,
      gateway: {
        getServer: vi.fn().mockResolvedValue(null),
      } as unknown as GatewayClient,
      accessToken: TOKEN,
      intake,
    }),
  );
  outer.onError((err, c) =>
    err instanceof ProtocolError
      ? c.json(err.toJSON(), err.code as 401)
      : c.json({ error: String(err) }, 500),
  );
  const call = (
    method: "PUT" | "POST",
    path: string,
    json: unknown,
    token: string | null = TOKEN,
    headers: Record<string, string> = {},
  ) =>
    outer.request(`/v1/stream-sync/runs/${path}`, {
      method,
      headers: {
        "content-type": "application/json",
        ...headers,
        ...(token ? { authorization: `Bearer ${token}` } : {}),
      },
      body: typeof json === "string" ? json : JSON.stringify(json),
    });
  return { sync, call, read, db, shared: { registry, blobs } };
}

const beginBody = (extra: Record<string, unknown> = {}) => {
  const connector = freshConnector("http");
  return {
    connector,
    artifactDigest: artifactFor(connector, DECLARATIONS),
    owner: { address: OWNER, leaseId: null },
    observedAt: T0,
    ...extra,
  };
};

describe("stream-sync run intake route", () => {
  it("takes a run from begin to a published, readable stream", async () => {
    const { sync, call, read } = await build("route-flow");
    const body = beginBody();
    const begun = await call("PUT", "r1", body);
    expect(begun.status).toBe(200);
    expect(await begun.json()).toMatchObject({
      status: "collecting",
      start: { collection_mode: "full_refresh", state: null },
    });
    const batch = await call("POST", "r1/batches", {
      batch: 0,
      records: [
        { stream: "items", data: { id: "a", n: 1 } },
        { stream: "items", op: "delete", data: { id: "x" } },
      ],
    });
    expect(batch.status).toBe(200);
    expect(await batch.json()).toMatchObject({
      accepted: 2,
      deletesSkipped: 0,
    });
    const ended = await call(
      "POST",
      "r1/end",
      endRequest({
        lastBatch: 0,
        live: ["items"],
        deleted: ["items"],
        checkpoints: { items: "c1" },
      }),
    );
    expect(ended.status).toBe(200);
    expect(await ended.json()).toEqual({
      result: "queued",
      stuck: false,
      updateRequired: false,
      outcome: "succeeded",
      coveredStreams: ["items"],
      provenFullStreams: [],
      unconfirmed: false,
    });
    // The early publish writes the log; the cycle's own pass finds nothing left.
    expect(
      (await sync.cycle()).connections
        .flatMap((c) => c.published)
        .map((r) => r.outcome),
    ).toEqual(["published", "noop"]);
    expect([...(await read(body.connector)).keys()]).toEqual(["a"]);
  });

  it("replays local end acknowledgements and exposes the retry-basis refusal", async () => {
    const { sync, call } = await build("route-receipts");
    const body = beginBody({ expectedControlVersion: 0 });
    expect((await call("PUT", "receipt", body)).status).toBe(200);
    await call("POST", "receipt/batches", {
      batch: 0,
      records: [{ stream: "items", data: { id: "kept" } }],
    });
    const end = endRequest({ lastBatch: 0, live: ["items"] });
    const first = await call("POST", "receipt/end", end);
    expect(first.status).toBe(200);
    const receipt = await first.json();
    expect(receipt.result).toBe("queued");
    await sync.cycle();
    const replay = await call("PUT", "receipt", body);
    expect(replay.status).toBe(200);
    expect(await replay.json()).toMatchObject({ status: "ended", receipt });
    expect(await (await call("POST", "receipt/end", end)).json()).toEqual(
      receipt,
    );
    const stale = await call("PUT", "new-retry", { ...body, connect: true });
    expect(stale.status).toBe(409);
    expect((await stale.json()).error).toBe("control_basis_mismatch");
  });

  it("answers each error with its contract status and name (§2.6)", async () => {
    const { call } = await build("route-errors");
    const unknown = await call(
      "PUT",
      "e1",
      beginBody({ artifactDigest: "sha256:" + "00".repeat(32) }),
    );
    expect(unknown.status).toBe(422);
    expect(await unknown.json()).toMatchObject({ error: "unknown_artifact" });

    const restricted = await call(
      "PUT",
      "e2",
      beginBody({ streams: [{ name: "items", fields: ["id"] }] }),
    );
    expect(restricted.status).toBe(422);
    expect(await restricted.json()).toMatchObject({
      error: "restricted_scope_unsupported",
    });

    expect((await call("PUT", "e3", "{not json")).status).toBe(400);
    expect(
      (await call("PUT", "e3", beginBody({ observedAt: "yesterday" }))).status,
    ).toBe(400);

    await call("PUT", "e4", beginBody());
    const gap = await call("POST", "e4/batches", { batch: 2, records: [] });
    expect(gap.status).toBe(409);
    expect(await gap.json()).toMatchObject({
      error: "batch_gap",
      nextBatch: 0,
    });

    // The old outcome body is not an end body.
    const old = await call("POST", "e4/end", {
      outcome: "succeeded",
      coveredStreams: [],
      lastBatch: -1,
    });
    expect(old.status).toBe(400);
    expect(await old.json()).toMatchObject({ error: "invalid_request" });

    const aborted = await call("POST", "e4/abort", { reason: "cancelled" });
    expect(aborted.status).toBe(200);
    const late = await call("POST", "e4/batches", { batch: 0, records: [] });
    expect(late.status).toBe(410);
    expect(await late.json()).toMatchObject({ error: "gone" });
    expect((await call("POST", "e4/abort", { reason: "nope" })).status).toBe(
      400,
    );

    const mismatch = await call(
      "PUT",
      "e5",
      beginBody({ owner: { address: "0x" + "11".repeat(20), leaseId: null } }),
    );
    expect(mismatch.status).toBe(409);
    expect(await mismatch.json()).toMatchObject({ error: "owner_mismatch" });
  });

  it("answers a scheduled begin of a deleted connection 409 connection_stopped over HTTP (review P2-3)", async () => {
    const { sync, call } = await build("route-stopped");
    const body = beginBody();
    const connector = body.connector;
    await sync.intake.begin("delete-setup", body);
    await sync.deleter.requestConnectionDelete(connector);
    expect(await sync.deleter.resumeDeletes()).toEqual([]);
    const res = await call("PUT", "stopped-1", body);
    expect(res.status).toBe(409);
    expect(await res.json()).toMatchObject({ error: "connection_stopped" });
  });

  it("takes an 8 MiB record through the batch route and reads it back byte-exact", async () => {
    const { sync, call, read } = await build("route-8mib");
    const body = beginBody();
    await call("PUT", "big1", body);
    const big = { id: "big", pad: 'é"\\}{'.repeat(1_300_000) };
    expect(JSON.stringify(big).length).toBeGreaterThan(8 * 1024 * 1024);
    const sent = await call("POST", "big1/batches", {
      batch: 0,
      records: [
        { stream: "items", data: { id: "small", n: 1 } },
        { stream: "items", data: big },
        { stream: "items", data: { id: "tail", n: 2 } },
      ],
    });
    expect(sent.status).toBe(200);
    expect(await sent.json()).toMatchObject({ accepted: 3, applied: true });
    const ended = await call(
      "POST",
      "big1/end",
      endRequest({
        lastBatch: 0,
        live: ["items"],
        checkpoints: { items: "c1" },
      }),
    );
    expect(ended.status).toBe(200);
    expect(
      (await sync.cycle()).connections.flatMap((c) => c.error ?? []),
    ).toEqual([]);
    const view = await read(body.connector);
    expect([...view.keys()].sort()).toEqual(["big", "small", "tail"]);
    expect(canonicalJson(view.get("big"))).toBe(canonicalJson(big));
  }, 120_000);

  it("takes a 30 MiB record through the batch route, and the log carries it out of line", async () => {
    const { sync, call, read } = await build("route-30mib");
    const body = beginBody();
    await call("PUT", "big2", body);
    const huge = { id: "huge", pad: 'é"\\}{'.repeat(5 * 1024 * 1024) };
    expect(JSON.stringify(huge).length).toBeGreaterThan(30 * 1024 * 1024);
    const sent = await call("POST", "big2/batches", {
      batch: 0,
      records: [{ stream: "items", data: huge }],
    });
    expect(sent.status).toBe(200);
    expect(await sent.json()).toMatchObject({ accepted: 1, applied: true });
    const ended = await call(
      "POST",
      "big2/end",
      endRequest({
        lastBatch: 0,
        live: ["items"],
        checkpoints: { items: "c1" },
      }),
    );
    expect(ended.status).toBe(200);
    // One segment holds at most 16 MiB (stream-sync log.ts) and a record is
    // never split across segments, so the body goes out of line.
    expect(
      (await sync.cycle()).connections.map((c) => [
        c.published.length > 0,
        c.error,
      ]),
    ).toEqual([[true, null]]);
    const view = await read(body.connector);
    expect(canonicalJson(view.get("huge"))).toBe(canonicalJson(huge));
  }, 120_000);

  it("refuses a request that declares a body over the ceiling", async () => {
    const { call } = await build("route-ceiling");
    await call("PUT", "c1", beginBody());
    const res = await call("POST", "c1/batches", "{}", TOKEN, {
      "content-length": String(MAX_BATCH_REQUEST_BYTES + 1),
    });
    expect(res.status).toBe(413);
    expect(await res.json()).toMatchObject({ error: "CONTENT_TOO_LARGE" });
  });

  it("refuses a caller that is not the owner", async () => {
    const { call } = await build("route-auth");
    expect((await call("PUT", "a1", beginBody(), null)).status).toBe(401);
    expect((await call("PUT", "a1", beginBody(), "wrong-token")).status).toBe(
      401,
    );
  });
});

describe("join gate over HTTP", () => {
  it("answers a second device 409 join_required until the begin carries join: true", async () => {
    const first = await build("route-join-a");
    const body = beginBody();
    expect((await first.call("PUT", "r1", body)).status).toBe(200);
    await first.call("POST", "r1/batches", {
      batch: 0,
      records: [{ stream: "items", data: { id: "a" } }],
    });
    await first.call(
      "POST",
      "r1/end",
      endRequest({
        lastBatch: 0,
        live: ["items"],
        checkpoints: { items: "c1" },
      }),
    );
    await first.sync.cycle();

    const second = await build("route-join-b", first.shared);
    const refused = await second.call("PUT", "r2", body);
    expect(refused.status).toBe(409);
    expect(await refused.json()).toMatchObject({ error: "join_required" });
    expect(await second.db.query("SELECT 1 FROM runs")).toEqual([]);

    const joined = await second.call("PUT", "r2", { ...body, join: true });
    expect(joined.status).toBe(200);
    expect(await joined.json()).toMatchObject({ status: "collecting" });
  });
});

it("delete_pending exposes only fixed error names", async () => {
  const f = await build("delete-error");
  vi.spyOn(f.sync.intake, "begin").mockRejectedValue(
    new RunIntakeError(
      "delete_pending",
      "delete_pending",
      undefined,
      "https://example.invalid/?token=private-record",
    ),
  );
  const response = await f.call("PUT", "run", beginBody());
  expect(response.status).toBe(409);
  expect(await response.json()).toMatchObject({
    error: "delete_pending",
    lastError: "Error",
  });
});

it.each(["http", "in-process"] as const)(
  "accepts raw DONE on the existing %s entry point and publishes its ordered result",
  async (transport) => {
    const { sync, call, read } = await build(`raw-${transport}`);
    const body = beginBody({ selectedStreams: ["items"] });
    expect((await call("PUT", "raw", body)).status).toBe(200);
    expect(
      (
        await call("POST", "raw/batches", {
          batch: 0,
          records: [
            { stream: "items", data: { id: "a", n: 1 } },
            { stream: "items", op: "delete", data: { id: "a" } },
            { stream: "items", data: { id: "a", n: 2 } },
          ],
        })
      ).status,
    ).toBe(200);
    const raw = validateRawEnd({
      wireDialect: "connector-end-evidence/1",
      lastBatch: 0,
      selectedStreams: ["items"],
      done: { status: "succeeded" },
      errors: [],
      checkpoints: { items: "c1" },
      preflightExcludedStreams: [],
      detailCoverage: {},
      invalidDetailCoverageStreams: [],
      wholeStreamEvidence: [],
    });
    for (const invalid of [
      { ...raw, wireDialect: "unknown" },
      { ...raw, done: null },
      { ...raw, selectedStreams: [] },
      { ...raw, finish: { kind: "certified_failed_done", failedStreams: [] } },
    ])
      expect((await call("POST", "raw/end", invalid)).status).toBe(400);
    expect(
      (await call("POST", "raw/end", { ...raw, lastBatch: -1 })).status,
    ).toBe(409);
    let receipt;
    if (transport === "http") {
      const result = await call("POST", "raw/end", raw);
      expect(result.status).toBe(200);
      receipt = await result.json();
    } else receipt = await sync.intake.end("raw", raw);
    expect(receipt).toMatchObject({
      outcome: "succeeded",
      coveredStreams: ["items"],
      provenFullStreams: [],
      streamStatus: { items: "succeeded" },
    });
    expect(await (await call("POST", "raw/end", raw)).json()).toEqual(receipt);
    await sync.cycle();
    expect([...(await read(body.connector)).values()]).toEqual([
      { id: "a", n: 2 },
    ]);
  },
);

it("rejects obsolete host key inventories", async () => {
  const { call } = await build("raw-inventory");
  expect(
    (await call("PUT", "raw", beginBody({ selectedStreams: ["items"] })))
      .status,
  ).toBe(200);
  const response = await call("POST", "raw/end", {
    wireDialect: "connector-end-evidence/1",
    lastBatch: -1,
    selectedStreams: ["items"],
    done: { status: "succeeded" },
    errors: [],
    records: { items: { liveKeys: [["invented"]] } },
    checkpoints: {},
    preflightExcludedStreams: [],
    detailCoverage: {},
    invalidDetailCoverageStreams: [],
    wholeStreamEvidence: [],
  });
  expect(response.status).toBe(400);
  expect((await response.json()).message).toMatch(
    /derived from durable batches/,
  );
});

it.each(["http", "in-process"] as const)(
  "binds end dialect to explicit begin selection over %s",
  async (transport) => {
    const { sync, call, db } = await build(`dialect-${transport}`);
    const body = beginBody({ connect: true });
    body.artifactDigest = artifactFor(body.connector, {
      ...DECLARATIONS,
      streams: [
        { ...DECLARATIONS.streams[0]!, coverageStrategy: "full_inventory" },
      ],
    });
    expect((await call("PUT", "old", body)).status).toBe(200);
    expect(
      (
        await call("POST", "old/batches", {
          batch: 0,
          records: [{ stream: "items", data: { id: "old" } }],
        })
      ).status,
    ).toBe(200);
    expect(
      (
        await call(
          "POST",
          "old/end",
          endRequest({
            lastBatch: 0,
            live: ["items"],
            checkpoints: { items: "old" },
          }),
        )
      ).status,
    ).toBe(200);
    expect(
      (
        await call("PUT", "selected", {
          ...body,
          connect: false,
          observedAt: T0 + 1,
          wantFull: true,
          selectedStreams: ["items"],
        })
      ).status,
    ).toBe(200);
    // Isolate end admission from the fixture's publication/checkpoint policy.
    await db.batch([
      {
        sql: "UPDATE connections SET checkpoint = ?",
        params: ['{"items":"old"}'],
      },
    ]);
    const records = await db.query("SELECT * FROM records");
    expect(records).toHaveLength(1);
    const checkpoints = await db.query("SELECT checkpoint FROM connections");
    expect(checkpoints).toEqual([{ checkpoint: '{"items":"old"}' }]);
    const forged = endRequest({
      lastBatch: -1,
      streams: ["items"],
      provenFullStreams: ["items"],
      checkpoints: { items: "forged" },
    });
    if (transport === "http") {
      const result = await call("POST", "selected/end", forged);
      expect(result.status).toBe(400);
      expect(await result.json()).toMatchObject({ error: "invalid_request" });
    } else {
      await expect(sync.intake.end("selected", forged)).rejects.toMatchObject({
        code: "invalid_request",
      });
    }
    expect(await db.query("SELECT * FROM records")).toEqual(records);
    expect(await db.query("SELECT checkpoint FROM connections")).toEqual(
      checkpoints,
    );
    expect(
      await db.query(
        "SELECT state,raw_end,end_response FROM runs WHERE run_id='selected'",
      ),
    ).toEqual([{ state: "collecting", raw_end: null, end_response: null }]);
    const raw = validateRawEnd({
      wireDialect: "connector-end-evidence/1",
      lastBatch: -1,
      selectedStreams: ["items"],
      covered: ["items"],
      done: { status: "succeeded", recordsEmitted: 0 },
      errors: [],
      checkpoints: { items: "new" },
      preflightExcludedStreams: [],
      detailCoverage: {},
      invalidDetailCoverageStreams: [],
      wholeStreamEvidence: [
        { stream: "items", report: { considered: 0, covered: 0 } },
      ],
    });
    let receipt;
    if (transport === "http") {
      const result = await call("POST", "selected/end", raw);
      expect(result.status).toBe(200);
      receipt = await result.json();
    } else receipt = await sync.intake.end("selected", raw);
    expect(receipt).toMatchObject({
      outcome: "succeeded",
      coveredStreams: ["items"],
      provenFullStreams: ["items"],
    });
    expect(
      await db.query("SELECT state FROM runs WHERE run_id='selected'"),
    ).toEqual([{ state: "ended" }]);
  },
);
