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
  createMemoryStreamSyncBlobs,
  type IntakeDeclarations,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import { canonicalJson } from "@opendatalabs/personal-server-ts-stream-sync";
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
async function build(device: string) {
  const registry = createMemoryStreamSyncRegistry(),
    blobs = createMemoryStreamSyncBlobs();
  const open = async (name: string) => {
    const db = await openLocalDb(openBetterSqlite3(":memory:"), {
      owner: OWNER,
      network: "test",
      deviceId: name,
    });
    drivers.push(db);
    return createLocalSync(
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
        declaredStreams: () => ["items"],
        olderVersionReads: () => true,
      },
    );
  };
  const sync = await open(device);
  const intake = sync.intake;
  const read = async (connector: string) => {
    const peer = await open(device + "-peer");
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
  return { sync, call, read };
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
    const ended = await call("POST", "r1/end", {
      outcome: "succeeded",
      coveredStreams: ["items"],
      checkpointCandidate: { items: "c1" },
      lastBatch: 0,
    });
    expect(ended.status).toBe(200);
    expect(await ended.json()).toMatchObject({ result: "queued" });
    expect(
      (await sync.cycle()).connections
        .flatMap((c) => c.published)
        .map((r) => r.outcome),
    ).toEqual(["published"]);
    expect([...(await read(body.connector)).keys()]).toEqual(["a"]);
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

  it("takes a 30 MiB record through the batch route and reads it back byte-exact", async () => {
    const { sync, call, read } = await build("route-30mib");
    const body = beginBody();
    await call("PUT", "big1", body);
    const huge = { id: "huge", pad: 'é"\\}{'.repeat(5 * 1024 * 1024) };
    expect(JSON.stringify(huge).length).toBeGreaterThan(30 * 1024 * 1024);
    const sent = await call("POST", "big1/batches", {
      batch: 0,
      records: [
        { stream: "items", data: { id: "small", n: 1 } },
        { stream: "items", data: huge },
        { stream: "items", data: { id: "tail", n: 2 } },
      ],
    });
    expect(sent.status).toBe(200);
    expect(await sent.json()).toMatchObject({ accepted: 3, applied: true });
    const ended = await call("POST", "big1/end", {
      outcome: "succeeded",
      coveredStreams: ["items"],
      checkpointCandidate: { items: "c1" },
      lastBatch: 0,
    });
    expect(ended.status).toBe(200);
    expect(
      (await sync.cycle()).connections
        .flatMap((c) => c.published)
        .map((r) => r.outcome),
    ).toEqual(["published"]);
    const view = await read(body.connector);
    expect([...view.keys()].sort()).toEqual(["huge", "small", "tail"]);
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
