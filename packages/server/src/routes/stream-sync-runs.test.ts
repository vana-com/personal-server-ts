/**
 * Run intake over HTTP (contract v2 §2): the route over the real adapter and
 * the real writer, with the in-memory exclusive-version registry and local
 * storage. Status codes are §2.6.
 */

import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { Hono } from "hono";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import { ProtocolError } from "@opendatalabs/personal-server-ts-core/errors";
import {
  createStreamSyncIntake,
  type IntakeDeclarations,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import {
  OWNER,
  activateControl,
  createOracleEnv,
  deleteConnection,
  finishedOutcome,
  artifactFor,
  freshConnector,
  readStream,
  resolveTestArtifact,
  startLocalStorage,
  type OracleEnv,
} from "../stream-sync/oracle.test-utils.js";
import { canonicalJson } from "@opendatalabs/personal-server-ts-stream-sync";
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

let storage: Awaited<ReturnType<typeof startLocalStorage>>;
let env: OracleEnv;

beforeAll(async () => {
  storage = await startLocalStorage();
  env = await createOracleEnv({
    surface: "full",
    backend: "fake",
    storageUrl: storage.url,
  });
});
afterAll(async () => {
  await env.cleanup();
  await storage.close();
});

async function build(device: string) {
  const writer = await env.writer(device);
  const intake = createStreamSyncIntake({
    writer,
    resolveArtifact: resolveTestArtifact,
  });
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
  return { writer, call };
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
    const { writer, call } = await build("route-flow");
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
      accepted: 1,
      deletesSkipped: 1,
    });
    const ended = await call("POST", "r1/end", {
      outcome: "succeeded",
      coveredStreams: ["items"],
      checkpointCandidate: { items: "c1" },
      lastBatch: 0,
    });
    expect(ended.status).toBe(200);
    expect(await ended.json()).toMatchObject({ result: "queued" });
    await writer.cycle();
    expect(finishedOutcome(await writer.status(), "r1")?.outcome?.kind).toBe(
      "checkpointed",
    );
    const view = await readStream(
      env.registry,
      env.blobs,
      body.connector,
      "",
      "items",
    );
    expect([
      ...(view as { records: Map<string, unknown> }).records.keys(),
    ]).toEqual(["a"]);
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
    const { call } = await build("route-stopped");
    const body = beginBody();
    const connector = body.connector;
    await activateControl(env.registry, connector, "");
    await deleteConnection(env.registry, connector, "", []);
    const res = await call("PUT", "stopped-1", body);
    expect(res.status).toBe(409);
    expect(await res.json()).toMatchObject({ error: "connection_stopped" });
  });

  it("takes a 30 MiB record through the batch route and reads it back byte-exact", async () => {
    const { writer, call } = await build("route-30mib");
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
    await writer.cycle();
    expect(finishedOutcome(await writer.status(), "big1")?.outcome?.kind).toBe(
      "checkpointed",
    );
    const view = await readStream(
      env.registry,
      env.blobs,
      body.connector,
      "",
      "items",
    );
    if (!view || view === "tombstoned") throw new Error("stream missing");
    expect([...view.records.keys()].sort()).toEqual(["huge", "small", "tail"]);
    expect(canonicalJson(view.records.get("huge"))).toBe(canonicalJson(huge));
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
