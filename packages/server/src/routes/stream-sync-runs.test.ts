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
  createOracleEnv,
  finishedOutcome,
  freshConnector,
  readStream,
  startLocalStorage,
  type OracleEnv,
} from "../stream-sync/oracle.test-utils.js";
import { MAX_BATCH_BYTES, streamSyncRunsRoutes } from "./stream-sync-runs.js";

const TOKEN = "runs-route-test-token";
const DIGEST = "sha256:" + "cd".repeat(32);
const DECLARATIONS: IntakeDeclarations = {
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
    resolveArtifact: (digest) => (digest === DIGEST ? DECLARATIONS : null),
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
  ) =>
    outer.request(`/v1/stream-sync/runs/${path}`, {
      method,
      headers: {
        "content-type": "application/json",
        ...(token ? { authorization: `Bearer ${token}` } : {}),
      },
      body: typeof json === "string" ? json : JSON.stringify(json),
    });
  return { writer, call };
}

const beginBody = (extra: Record<string, unknown> = {}) => ({
  connector: freshConnector("http"),
  artifactDigest: DIGEST,
  owner: { address: OWNER, leaseId: null },
  observedAt: T0,
  ...extra,
});

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

  it("refuses a body over the batch cap", async () => {
    const { call } = await build("route-cap");
    await call("PUT", "c1", beginBody());
    const big = JSON.stringify({
      batch: 0,
      records: [
        {
          stream: "items",
          data: { id: "a", pad: "x".repeat(MAX_BATCH_BYTES) },
        },
      ],
    });
    expect((await call("POST", "c1/batches", big)).status).toBe(400);
  });

  it("refuses a caller that is not the owner", async () => {
    const { call } = await build("route-auth");
    expect((await call("PUT", "a1", beginBody(), null)).status).toBe(401);
    expect((await call("PUT", "a1", beginBody(), "wrong-token")).status).toBe(
      401,
    );
  });
});
