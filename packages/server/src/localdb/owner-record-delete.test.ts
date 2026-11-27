/**
 * spec-core §8 "Delete a record" on a switched (stream-sync) account: the
 * owner DELETE is written as a run through the intake and publication path a
 * connector's explicit delete uses, so the record leaves every device of the
 * owner (§9 RS item 1; core localdb/owner-delete.ts).
 */
import { afterEach, expect, it, vi } from "vitest";
import { Hono } from "hono";
import {
  createLocalSync,
  openLocalDb,
  connectionQueue,
  type ConnectionLink,
  type OwnerRecordDeleteResult,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
import {
  createMemoryStreamSyncRegistry,
  createMemoryStreamSyncBlobs,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import { endRequest } from "@opendatalabs/personal-server-ts-core/test-utils";
import { createFixtureAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth.test-utils";
import {
  createMemoryRecordStore,
  createStreamDeclarationRegistry,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { pdppRecordsRoutes } from "../routes/pdpp-records.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});
const owner = `0x${"11".repeat(20)}` as const;
const connectionId = "pdpp.fixture~";
const HANDLE = "handle";
const link: ConnectionLink = (instance, stream) =>
  instance === HANDLE && stream === "items"
    ? { connector: "fixture", namespace: "" }
    : null;

async function device(
  registry: ReturnType<typeof createMemoryStreamSyncRegistry>,
  blobs: ReturnType<typeof createMemoryStreamSyncBlobs>,
  deviceId: string,
  clock: { now: number },
  semantics: "mutable_state" | "append_only" = "mutable_state",
) {
  const db = await openLocalDb(openBetterSqlite3(":memory:"), {
    owner,
    network: "test",
    deviceId,
  });
  drivers.push(db);
  let op = 0;
  const sync = createLocalSync(
    {
      db,
      queue: connectionQueue(),
      registry,
      blobs,
      ownerAddress: owner,
      keys: {
        namespaceHmac: async () => new Uint8Array(32),
        encrypt: async (_s, b) => b,
        encryptPart: async (_s, b) => b,
        decrypt: async (_s, b) => b,
      },
      signer: { signAddData: async () => "0x00" },
      logger: { info: vi.fn(), warn: vi.fn() },
      now: () => clock.now,
      newOp: () => `${deviceId}-${++op}`,
    },
    {
      resolveArtifact: (digest) =>
        digest === "fixture-digest"
          ? {
              connector: "fixture",
              version: "1",
              streams: [
                {
                  name: "items",
                  semantics,
                  primaryKey: ["id"],
                  coverageStrategy: "checkpoint_window",
                },
              ],
            }
          : null,
    },
  );
  const keys = async () =>
    (
      await sync.query.listRecords({
        connectionId,
        stream: "items",
        limit: 100,
      })
    ).records
      .map((r) => r.recordKey)
      .sort();
  return { db, sync, keys };
}

// spec-core §4 "Stream semantics", `append_only`: "Explicit deletion is
// permitted": the same delete works on both semantics.
it.each(["mutable_state", "append_only"] as const)(
  "an owner DELETE on a switched account (%s) runs a delete, answers 204, and the record leaves every device",
  async (semantics) => {
    const registry = createMemoryStreamSyncRegistry();
    const blobs = createMemoryStreamSyncBlobs();
    const clock = { now: Date.parse("2026-09-01T00:00:00Z") };
    const a = await device(registry, blobs, "a", clock, semantics);
    const b = await device(registry, blobs, "b", clock, semantics);
    // A connector run on device a, published and applied on device b.
    await a.sync.intake.begin("seed", {
      connector: "fixture",
      artifactDigest: "fixture-digest",
      join: true,
      wantFull: true,
      owner: { address: owner, leaseId: null },
    });
    await a.sync.intake.batch("seed", {
      batch: 0,
      records: ["keep", "gone"].map((id) => ({
        stream: "items",
        data: { id, name: id },
      })),
    });
    await a.sync.intake.end(
      "seed",
      endRequest({
        lastBatch: 0,
        live: ["items"],
        checkpoints: { items: { at: 1 } },
      }),
    );
    expect(
      (await a.sync.cycle()).connections.every((c) => c.error === null),
    ).toBe(true);
    await b.sync.apply();
    expect(await b.keys()).toEqual(["gone", "keep"]);

    const results: OwnerRecordDeleteResult[] = [];
    const digestFor = vi.fn((connector: string) =>
      connector === "fixture" ? "fixture-digest" : undefined,
    );
    const app = new Hono();
    app.route(
      "/v1",
      pdppRecordsRoutes({
        accountStorageMode: { owner, read: () => "switched" },
        store: createMemoryRecordStore(),
        recordQuery: a.sync.recordsFor(link),
        recordHistory: (stream, options) =>
          a.sync.changesFor(link)(stream, options),
        switchedDelete: async (input) => {
          const result = await a.sync.ownerRecordDelete(link, digestFor)(input);
          results.push(result);
          return result;
        },
        auth: createFixtureAuthorizationService({
          owner: {
            active: true,
            tokenKind: "owner",
            subjectId: owner,
            instanceIds: [HANDLE],
          },
          client: {
            active: true,
            tokenKind: "client",
            subjectId: "s",
            clientId: "c",
            grant: {
              version: "0.1.0",
              grant_id: "g",
              issued_at: "2026-01-01T00:00:00Z",
              subject: { id: "s" },
              client: { client_id: "c" },
              source: { kind: "connector", id: "src" },
              source_declaration: { version: "1" },
              purpose_code: "p",
              access_mode: "continuous",
              streams: [
                {
                  name: "items",
                  instance_ids: [HANDLE],
                  fields: ["id"],
                  required_fields: ["id"],
                },
              ],
            },
          },
        }),
        declarations: createStreamDeclarationRegistry([
          {
            name: "items",
            semantics,
            primaryKey: ["id"],
            requiredFields: ["id"],
          },
        ]),
        instancesForSubject: () => [HANDLE],
      }),
    );
    const call = (path: string, method = "GET", token = "owner") =>
      app.request(`/v1${path}`, {
        method,
        headers: { Authorization: `Bearer ${token}` },
      });

    const start = await (
      await call("/streams/items/records?changes_since=beginning")
    ).json();
    expect(start.data.map((r: { id: string }) => r.id).sort()).toEqual([
      "gone",
      "keep",
    ]);

    // Owner-token only; an unknown record is 404 and writes no run.
    expect(
      (await call("/streams/items/records/gone", "DELETE", "client")).status,
    ).toBe(401);
    expect((await call("/streams/items/records/nope", "DELETE")).status).toBe(
      404,
    );
    expect(results).toEqual([{ kind: "not_found" }]);

    clock.now += 60_000;
    const removed = await call("/streams/items/records/gone", "DELETE");
    expect(removed.status).toBe(204);
    expect(results.at(-1)).toMatchObject({ kind: "deleted" });
    expect(digestFor).toHaveBeenCalledWith("fixture", "1");

    // Gone from get, list and the next change session on this device.
    expect((await call("/streams/items/records/gone")).status).toBe(404);
    const list = await (await call("/streams/items/records")).json();
    expect(list.data.map((r: { id: string }) => r.id)).toEqual(["keep"]);
    const next = await (
      await call(
        `/streams/items/records?changes_since=${encodeURIComponent(start.next_changes_since)}`,
      )
    ).json();
    expect(next.data, JSON.stringify(next)).toEqual([
      {
        object: "record",
        id: "gone",
        instance_id: HANDLE,
        stream: "items",
        deleted: true,
        removal: "deleted",
        deleted_at: new Date(clock.now).toISOString(),
        emitted_at: new Date(clock.now).toISOString(),
      },
    ]);

    // The run is the connector's own publication path: it is pending until
    // the next cycle publishes it, then every device applies the tombstone.
    const runId = (results.at(-1) as { runId: string }).runId;
    expect((await a.sync.intake.publicationStatus(runId)).state).toBe(
      "pending",
    );
    expect(
      (await a.sync.cycle()).connections.every((c) => c.error === null),
    ).toBe(true);
    expect((await a.sync.intake.publicationStatus(runId)).state).toBe(
      "published",
    );
    await b.sync.apply();
    expect(await b.keys()).toEqual(["keep"]);
    // The connector's own cursor is untouched.
    expect(await a.sync.intake.checkpoint!("fixture")).toMatchObject({
      streams: { items: { state: { at: 1 } } },
    });
  },
);
