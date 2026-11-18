import { afterEach, expect, it, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  connectionQueue,
  openLocalDb,
  type LocalSyncDeps,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
import { createSystemStreamStore } from "../../../core/src/localdb/system-streams.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { remoteFixture } from "./apply-fixture.test-utils.js";

const owner = `0x${"12".repeat(20)}` as const;
const descriptor = {
  connector: "vana-system-access-v1",
  stream: "events",
  version: "1",
  primaryKey: ["eventId"],
  timestampField: "occurredAt",
} as const;
const drivers: SqlDriver[] = [];
const dirs: string[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
  for (const dir of dirs.splice(0))
    await rm(dir, { recursive: true, force: true });
});

async function fixture(path: string) {
  const db = await openLocalDb(openBetterSqlite3(path), {
    owner,
    network: "test",
    deviceId: "fixture",
  });
  drivers.push(db);
  const keys = {
    namespaceHmac: async () => new Uint8Array(32),
    encrypt: async (_s: string, b: Uint8Array) => b,
    encryptPart: async (_s: string, b: Uint8Array) => b,
    decrypt: async (_s: string, b: Uint8Array) => b,
  };
  const remote = await remoteFixture(keys);
  const deps: LocalSyncDeps = {
    db,
    keys,
    registry: remote.registry,
    blobs: remote.storage,
    queue: connectionQueue(),
    ownerAddress: owner,
    signer: { signAddData: async () => "0x00" },
    logger: { info: vi.fn(), warn: vi.fn() },
    now: () => Date.parse("2026-06-01T00:00:00.000Z"),
    newOp: () => crypto.randomUUID(),
  };
  return { db, deps };
}

it.each(["before end", "after end"] as const)(
  "settles the original admitted run after restart %s",
  async (stop) => {
    const dir = await mkdtemp(join(tmpdir(), "system-stream-recovery-"));
    dirs.push(dir);
    const path = join(dir, "data.db");
    const first = await fixture(path);
    const queue = first.deps.queue;
    const producer = createSystemStreamStore(
      {
        ...first.deps,
        queue: {
          async run(id, kind, work) {
            if (
              stop === "before end" &&
              kind === "end" &&
              (
                await first.db.query(
                  "SELECT 1 FROM runs WHERE state='collecting' AND last_batch=0",
                )
              ).length > 0
            )
              throw new Error("interrupted before end");
            return queue.run(id, kind, work);
          },
        },
      },
      descriptor,
    );
    const data = { eventId: "one", occurredAt: "2026-06-01T00:00:00.000Z" };
    await producer.append(data);
    const batch = first.db.batch.bind(first.db);
    if (stop === "after end")
      vi.spyOn(first.db, "batch").mockImplementation(async (statements) => {
        if (
          statements.some((s) =>
            s.sql.startsWith("DELETE FROM system_stream_outbox"),
          )
        )
          throw new Error("interrupted after end");
        return batch(statements);
      });
    await expect(producer.drain()).rejects.toThrow("interrupted");
    const [outbox] = await first.db.query<{
      run_id: string;
      record_id: string;
    }>("SELECT run_id,record_id FROM system_stream_outbox");
    const runId = outbox!.run_id;
    expect(outbox!.record_id).toBe("one");
    await first.db.close();
    drivers.splice(drivers.indexOf(first.db), 1);

    const reopened = await fixture(path);
    const recovered = createSystemStreamStore(reopened.deps, descriptor);
    expect(await reopened.db.query("SELECT body FROM records")).toEqual([
      { body: JSON.stringify(data) },
    ]);
    expect(
      await reopened.db.query(
        "SELECT run_id,record_id FROM system_stream_outbox",
      ),
    ).toEqual([{ run_id: runId, record_id: "one" }]);
    expect(await reopened.db.query("SELECT run_id,state FROM runs")).toEqual([
      { run_id: runId, state: stop === "before end" ? "collecting" : "ended" },
    ]);

    expect(await recovered.drain()).toBe(1);
    expect(await reopened.db.query("SELECT body FROM records")).toEqual([
      { body: JSON.stringify(data) },
    ]);
    expect(await reopened.db.query("SELECT run_id,state FROM runs")).toEqual([
      { run_id: runId, state: "ended" },
    ]);
    expect(
      await reopened.db.query(
        "SELECT run_id FROM runs WHERE state='collecting'",
      ),
    ).toEqual([]);
    expect(
      await reopened.db.query("SELECT * FROM system_stream_outbox"),
    ).toEqual([]);
    expect(await recovered.drain()).toBe(0);
    expect(
      await reopened.db.query("SELECT count(*) AS n FROM record_changes"),
    ).toEqual([{ n: 1 }]);
  },
);
