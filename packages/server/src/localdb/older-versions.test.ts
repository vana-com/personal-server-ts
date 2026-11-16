import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  connectionQueue,
  createOlderVersions,
  openLocalDb,
  type LocalSyncDeps,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
import { streamScope } from "@opendatalabs/personal-server-ts-stream-sync";
import { createMemoryStreamSyncBlobs } from "../../../core/src/stream-sync/memory-registry.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const connector = "fixture";
const ns = "0123456789abcdef";
const stream = "events";
const scope = streamScope(connector, ns, stream);
const dirs: string[] = [];
const drivers: SqlDriver[] = [];

afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
  for (const dir of dirs.splice(0))
    rmSync(dir, { recursive: true, force: true });
});

async function fixture() {
  const dir = mkdtempSync(join(process.cwd(), ".older-versions-"));
  dirs.push(dir);
  const driver = openBetterSqlite3(join(dir, "db.sqlite"));
  drivers.push(driver);
  const db = await openLocalDb(driver, {
    owner: "0xabc",
    network: "test-network",
    deviceId: "test-device",
  });
  await db.batch([
    {
      sql: "INSERT INTO connections(connection_id, connector, ns, generation, control_state) VALUES (?, ?, ?, 2, 'active')",
      params: ["c1", connector, ns],
    },
    {
      sql: "INSERT INTO stream_state(connection_id, stream, primary_key, semantics, incremental) VALUES (?, ?, ?, 'mutable_state', 0)",
      params: ["c1", stream, '["id"]'],
    },
  ]);
  const get = vi.fn(async () => null);
  const put = vi.fn(async () => undefined);
  const info = vi.fn();
  let enabled = true;
  const unused = vi.fn(async () => {
    throw new Error("Unexpected port call");
  });
  const deps: LocalSyncDeps = {
    db,
    queue: connectionQueue(),
    ownerAddress: "0xabc",
    blobs: { governor: createMemoryStreamSyncBlobs().governor, get, put },
    keys: {
      namespaceHmac: async () => new Uint8Array(32),
      decrypt: unused,
      encrypt: unused,
      encryptPart: unused,
    },
    registry: {
      read: unused,
      post: unused,
      listControlRows: unused,
      listStreamRows: unused,
    },
    signer: { signAddData: unused },
    logger: { info, warn: vi.fn() },
    now: () => 10_000,
    newOp: () => "unused",
  };
  const history = createOlderVersions(deps, { enabled: () => enabled });
  /** A version row, as a log apply writes it: the head blob column holds the segment name. */
  async function version(version: number, observedAt: number, generation = 2) {
    const fileId = `s-${version.toString(16).padStart(8, "0")}`;
    await db.batch([
      {
        sql: "INSERT INTO stream_versions(connection_id, stream, version, generation, head_blob, head_format, record_count, observed_at, complete, kind) VALUES (?, ?, ?, ?, ?, 4, 1, ?, 1, 'applied')",
        params: ["c1", stream, version, generation, fileId, observedAt],
      },
    ]);
    return {
      fileId,
      info: {
        version,
        fileId,
        observedAt,
        recordCount: 1,
        complete: true,
      },
    };
  }
  return {
    db,
    history,
    version,
    get,
    put,
    info,
    setEnabled: (value: boolean) => {
      enabled = value;
    },
  };
}

describe("older versions", () => {
  it("lists only the current generation; disabling reads lists only the current head", async () => {
    const f = await fixture();
    await f.version(1, 500, 1);
    const a = await f.version(2, 1_000);
    const current = await f.version(3, 2_000);
    const latest = await f.version(4, 3_000);
    const lateArrival = await f.version(5, 1_500);
    await f.db.batch([
      {
        sql: "UPDATE stream_state SET head_version = ?, head_generation = 2, head_blob = ? WHERE connection_id = 'c1' AND stream = ?",
        params: [3, current.fileId, stream],
      },
    ]);
    expect(await f.history.list("c1", stream)).toEqual([
      latest.info,
      current.info,
      lateArrival.info,
      a.info,
    ]);
    f.setEnabled(false);
    expect(await f.history.list("c1", stream)).toEqual([current.info]);
    f.setEnabled(true);
    expect(await f.history.list("c1", stream)).toHaveLength(4);
    expect(f.get).not.toHaveBeenCalled();
    expect(f.put).not.toHaveBeenCalled();

    // A generation change drops every listed version.
    await f.db.batch([
      {
        sql: "UPDATE connections SET generation = 3 WHERE connection_id = 'c1'",
      },
    ]);
    expect(await f.history.list("c1", stream)).toEqual([]);
  });

  it("answers gone for every read, whatever it selects, and fetches nothing", async () => {
    const f = await fixture();
    const a = await f.version(2, 1_000);
    expect(await f.history.read(scope, { fileId: a.fileId })).toBe("gone");
    expect(
      await f.history.read(scope, { at: new Date(1_000).toISOString() }),
    ).toBe("gone");
    expect(
      await f.history.read(streamScope(connector, "fedcba9876543210", stream), {
        fileId: a.fileId,
      }),
    ).toBe("gone");
    expect(f.get).not.toHaveBeenCalled();
    expect(f.put).not.toHaveBeenCalled();
    expect(await f.db.query("SELECT count(*) AS n FROM records")).toEqual([
      { n: 0 },
    ]);
  });

  it("counts and logs exactly one privacy-safe outcome for each gone and disabled read", async () => {
    const f = await fixture();
    const available = await f.version(2, 1_000);
    expect(f.history.counts()).toEqual({ served: 0, gone: 0, off: 0 });
    await f.history.list("c1", stream);
    expect(f.info).not.toHaveBeenCalled();
    expect(await f.history.read(scope, { fileId: available.fileId })).toBe(
      "gone",
    );
    expect(f.history.counts()).toEqual({ served: 0, gone: 1, off: 0 });
    f.setEnabled(false);
    expect(await f.history.read(scope, { fileId: available.fileId })).toBe(
      "gone",
    );
    expect(f.history.counts()).toEqual({ served: 0, gone: 1, off: 1 });
    expect(f.info.mock.calls).toEqual([
      [{}, "older-version read outcome=gone"],
      [{}, "older-version read outcome=off"],
    ]);
  });
});
