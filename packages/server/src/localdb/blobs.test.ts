import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createBlobStore,
  openLocalDb,
  type LocalSyncDeps,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
import { IDENTITYLESS_NS } from "@opendatalabs/personal-server-ts-stream-sync";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const digest = (bytes: Uint8Array) =>
  createHash("sha256").update(bytes).digest("hex");
const dirs: string[] = [];
const drivers: SqlDriver[] = [];

async function fresh() {
  const dir = mkdtempSync(join(process.cwd(), ".blobs-test-"));
  dirs.push(dir);
  const driver = openBetterSqlite3(join(dir, "db.sqlite"));
  drivers.push(driver);
  const db = await openLocalDb(driver, {
    owner: "0xabc",
    network: "test",
    deviceId: "device",
  });
  const get = vi
    .fn<(key: string) => Promise<Uint8Array | null>>()
    .mockResolvedValue(null);
  const decrypt = vi.fn(async (_scope: string, bytes: Uint8Array) => bytes);
  const deps: LocalSyncDeps = {
    db,
    queue: { run: async (_connection, _kind, fn) => fn() },
    ownerAddress: "0xabc",
    blobs: { get, put: vi.fn() },
    keys: {
      namespaceHmac: vi.fn(),
      encrypt: vi.fn(),
      encryptPart: vi.fn(),
      decrypt,
    },
    registry: {
      read: vi.fn(),
      post: vi.fn(),
      listControlRows: vi.fn(),
      listStreamRows: vi.fn(),
    },
    signer: { signAddData: vi.fn() },
    logger: { info: vi.fn(), warn: vi.fn() },
    now: () => 100,
    newOp: () => "op",
  };
  await db.batch([
    {
      sql: "INSERT INTO connections(connection_id, connector, ns, generation, control_state) VALUES ('c', 'example', ?, 4, 'active')",
      params: [IDENTITYLESS_NS],
    },
    {
      sql: "INSERT INTO runs(run_id, connection_id, o, generation, artifact_version, collection_mode, state) VALUES ('run', 'c', 100, 4, '1', 'incremental', 'collecting')",
    },
    {
      sql: "INSERT INTO stream_state(connection_id, stream, primary_key, semantics, incremental, head_generation) VALUES ('c', 'files', '[\"id\"]', 'mutable_state', 1, 4)",
    },
  ]);
  return { db, store: createBlobStore(deps), get, decrypt };
}

function record(pk: string, hash: string) {
  return {
    sql: "INSERT INTO records(connection_id, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256) VALUES ('c', 'files', ?, ?, 100, 'run', ?, 'fixture')",
    params: [pk, pk, JSON.stringify({ attachment: { sha256: hash } })],
  };
}

afterEach(async () => {
  for (const driver of drivers.splice(0)) await driver.close();
  for (const dir of dirs.splice(0))
    rmSync(dir, { recursive: true, force: true });
});

describe("local database blobs", () => {
  it("stores run bytes and exact record refs, reads locally, and fetches missing bytes lazily", async () => {
    const { db, store, get, decrypt } = await fresh();
    const bytes = new Uint8Array([0, 1, 127, 255]);
    const hash = digest(bytes);
    await db.batch([
      record("current", hash),
      {
        sql: "INSERT INTO run_rows(run_id, stream, pk_hash, record_key, body, body_sha256) VALUES ('run', 'files', 'staged', 'staged', ?, 'fixture')",
        params: [JSON.stringify({ attachments: [{ sha256: hash }] })],
      },
      record("unrelated", `prefix-${hash}-suffix`),
    ]);
    await store.put({
      runId: "run",
      sha256: hash,
      mimeType: "image/png",
      bytes,
    });
    await store.put({
      runId: "run",
      sha256: hash,
      mimeType: "image/png",
      bytes,
    });
    const [row] = await db.query<{
      blob_id: string;
      mime_type: string;
      size_bytes: number;
      generation: number;
      bytes: Uint8Array;
    }>("SELECT * FROM blobs");
    expect(row && { ...row, bytes: new Uint8Array(row.bytes) }).toEqual({
      blob_id: hash,
      mime_type: "image/png",
      size_bytes: bytes.length,
      generation: 4,
      bytes,
    });
    expect(await db.query("SELECT * FROM blob_refs ORDER BY pk_hash")).toEqual([
      {
        blob_id: hash,
        connection_id: "c",
        stream: "files",
        pk_hash: "current",
      },
      { blob_id: hash, connection_id: "c", stream: "files", pk_hash: "staged" },
    ]);
    const local = await store.get(hash);
    expect(local?.mimeType).toBe("image/png");
    expect(local && new Uint8Array(local.bytes)).toEqual(bytes);
    expect(get).not.toHaveBeenCalled();
    expect(decrypt).not.toHaveBeenCalled();

    const remoteBytes = new Uint8Array([2, 3, 4]);
    const remoteHash = digest(remoteBytes);
    await db.batch([
      {
        sql: "INSERT INTO blobs(blob_id, mime_type, size_bytes, generation, bytes) VALUES (?, 'image/jpeg', 3, 4, NULL)",
        params: [remoteHash],
      },
      {
        sql: "INSERT INTO blob_refs(blob_id, connection_id, stream, pk_hash) VALUES (?, 'c', 'files', 'remote')",
        params: [remoteHash],
      },
    ]);
    get.mockResolvedValueOnce(remoteBytes);
    expect(await store.get(remoteHash)).toEqual({
      mimeType: "image/jpeg",
      bytes: remoteBytes,
    });
    const scope = `pdpp.example~${IDENTITYLESS_NS}.files`;
    expect(get).toHaveBeenLastCalledWith(`${scope}/g4-b-${remoteHash}`);
    expect(decrypt).toHaveBeenLastCalledWith(scope, remoteBytes);
    const cached = await store.get(remoteHash);
    expect(cached && new Uint8Array(cached.bytes)).toEqual(remoteBytes);
    expect(get).toHaveBeenCalledTimes(1);

    const absent = digest(new Uint8Array([9]));
    expect(await store.get(absent)).toBeNull();
    expect(get).toHaveBeenLastCalledWith(absent);
    expect(
      await db.query("SELECT blob_id FROM blobs WHERE blob_id = ?", [absent]),
    ).toEqual([]);

    await expect(
      store.put({
        runId: "run",
        sha256: hash,
        mimeType: "image/png",
        bytes: new Uint8Array(32 * 1024 * 1024 + 1),
      }),
    ).rejects.toThrow("32 MiB");
    await expect(
      store.put({
        runId: "run",
        sha256: hash,
        mimeType: "image/png",
        bytes: new Uint8Array([8]),
      }),
    ).rejects.toThrow("sha256");
    expect((await db.query("SELECT blob_id FROM blobs")).length).toBe(2);
  });

  it("removes refs when their records are deleted and permits dropping only unreferenced blobs", async () => {
    const { db, store } = await fresh();
    const bytes = new Uint8Array([5, 6]);
    const hash = digest(bytes);
    await db.batch([record("one", hash), record("two", hash)]);
    await store.put({
      runId: "run",
      sha256: hash,
      mimeType: "text/plain",
      bytes,
    });
    const drop = {
      sql: "DELETE FROM blobs WHERE NOT EXISTS (SELECT 1 FROM blob_refs WHERE blob_refs.blob_id = blobs.blob_id)",
    };
    await db.batch([
      {
        sql: "DELETE FROM records WHERE connection_id = 'c' AND stream = 'files' AND pk_hash = 'one'",
      },
      drop,
    ]);
    expect(await db.query("SELECT pk_hash FROM blob_refs")).toEqual([
      { pk_hash: "two" },
    ]);
    expect(await db.query("SELECT blob_id FROM blobs")).toEqual([
      { blob_id: hash },
    ]);
    await db.batch([
      {
        sql: "DELETE FROM records WHERE connection_id = 'c' AND stream = 'files' AND pk_hash = 'two'",
      },
      drop,
    ]);
    expect(await db.query("SELECT * FROM blob_refs")).toEqual([]);
    expect(await db.query("SELECT blob_id FROM blobs")).toEqual([]);
  });
});
