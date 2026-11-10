import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { sha256 } from "@noble/hashes/sha2";
import { keccak_256 } from "@noble/hashes/sha3";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  connectionQueue,
  createOlderVersions,
  openLocalDb,
  type LocalSyncDeps,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
import {
  canonicalJson,
  digestHead,
  encodeFramePart,
  encodeHead,
  frameOfLine,
  partBlobName,
  pkHash,
  streamScope,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const SHA = async (bytes: Uint8Array) => sha256(bytes);
const KECCAK = async (bytes: Uint8Array) => keccak_256(bytes);
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
  const blobs = new Map<string, Uint8Array>();
  const get = vi.fn(async (key: string) => blobs.get(key) ?? null);
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
    blobs: { get, put },
    keys: {
      namespaceHmac: async () => new Uint8Array(32),
      decrypt: vi.fn(async (_scope: string, bytes: Uint8Array) => bytes),
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
  async function version(
    version: number,
    observedAt: number,
    generation = 2,
    ids = [version],
  ) {
    const rows = await Promise.all(
      ids.map(async (id) => {
        const value = { id };
        const k = await pkHash(SHA, value, ["id"]);
        const frame = await frameOfLine(
          SHA,
          k,
          canonicalJson({ o: observedAt, r: "fixture-run", v: value }),
        );
        return { k, bytes: frame.bytes };
      }),
    );
    rows.sort((a, b) => a.k.localeCompare(b.k));
    const parts = [];
    const partKeys: string[] = [];
    for (const row of rows) {
      const part = (await encodeFramePart(SHA, "", [row]))!;
      parts.push(part.entry);
      const key = `${scope}/${partBlobName(generation, part.entry.hash)}`;
      blobs.set(key, part.data);
      partKeys.push(key);
    }
    const head = encodeHead({
      complete: true,
      connector,
      format: 4,
      generation,
      lastDeleteVersion: 0,
      keyCheck: "0000000000000000",
      ns,
      observedAt,
      parts,
      primaryKey: ["id"],
      profile: { key: null, version: "1" },
      recordCount: ids.length,
      stream,
    });
    const { blobName } = await digestHead(KECCAK, head);
    blobs.set(`${scope}/${blobName}`, head);
    await db.batch([
      {
        sql: "INSERT INTO stream_versions(connection_id, stream, version, generation, head_blob, head_format, record_count, observed_at, complete, kind) VALUES (?, ?, ?, ?, ?, 4, ?, ?, 1, 'applied')",
        params: [
          "c1",
          stream,
          version,
          generation,
          blobName,
          ids.length,
          observedAt,
        ],
      },
    ]);
    return {
      fileId: blobName,
      partKeys,
      info: {
        version,
        fileId: blobName,
        observedAt,
        recordCount: ids.length,
        complete: true,
      },
    };
  }
  return {
    db,
    history,
    version,
    blobs,
    get,
    put,
    info,
    deps,
    setEnabled: (value: boolean) => {
      enabled = value;
    },
  };
}

async function consume(body: ReadableStream<Uint8Array> | "gone") {
  expect(body).not.toBe("gone");
  if (body === "gone") throw new Error("Expected a readable version");
  return new Response(body).text();
}

describe("older versions", () => {
  it("resolves fileId and at only in the current generation; disabling reads lists only the current head", async () => {
    const f = await fixture();
    const old = await f.version(1, 500, 1);
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
    f.get.mockClear();
    expect(
      JSON.parse(
        await consume(await f.history.read(scope, { fileId: a.fileId })),
      ),
    ).toEqual([{ id: 2 }]);
    expect(f.get.mock.calls[0]).toEqual([`${scope}/${a.fileId}`]);
    f.get.mockClear();
    expect(
      JSON.parse(
        await consume(
          await f.history.read(scope, { at: new Date(2_000).toISOString() }),
        ),
      ),
    ).toEqual([{ id: 3 }]);
    expect(f.get.mock.calls[0]).toEqual([`${scope}/${current.fileId}`]);
    f.get.mockClear();
    await consume(await f.history.read(scope, { at: "2500" }));
    expect(f.get.mock.calls[0]).toEqual([`${scope}/${current.fileId}`]);
    f.get.mockClear();
    expect(await f.history.read(scope, { fileId: old.fileId })).toBe("gone");
    expect(
      await f.history.read(scope, { at: new Date(500).toISOString() }),
    ).toBe("gone");
    expect(f.get).not.toHaveBeenCalled();

    // A matching stream in another namespace cannot be selected by this scope.
    await f.db.batch([
      {
        sql: "INSERT INTO connections(connection_id, connector, ns, generation, control_state) VALUES ('c2', ?, '', 2, 'active')",
        params: [connector],
      },
      {
        sql: "INSERT INTO stream_versions SELECT 'c2', stream, version, generation, head_blob, head_format, record_count, observed_at, complete, kind FROM stream_versions WHERE connection_id = 'c1' AND version = 4",
      },
    ]);
    expect(
      await f.history.read(streamScope(connector, "fedcba9876543210", stream), {
        fileId: latest.fileId,
      }),
    ).toBe("gone");

    f.setEnabled(false);
    f.get.mockClear();
    expect(await f.history.read(scope, { fileId: a.fileId })).toBe("gone");
    expect(await f.history.list("c1", stream)).toEqual([current.info]);
    expect(f.get).not.toHaveBeenCalled();
    f.setEnabled(true);
    expect(await f.history.list("c1", stream)).toHaveLength(4);
    expect(f.put).not.toHaveBeenCalled();
    expect(await f.db.query("SELECT count(*) AS n FROM records")).toEqual([
      { n: 0 },
    ]);

    // A generation change while downloading must also fence the selected row.
    f.get.mockImplementationOnce(async (key) => {
      await f.db.batch([
        {
          sql: "UPDATE connections SET generation = 3 WHERE connection_id = 'c1'",
        },
      ]);
      return f.blobs.get(key) ?? null;
    });
    expect(await f.history.read(scope, { fileId: a.fileId })).toBe("gone");
    expect(await f.history.list("c1", stream)).toEqual([]);
  });

  it("answers gone before returning a body when any part is missing and evicts only that history row", async () => {
    const f = await fixture();
    const retained = await f.version(2, 1_000);
    const missing = await f.version(3, 2_000, 2, [31, 32]);
    await f.db.batch([
      {
        sql: "INSERT INTO stream_versions SELECT connection_id, 'other', version, generation, head_blob, head_format, record_count, observed_at, complete, kind FROM stream_versions WHERE version = 3",
      },
    ]);
    f.blobs.delete(missing.partKeys[1]!);
    expect(await f.history.read(scope, { fileId: missing.fileId })).toBe(
      "gone",
    );
    expect(await f.history.list("c1", stream)).toEqual([retained.info]);
    expect(
      await f.db.query(
        "SELECT stream, version FROM stream_versions ORDER BY stream, version",
      ),
    ).toEqual([
      { stream: "events", version: 2 },
      { stream: "other", version: 3 },
    ]);
    expect(f.put).not.toHaveBeenCalled();
  });

  it("counts and logs exactly one privacy-safe outcome for each served, gone and disabled read", async () => {
    const f = await fixture();
    const available = await f.version(2, 1_000);
    const snapshot = f.history.counts();
    expect(snapshot).toEqual({ served: 0, gone: 0, off: 0 });
    await f.history.list("c1", stream);
    expect(f.info).not.toHaveBeenCalled();
    await consume(await f.history.read(scope, { fileId: available.fileId }));
    expect(f.history.counts()).toEqual({ served: 1, gone: 0, off: 0 });
    expect(await f.history.read(scope, { fileId: "not-retained" })).toBe(
      "gone",
    );
    expect(f.history.counts()).toEqual({ served: 1, gone: 1, off: 0 });
    f.setEnabled(false);
    expect(await f.history.read(scope, { fileId: available.fileId })).toBe(
      "gone",
    );
    expect(f.history.counts()).toEqual({ served: 1, gone: 1, off: 1 });
    expect(snapshot).toEqual({ served: 0, gone: 0, off: 0 });
    expect(f.info.mock.calls).toEqual([
      [{}, "older-version read outcome=served"],
      [{}, "older-version read outcome=gone"],
      [{}, "older-version read outcome=off"],
    ]);
  });
});
