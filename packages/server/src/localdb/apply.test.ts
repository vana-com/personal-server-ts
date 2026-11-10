import { afterEach, describe, expect, it, vi } from "vitest";
import { sha256 } from "@noble/hashes/sha2";
import {
  canonicalJson,
  pkHash,
  toHex,
  type JsonObject,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  applyConnection,
  applyStream,
} from "../../../core/src/localdb/apply.js";
import {
  connectionQueue,
  openLocalDb,
  type LocalSyncDeps,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
import { withOrigin } from "../../../core/src/localdb/merge.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { remoteFixture } from "./apply-fixture.js";

const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});
async function fixture() {
  const db = await openLocalDb(openBetterSqlite3(":memory:"), {
    owner: "0xabc",
    network: "test",
    deviceId: "apply-test",
  });
  drivers.push(db);
  const keys = {
    namespaceHmac: async () => new Uint8Array(32),
    encrypt: async (_s: string, b: Uint8Array) => b,
    encryptPart: async (_s: string, b: Uint8Array) => b,
    decrypt: async (_s: string, b: Uint8Array) => b,
  };
  const remote = await remoteFixture(keys);
  const get = vi.fn(remote.storage.get);
  let op = 0;
  const deps: LocalSyncDeps = {
    db,
    keys,
    blobs: { ...remote.storage, get },
    registry: remote.registry,
    queue: connectionQueue(),
    ownerAddress: "0xabc",
    signer: { signAddData: async () => "0x00" },
    logger: { info: vi.fn(), warn: vi.fn() },
    now: () => 1000,
    newOp: () => `apply-${++op}`,
  };
  const id = remote.control;
  await db.batch([
    {
      sql: "INSERT INTO connections(connection_id,connector,ns,generation,control_state,control_version) VALUES (?,'fixture-source','',1,'active',1)",
      params: [id],
    },
  ]);
  async function insert(
    value: JsonObject,
    origin: "local" | "remote",
    stream = "items",
  ) {
    const body = canonicalJson(value);
    const hash = await pkHash(async (b) => sha256(b), value, ["id"]);
    await db.batch(
      withOrigin(origin, [
        {
          sql: "INSERT INTO records(connection_id,stream,pk_hash,record_key,stamp_o,stamp_r,body,body_sha256,first_o) VALUES (?,?,?,?,200,'local-run',?,?,100)",
          params: [
            id,
            stream,
            hash,
            String(value.id),
            body,
            toHex(sha256(new TextEncoder().encode(body))),
          ],
        },
      ]),
    );
  }
  const rows = () =>
    db.query<{ record_key: string; first_o: number | null }>(
      "SELECT record_key,first_o FROM records ORDER BY record_key",
    );
  return { ...remote, db, deps, get, id, insert, rows };
}

describe("P06 database apply", () => {
  it("copies frame f to first_o, uses remote origin, and is idempotent", async () => {
    const f = await fixture();
    await f.head("items", [{ id: "a" }, { id: "b" }], { f: 17 });
    expect(await applyStream(f.deps, f.id, "items")).toMatchObject({
      outcome: "applied",
      partsDownloaded: 2,
    });
    expect(await f.rows()).toEqual([
      { record_key: "a", first_o: 17 },
      { record_key: "b", first_o: 17 },
    ]);
    expect(
      await f.db.query("SELECT DISTINCT origin FROM record_changes"),
    ).toEqual([{ origin: "remote" }]);
    const before = f.get.mock.calls.length;
    expect(await applyStream(f.deps, f.id, "items")).toMatchObject({
      outcome: "noop",
    });
    expect(f.get).toHaveBeenCalledTimes(before);
    expect(
      await f.db.query("SELECT count(*) AS n FROM record_changes"),
    ).toEqual([{ n: 2 }]);
  });

  it("single-flights concurrent streams and a connection apply, with isolated TEMP rows", async () => {
    const f = await fixture();
    await f.head("items", [{ id: "a" }]);
    await f.head("events", [{ id: "b" }]);
    await f.db.batch([
      {
        sql: "INSERT INTO temp.incoming VALUES ('other','items',?,'other',0,'other','{}','hash',NULL)",
        params: ["f".repeat(64)],
      },
      {
        sql: "INSERT INTO temp.apply_keys VALUES ('other',?)",
        params: ["f".repeat(64)],
      },
      { sql: "INSERT INTO temp.keep_ranges VALUES ('other','0','g')" },
    ]);
    const [a, b, all, repeated] = await Promise.all([
      applyStream(f.deps, f.id, "items"),
      applyStream(f.deps, f.id, "events"),
      applyConnection(f.deps, f.id),
      applyStream(f.deps, f.id, "items"),
    ]);
    expect(a).toEqual(repeated);
    expect(b.stream).toBe("events");
    expect(all).toHaveLength(2);
    expect(f.get).toHaveBeenCalledTimes(4);
    for (const table of ["incoming", "apply_keys", "keep_ranges"])
      expect(await f.db.query(`SELECT op FROM temp.${table}`)).toEqual([
        { op: "other" },
      ]);
    expect(await f.rows()).toHaveLength(2);
  });

  it("reruns after a failure between merges and the final head batch", async () => {
    const f = await fixture();
    await f.head("items", [{ id: "a" }, { id: "b" }]);
    const batch = f.db.batch.bind(f.db);
    let crash = true;
    vi.spyOn(f.db, "batch").mockImplementation(async (statements) => {
      if (
        crash &&
        statements.some((s) =>
          s.sql.includes("INSERT OR REPLACE INTO stream_versions"),
        )
      ) {
        crash = false;
        throw new Error("simulated crash");
      }
      return batch(statements);
    });
    await expect(applyStream(f.deps, f.id, "items")).rejects.toThrow(
      "simulated crash",
    );
    expect(await f.rows()).toHaveLength(2);
    expect(await f.db.query("SELECT * FROM head_parts")).toEqual([]);
    expect(await applyStream(f.deps, f.id, "items")).toMatchObject({
      outcome: "applied",
      partsDownloaded: 2,
    });
    expect(
      await f.db.query("SELECT count(*) AS n FROM record_changes"),
    ).toEqual([{ n: 2 }]);
    expect(
      await f.db.query("SELECT count(*) AS n FROM stream_versions"),
    ).toEqual([{ n: 1 }]);
  });

  it("keeps unpublished local rows and removes only missing remote rows", async () => {
    const f = await fixture();
    await f.head("items", [{ id: "remote" }]);
    await applyStream(f.deps, f.id, "items");
    await f.insert({ id: "local" }, "local");
    await f.head("items", [], { version: 2 });
    await applyStream(f.deps, f.id, "items");
    expect(await f.rows()).toEqual([{ record_key: "local", first_o: 100 }]);
  });

  it("does not keep deleted keys when just one part of a prefix is unchanged", async () => {
    const f = await fixture();
    await f.head("items", [{ id: "a" }, { id: "b" }]);
    await applyStream(f.deps, f.id, "items");
    await f.head("items", [{ id: "a" }], { version: 2 });
    expect(await applyStream(f.deps, f.id, "items")).toMatchObject({
      partsDownloaded: 1,
      partsKept: 0,
    });
    expect(await f.rows()).toEqual([{ record_key: "a", first_o: 50 }]);
    await f.head("items", [{ id: "a" }], { version: 3, o: 100 });
    expect(await applyStream(f.deps, f.id, "items")).toMatchObject({
      partsDownloaded: 0,
      partsKept: 1,
    });
  });

  it("repairs empty head_parts and reads split frames with bounded part downloads", async () => {
    const f = await fixture();
    const head = await f.head(
      "items",
      [{ id: "long", text: "x".repeat(1000) }],
      { pieceBytes: 256, f: 9 },
    );
    await applyStream(f.deps, f.id, "items");
    await f.db.batch([{ sql: "DELETE FROM head_parts" }]);
    expect(await applyStream(f.deps, f.id, "items")).toMatchObject({
      partsDownloaded: head.parts.length,
    });
    expect(await f.rows()).toEqual([{ record_key: "long", first_o: 9 }]);
  });

  it("older frames have unknown first_o", async () => {
    const f = await fixture();
    await f.head("items", [{ id: "old" }], { format: 3 });
    await applyStream(f.deps, f.id, "items");
    expect(await f.rows()).toEqual([{ record_key: "old", first_o: null }]);
  });

  it("a deletion during download purges staged data and unpublished rows", async () => {
    const f = await fixture();
    await f.head("items", [{ id: "remote" }]);
    await f.insert({ id: "local" }, "local");
    f.get.mockImplementation(async (key) => {
      const bytes = await f.storage.get(key);
      if (key.includes("/g1-p-")) f.setControl(2, true);
      return bytes;
    });
    expect(await applyStream(f.deps, f.id, "items")).toMatchObject({
      outcome: "purged",
    });
    expect(await f.rows()).toEqual([]);
    expect(await f.db.query("SELECT * FROM head_parts")).toEqual([]);
  });

  it("a new generation purges the old image before merging", async () => {
    const f = await fixture();
    await f.head("items", [{ id: "old" }]);
    await applyStream(f.deps, f.id, "items");
    await f.insert({ id: "old-local" }, "local");
    f.setControl(3);
    await f.head("items", [{ id: "new" }], { generation: 3, version: 2 });
    await applyStream(f.deps, f.id, "items");
    expect(await f.rows()).toEqual([{ record_key: "new", first_o: 50 }]);
    expect(
      await f.db.query("SELECT control_state,generation FROM connections"),
    ).toEqual([{ control_state: "active", generation: 3 }]);
  });

  it("purges a deleted control even when the registry lists no streams", async () => {
    const f = await fixture();
    await f.head("items", [{ id: "remote" }]);
    await applyConnection(f.deps, f.id);
    f.setControl(2, true);
    f.registry.listStreamRows = async () => [];
    expect(await applyConnection(f.deps, f.id)).toMatchObject([
      { outcome: "purged" },
    ]);
    expect(await f.rows()).toEqual([]);
  });

  it("merges first_o independently of an older stamp without logging a write", async () => {
    const f = await fixture();
    await f.head("items", [{ id: "a", value: "new" }], { o: 100, f: 50 });
    await applyStream(f.deps, f.id, "items");
    await f.head("items", [{ id: "a", value: "old" }], {
      o: 90,
      f: 10,
      version: 2,
    });
    await applyStream(f.deps, f.id, "items");
    expect(await f.rows()).toEqual([{ record_key: "a", first_o: 10 }]);
    expect(await f.db.query("SELECT stamp_o FROM records")).toEqual([
      { stamp_o: 100 },
    ]);
    expect(
      await f.db.query("SELECT count(*) AS n FROM record_changes"),
    ).toEqual([{ n: 1 }]);
  });

  it("rejects corrupt parts without advancing the durable head", async () => {
    const f = await fixture();
    const h = await f.head("items", [{ id: "a" }]);
    f.blobs.set(
      `${h.scope}/g1-p-${h.parts[0]!.hash}`,
      new Uint8Array(h.parts[0]!.bytes),
    );
    await expect(applyStream(f.deps, f.id, "items")).rejects.toThrow();
    expect(await f.db.query("SELECT * FROM stream_versions")).toEqual([]);
    expect(await f.rows()).toEqual([]);
  });
});
