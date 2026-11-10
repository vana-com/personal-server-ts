import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  controlHashes,
  controlScope,
  type ControlRead,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  bootstrapConnections,
  syncBeforeBegin,
} from "../../../core/src/localdb/bootstrap.js";
import { applyConnection } from "../../../core/src/localdb/apply.js";
import { purgeConnection } from "../../../core/src/localdb/purge.js";
import { connectionQueue } from "../../../core/src/localdb/queue.js";
import { openLocalDb } from "../../../core/src/localdb/open.js";
import { streamSyncHashes } from "../../../core/src/stream-sync/crypto.js";
import type { LocalSyncDeps } from "../../../core/src/localdb/deps.js";
import type { SqlDriver } from "../../../core/src/localdb/driver.js";
import type { StreamSyncRegistry } from "../../../core/src/stream-sync/ports.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

vi.mock("../../../core/src/localdb/apply.js", () => ({
  applyConnection: vi.fn(),
}));
vi.mock("../../../core/src/localdb/purge.js", () => ({
  purgeConnection: vi.fn(),
}));

const connector = "sample";
const scope = controlScope(connector, "");
const identity = { owner: "0xabc", network: "test", deviceId: "device-b" };
const dirs: string[] = [];
const databases: SqlDriver[] = [];

async function fresh() {
  const dir = mkdtempSync(join(process.cwd(), ".bootstrap-test-"));
  dirs.push(dir);
  const db = openBetterSqlite3(join(dir, "local.sqlite"));
  databases.push(db);
  return openLocalDb(db, identity);
}

function deps(db: SqlDriver, registry: StreamSyncRegistry): LocalSyncDeps {
  const unused = async (): Promise<never> => {
    throw new Error("unexpected port");
  };
  return {
    db,
    registry,
    queue: connectionQueue(),
    ownerAddress: "0xabc",
    blobs: { get: unused, put: unused },
    keys: {
      namespaceHmac: async () => new Uint8Array(32).fill(7),
      encrypt: unused,
      encryptPart: unused,
      decrypt: unused,
    },
    signer: { signAddData: unused },
    logger: { info() {}, warn() {} },
    now: () => 1000,
    newOp: () => "bootstrap-op",
  };
}

function registryWith(read: ControlRead): StreamSyncRegistry {
  return {
    read: vi.fn(async () => read),
    listControlRows: vi.fn(async () => [{ scope, read }]),
    listStreamRows: vi.fn(async () => []),
    post: vi.fn(async () => ({ kind: "committed" as const })),
  };
}

beforeEach(() => {
  vi.mocked(applyConnection).mockReset();
  vi.mocked(purgeConnection).mockReset();
  // The sibling interfaces are intentionally unbuilt. Exercise their queue
  // contracts while leaving their own implementation to their slices.
  vi.mocked(applyConnection).mockImplementation((d, id) =>
    d.queue.run(id, "apply", async () => []),
  );
  vi.mocked(purgeConnection).mockImplementation((d, id, deleted) =>
    d.queue.run(id, "purge", async () => {
      await d.db.batch([
        { sql: "UPDATE write_ctx SET origin = 'purge' WHERE id = 1" },
        { sql: "DELETE FROM records WHERE connection_id = ?", params: [id] },
        {
          sql: "DELETE FROM run_rows WHERE run_id IN (SELECT run_id FROM runs WHERE connection_id = ?)",
          params: [id],
        },
        { sql: "DELETE FROM head_parts WHERE connection_id = ?", params: [id] },
        { sql: "DELETE FROM blob_refs WHERE connection_id = ?", params: [id] },
        {
          sql: "UPDATE connections SET control_state = 'deleted', checkpoint = NULL WHERE connection_id = ?",
          params: [id],
        },
        {
          sql: "UPDATE stream_state SET last_delete_version = ? WHERE connection_id = ?",
          params: [deleted.controlVersion, id],
        },
        { sql: "UPDATE write_ctx SET origin = 'local' WHERE id = 1" },
      ]);
    }),
  );
});

afterEach(async () => {
  for (const db of databases.splice(0)) await db.close();
  for (const dir of dirs.splice(0))
    rmSync(dir, { recursive: true, force: true });
});

describe("local database bootstrap", () => {
  it("a fresh database sees a remote connection delete at its next bootstrap and keeps no rows", async () => {
    const control = await controlHashes(
      streamSyncHashes.keccak256,
      "0707070707070707",
    );
    const deleted: ControlRead = {
      found: true,
      version: 4,
      deleted: false,
      dataHash: control.tombstoneData,
      metadataHash: control.tombstoneMetadata,
    };
    const registry = registryWith(deleted);
    const db = await fresh();
    // Rows collected locally before the fresh device could reach the registry.
    await db.batch([
      {
        sql: "INSERT INTO connections (connection_id, connector, ns) VALUES (?, ?, '')",
        params: [scope, connector],
      },
      {
        sql: "INSERT INTO records (connection_id, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256) VALUES (?, 'items', 'pk', 'key', 1, 'run', '{}', 'digest')",
        params: [scope],
      },
      {
        sql: "INSERT INTO runs (run_id, connection_id, o, artifact_version, collection_mode, state) VALUES ('run', ?, 1, 'v1', 'full_refresh', 'collecting')",
        params: [scope],
      },
      {
        sql: "INSERT INTO run_rows VALUES ('run', 'items', 'pk', 'key', '{}', 'digest')",
      },
    ]);
    const d = deps(db, registry);
    const rows = await bootstrapConnections(d);
    expect(rows).toEqual([
      {
        connectionId: scope,
        connector,
        ns: "",
        generation: 1,
        controlState: "deleted",
        controlVersion: 4,
      },
    ]);
    expect(await db.query("SELECT count(*) AS n FROM records")).toEqual([
      { n: 0 },
    ]);
    expect(await db.query("SELECT count(*) AS n FROM run_rows")).toEqual([
      { n: 0 },
    ]);
    expect(purgeConnection).toHaveBeenCalledTimes(1);
    expect(purgeConnection).toHaveBeenCalledWith(
      expect.objectContaining({ db }),
      scope,
      { controlVersion: 4 },
    );
    expect(applyConnection).not.toHaveBeenCalled();

    // A device with no local rows still discovers the tombstone and its id.
    const empty = await fresh();
    expect(await bootstrapConnections(deps(empty, registry))).toEqual(rows);
    expect(await empty.query("SELECT count(*) AS n FROM records")).toEqual([
      { n: 0 },
    ]);
    await bootstrapConnections(d);
    expect(purgeConnection).toHaveBeenCalledTimes(1);
    expect(registry.listControlRows).toHaveBeenCalledTimes(3);
  });

  it("uses the cached control when begin is offline and leaves a fresh run generation-unbound", async () => {
    const control = await controlHashes(
      streamSyncHashes.keccak256,
      "0707070707070707",
    );
    const active: ControlRead = {
      found: true,
      version: 7,
      deleted: false,
      dataHash: control.activeData,
      metadataHash: control.activeMetadata,
    };
    const registry = registryWith(active);
    const db = await fresh();
    const d = deps(db, registry);
    const [known] = await bootstrapConnections(d);
    vi.mocked(registry.read).mockRejectedValue(new Error("offline"));
    expect(await syncBeforeBegin(d, connector)).toEqual({
      connection: known,
      unreachable: true,
    });
    expect(known).toMatchObject({
      generation: 7,
      controlState: "active",
      controlVersion: 7,
    });
    expect(registry.read).toHaveBeenCalledWith(scope);
    const empty = await fresh();
    expect(await syncBeforeBegin(deps(empty, registry), connector)).toEqual({
      connection: null,
      unreachable: true,
    });
    expect(await empty.query("SELECT count(*) AS n FROM connections")).toEqual([
      { n: 0 },
    ]);
    expect(applyConnection).not.toHaveBeenCalled();

    // A failed stream listing does not erase a successful control read.
    vi.mocked(registry.read).mockResolvedValue({ ...active, version: 8 });
    vi.mocked(registry.listStreamRows).mockRejectedValue(new Error("offline"));
    expect(await syncBeforeBegin(d, connector)).toMatchObject({
      connection: { generation: 8, controlVersion: 8 },
      unreachable: true,
    });
    expect(applyConnection).not.toHaveBeenCalled();
    vi.mocked(registry.listStreamRows).mockResolvedValue([]);
    expect(await syncBeforeBegin(d, connector)).toMatchObject({
      connection: { generation: 8, controlVersion: 8 },
      unreachable: false,
    });
    expect(applyConnection).toHaveBeenCalledTimes(1);
    expect(purgeConnection).not.toHaveBeenCalled();
  });
});
