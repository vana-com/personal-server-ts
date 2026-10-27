/**
 * The replication door (`pdpp-replication-door.ts`): off is permanent, a write
 * outside capture closes the door whichever build makes it, and a database
 * that never enabled replication carries none of it.
 *
 * `createSqliteRecordStore` without a replica port is main's store, unchanged
 * by the door, so here it stands for an older build that knows nothing of
 * replication.
 */
import Database from "better-sqlite3";
import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ReplicaOperation } from "@opendatalabs/personal-server-ts-core/replication/envelope";
import type { MergeContext } from "@opendatalabs/personal-server-ts-core/replication/merge-plan";
import { ReplicationRefusedError } from "@opendatalabs/personal-server-ts-core/replication/door";
import {
  openRecordStore,
  resolveReplication,
} from "../pdpp/records-bootstrap.js";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import { createReplicaRecordStore } from "./pdpp-replica-canonical-port.js";
import { REPLICATION_DOOR_PROBE } from "./pdpp-replication-door.js";
import { createReplicaReceiver } from "./pdpp-replication-receiver.js";
import { liveSnapshotDigest } from "./pdpp-stream-completion.js";

interface SchemaObject {
  type: string;
  name: string;
  tableName: string;
  sql: string | null;
}
const main = JSON.parse(
  readFileSync(
    new URL("../__fixtures__/main-record-store-schema.json", import.meta.url),
    "utf8",
  ),
) as { schemaVersion: number; objects: SchemaObject[] };

const sourceId = "https://source.invalid/declaration";
const at = "2026-10-20T00:00:00.000Z";
const binding = {
  digest: `sha256:${"a".repeat(64)}`,
  version: "1",
  stream: "messages",
  semantics: "mutable_state" as const,
  primaryKey: ["id"],
  schemaDigest: `sha256:${"b".repeat(64)}`,
};
const declarations: MergeContext["declarations"] = [
  { sourceId, binding, validateData: (data) => typeof data.id === "string" },
];
const baseline = { owner: "owner", declarations: [{ sourceId, binding }] };
const quiet = { warn: () => undefined };
const refused = { state: "refused", refusal: "reenable_refused" };

type Store = ReturnType<typeof createSqliteRecordStore>;

const register = (store: Store, instance = "conn_a") =>
  store.registerConnection({
    instance,
    sourceId,
    method: "collector",
    label: "A",
  });
const ingest = (store: Store, key: string, text = key) =>
  store.ingestBatch(
    [
      {
        instance: "conn_a",
        stream: "messages",
        key,
        data: { id: key, text },
        emitted_at: at,
      },
    ],
    () => "mutable_state",
    () => ["id"],
    { method: "collector", generation: 1 },
  );
/** Completes `messages` over the single live record `a`. */
const complete = (store: Store) =>
  store.completeStreams(
    {
      instance: "conn_a",
      sourceId,
      method: "collector",
      generation: 1,
      sourceCollectedAt: at,
      collectionTimeBasis: "host_run_finished",
      streams: [
        {
          stream: "messages",
          coverage: "full_stream",
          liveCount: 1,
          snapshotSha256: liveSnapshotDigest(
            {
              sourceId,
              instance: "conn_a",
              method: "collector",
              generation: 1,
              stream: "messages",
            },
            ["id"],
            [
              {
                recordKey: "a",
                dataJson: JSON.stringify({ id: "a", text: "a" }),
              },
            ],
          ),
        },
      ],
    },
    () => ["id"],
  );
const keys = (store: Store) =>
  store
    .listRecords("messages", {
      instanceIds: ["conn_a"],
      limit: 100,
      order: "asc",
    })
    .data.map((row) => row.recordKey);

const directories: string[] = [];
const handles: Database.Database[] = [];
function file(): string {
  const directory = mkdtempSync(join(tmpdir(), "pdpp-replication-door-"));
  directories.push(directory);
  return join(directory, "db.sqlite");
}
function open(path: string): Database.Database {
  const db = new Database(path);
  handles.push(db);
  return db;
}
afterEach(() => {
  for (const db of handles.splice(0)) if (db.open) db.close();
  for (const directory of directories.splice(0))
    rmSync(directory, { recursive: true, force: true });
});

/** One boot: pass the door, open the store this boot would, run `use`. */
function boot(
  path: string,
  requested: boolean,
  use?: (store: Store) => void,
): ReturnType<typeof resolveReplication>["status"] {
  const db = open(path);
  const { enabled, status } = resolveReplication(db, requested, quiet);
  use?.(openRecordStore(db, enabled));
  db.close();
  return status;
}
const door = (path: string) => {
  const db = open(path);
  const row = db
    .prepare("SELECT capturing, uncaptured, off FROM pdpp_replica_door")
    .get();
  db.close();
  return row;
};
const fenceTriggers = (path: string) => {
  const db = open(path);
  const { n } = db
    .prepare(
      "SELECT count(*) AS n FROM sqlite_master WHERE type = 'trigger' AND name GLOB 'pdpp_replica_door_*'",
    )
    .get() as { n: number };
  db.close();
  return n;
};
/** A database enabled, baselined, written and completed once, then closed. */
function enabledDatabase(): string {
  const path = file();
  expect(
    boot(path, true, (store) => {
      register(store);
      (
        store as ReturnType<typeof createReplicaRecordStore>
      ).replication.beginBaseline(baseline);
      ingest(store, "a");
      complete(store);
    }),
  ).toEqual({ state: "on" });
  return path;
}

describe("a database that never enabled replication", () => {
  it("gets nothing from a flag-off boot but one read of sqlite_master", () => {
    const path = file();
    const db = open(path);
    const seen: string[] = [];
    const traced = new Proxy(db, {
      get(target, property) {
        if (property === "prepare" || property === "exec")
          return (sql: string) => {
            seen.push(sql);
            return property === "prepare"
              ? target.prepare(sql)
              : target.exec(sql);
          };
        const value = Reflect.get(target, property, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
    const store = createSqliteRecordStore(db);
    register(store);
    ingest(store, "a");
    expect(resolveReplication(traced, false, quiet)).toEqual({
      enabled: false,
      status: { state: "never" },
    });
    expect(seen).toEqual([REPLICATION_DOOR_PROBE]);
    expect(
      db
        .prepare(
          "SELECT type, name, tbl_name AS tableName, sql FROM sqlite_master ORDER BY type, name",
        )
        .all(),
    ).toEqual(main.objects);
  });

  it("opens the door on the first enabled boot, over rows written while off", () => {
    const path = file();
    expect(
      boot(path, false, (store) => (register(store), ingest(store, "a"))),
    ).toEqual({ state: "never" });
    expect(boot(path, true, (store) => ingest(store, "b"))).toEqual({
      state: "on",
    });
    expect(door(path)).toEqual({ capturing: 0, uncaptured: 0, off: 0 });
    expect(boot(path, true)).toEqual({ state: "on" });
  });
});

describe("the door after replication was on", () => {
  it("on → off → write → on: refused, and every record is still readable", () => {
    const path = enabledDatabase();
    expect(
      boot(path, false, (store) => ingest(store, "written while off")),
    ).toEqual({ state: "off" });
    expect(boot(path, true)).toEqual(refused);
    // The refused boot runs as flag-off and keeps every row.
    boot(path, true, (store) =>
      expect(keys(store)).toEqual(["a", "written while off"]),
    );
    expect(door(path)).toMatchObject({ off: 1 });
  });

  it("on → off → on with no write in between: refused, because off is permanent", () => {
    // A flag-off boot of an older build cannot be told apart from a later
    // write it made, and the host has already told the owner off is final.
    const path = enabledDatabase();
    expect(boot(path, false)).toEqual({ state: "off" });
    expect(door(path)).toEqual({ capturing: 0, uncaptured: 0, off: 1 });
    expect(fenceTriggers(path)).toBe(0);
    expect(boot(path, true)).toEqual(refused);
    expect(boot(path, false)).toEqual({ state: "off" });
  });

  it("downgrade: a build without capture that writes closes the door", () => {
    const path = enabledDatabase();
    const db = open(path);
    ingest(createSqliteRecordStore(db), "older build");
    db.close();
    expect(door(path)).toEqual({ capturing: 0, uncaptured: 1, off: 0 });
    expect(boot(path, true)).toEqual(refused);
    // The refused boot ran as flag-off, so it closed the door too.
    expect(door(path)).toEqual({ capturing: 0, uncaptured: 1, off: 1 });
    expect(fenceTriggers(path)).toBe(0);
  });

  it("downgrade: a build without capture that only opens and reads leaves it open", () => {
    const path = enabledDatabase();
    const db = open(path);
    expect(keys(createSqliteRecordStore(db))).toEqual(["a"]);
    db.close();
    expect(boot(path, true)).toEqual({ state: "on" });
  });

  it("fences every replicated table against raw SQL from any build", () => {
    const writes = [
      "UPDATE pdpp_records SET data = data",
      "DELETE FROM pdpp_records",
      "UPDATE pdpp_instance_binding SET label = 'x'",
      "DELETE FROM pdpp_stream_completion",
      "UPDATE pdpp_stream_completion SET live_count = live_count",
      "INSERT INTO pdpp_strava_transition (instance, archive_instance, generation, snapshots_json) VALUES ('conn_a', 'retired', 2, '{}')",
      "INSERT INTO pdpp_claude_transition (instance, archive_instance, generation, snapshots_json) VALUES ('conn_a', 'retired', 2, '{}')",
      // pdpp_blobs is not fenced: bytes alone change no replicated state.
      "INSERT INTO pdpp_blobs VALUES ('sha256:x', 'text/plain', 1, 'x'); INSERT INTO pdpp_blob_claims VALUES ('sha256:x', 'conn_a', 1)",
    ];
    for (const sql of writes) {
      const path = enabledDatabase();
      const db = open(path);
      db.exec(sql);
      db.close();
      expect(door(path), sql).toMatchObject({ uncaptured: 1 });
      expect(() => createReplicaRecordStore(open(path)), sql).toThrow(
        ReplicationRefusedError,
      );
    }
  });

  it("does not trip on enabled writes, imports, or a rolled-back write", () => {
    const path = enabledDatabase();
    const db = open(path);
    const store = createReplicaRecordStore(db);
    const blob = store.storeBlobBytesForInstance({
      instance: "conn_a",
      method: "collector",
      generation: 1,
      bytes: new Uint8Array([1, 2, 3]),
      mimeType: "application/octet-stream",
    });
    ingest(store, "b");
    store.deleteRecord("conn_a", "messages", "a", at, "mutable_state");
    expect(() =>
      store.writeTransaction(() => {
        ingest(store, "rolled back");
        throw new Error("boom");
      }),
    ).toThrow("boom");
    // An import through the receiver writes canonical rows too.
    const source = createReplicaRecordStore(open(file()));
    register(source);
    source.replication.beginBaseline(baseline);
    ingest(source, "imported");
    const operations: ReplicaOperation[] = [
      ...source.replication.readBaselinePage({ limit: 1000 }).operations,
      ...source.replication.readTailPage({ limit: 1000 }).operations,
    ];
    createReplicaReceiver({
      db,
      store,
      owner: "owner",
      authenticate: () => "owner",
      declarations: () => declarations,
    }).import({
      credential: "x",
      envelope: {
        format: "vana-pdpp-replica",
        version: 1,
        owner: "owner",
        batchId: "door-import",
        operations,
      },
    });
    expect(keys(store)).toEqual(["b", "imported"]);
    store.deleteConnection("conn_a");
    expect(blob.blobId).toBeTruthy();
    db.close();
    expect(door(path)).toEqual({ capturing: 0, uncaptured: 0, off: 0 });
    expect(boot(path, true)).toEqual({ state: "on" });
  });

  it("refuses a database a pre-door build baselined, and adopts one it never baselined", () => {
    const baselined = enabledDatabase();
    const unbaselined = file();
    boot(unbaselined, true, (store) => register(store));
    for (const path of [baselined, unbaselined]) {
      const db = open(path);
      db.exec(
        "DROP TABLE pdpp_replica_door; " +
          (
            db
              .prepare(
                "SELECT group_concat('DROP TRIGGER ' || name, '; ') AS sql FROM sqlite_master WHERE type = 'trigger' AND name GLOB 'pdpp_replica_door_*'",
              )
              .get() as { sql: string }
          ).sql,
      );
      db.close();
    }
    expect(boot(baselined, true)).toEqual(refused);
    expect(boot(unbaselined, true)).toEqual({ state: "on" });
  });

  it("rollback: plain main code still opens, reads and writes a database with the fence", () => {
    const path = enabledDatabase();
    const db = open(path);
    const plain = createSqliteRecordStore(db);
    const objects = new Map(
      (
        db
          .prepare(
            "SELECT type, name, tbl_name AS tableName, sql FROM sqlite_master",
          )
          .all() as SchemaObject[]
      ).map((o) => [o.name, o]),
    );
    for (const object of main.objects)
      expect(objects.get(object.name), object.name).toEqual(object);
    expect(
      [...objects.values()].filter(
        (o) => o.type === "trigger" && o.name.startsWith("pdpp_replica_door_"),
      ),
    ).toHaveLength(17);
    ingest(plain, "b");
    expect(keys(plain)).toEqual(["a", "b"]);
    plain.deleteConnection("conn_a");
    expect(keys(plain)).toEqual([]);
  });
});

describe("the fence's cost on a flag-off database", () => {
  /** Milliseconds for `rows` flag-off writes in batches of 100, best of three. */
  function writeTime(path: string, rows: number): number {
    let best = Infinity;
    for (let run = 0; run < 3; run++) {
      const db = open(path);
      const store = createSqliteRecordStore(db);
      const started = performance.now();
      for (let batch = 0; batch < rows / 100; batch++)
        store.ingestBatch(
          Array.from({ length: 100 }, (_, i) => ({
            instance: "conn_a",
            stream: "messages",
            key: `k${batch * 100 + i}`,
            data: { id: `k${batch * 100 + i}`, text: `run ${run}` },
            emitted_at: at,
          })),
          () => "mutable_state",
          () => ["id"],
          { method: "collector", generation: 1 },
        );
      best = Math.min(best, performance.now() - started);
      db.close();
    }
    return best;
  }

  it("costs a flag-off database nothing, and an older build's writes little", () => {
    const never = file();
    boot(never, false, (store) => register(store));
    // An A1 flag-off boot after an enable: the door closes and the fence goes.
    const closed = enabledDatabase();
    expect(boot(closed, false)).toEqual({ state: "off" });
    expect(fenceTriggers(closed)).toBe(0);
    // A build without the door writing to an enabled database: the fence
    // stays, trips on the first row, then costs one point read per row.
    const fenced = enabledDatabase();
    const times = {
      never: writeTime(never, 3000),
      closed: writeTime(closed, 3000),
      fenced: writeTime(fenced, 3000),
    };
    process.stderr.write(
      `3000 flag-off writes (ms, best of 3): ${JSON.stringify(times, (_, v: unknown) => (typeof v === "number" ? Math.round(v) : v))}\n`,
    );
    // Loose bounds: a shared CI runner is noisy. These catch a per-row write
    // or scan, not a few percent.
    expect(times.closed).toBeLessThan(times.never * 1.5);
    expect(times.fenced).toBeLessThan(times.never * 2);
  }, 30_000);
});
