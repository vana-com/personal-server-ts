import Database from "better-sqlite3";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it } from "vitest";
import { BINARY_CHUNKS_MIGRATION, readBinary } from "./pdpp-binary-chunks.js";
import { createReplicaStagingStore } from "./pdpp-replica-staging.js";
import {
  ReplicaByteBudget,
  admit,
} from "@opendatalabs/personal-server-ts-core/replication/limits";

const databases: Database[] = [];
const directories: string[] = [];
const open = () => {
  const db = new Database(":memory:");
  db.exec(BINARY_CHUNKS_MIGRATION);
  databases.push(db);
  return db;
};
afterEach(() => {
  databases.splice(0).forEach((db) => {
    if (db.open) db.close();
  });
  directories
    .splice(0)
    .forEach((directory) =>
      rmSync(directory, { recursive: true, force: true }),
    );
});

function makeAdmission(
  owner = "owner-a",
  repositoryId = "repo-a",
  budget = new ReplicaByteBudget(100),
) {
  const result = admit({ totalBytes: 3, fragments: [{ bytes: 3 }] }, budget, {
    repositoryId,
    owner,
    manifestDigest: "sha256:manifest",
  });
  if ("kind" in result) throw new Error("expected admission");
  return result;
}

function stage(
  store: ReturnType<typeof createReplicaStagingStore>,
  admission = makeAdmission(),
) {
  const bytes = new Uint8Array([1, 2, 3]);
  const hash = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
  const writer = store.begin(admission);
  writer.write(bytes);
  const handle = writer.complete();
  store.verify(handle, { blobId: hash, sha256: hash, sizeBytes: bytes.length });
  return {
    handle,
    bytes,
    expected: { blobId: hash, sha256: hash, sizeBytes: bytes.length },
  };
}

it("E4 rejects foreign owner and repository handles before publishing them", () => {
  const db = open();
  const store = createReplicaStagingStore({
    db,
    repositoryId: "repo-a",
    owner: "owner-a",
  });
  const wrongOwner = stage(store);
  const wrongRepository = stage(store);
  const staged = stage(store);

  expect(() =>
    db.transaction(() =>
      createReplicaStagingStore({
        db,
        repositoryId: "repo-a",
        owner: "owner-b",
      }).attach(wrongOwner.handle, wrongOwner.expected),
    )(),
  ).toThrow();
  expect(() =>
    db.transaction(() =>
      createReplicaStagingStore({
        db,
        repositoryId: "repo-b",
        owner: "owner-a",
      }).attach(wrongRepository.handle, wrongRepository.expected),
    )(),
  ).toThrow();
  expect(
    (
      db
        .prepare(
          "SELECT count(*) AS count FROM pdpp_transport_staged_objects WHERE state='attached'",
        )
        .get() as { count: number }
    ).count,
  ).toBe(0);

  expect(() =>
    db.transaction(() => store.attach(staged.handle, staged.expected))(),
  ).not.toThrow();
  const attachedKey = (
    db
      .prepare(
        "SELECT namespace_key FROM pdpp_transport_staged_objects WHERE state='attached'",
      )
      .get() as {
      namespace_key: string;
    }
  ).namespace_key;
  expect(readBinary(db, "staging", attachedKey)).toEqual(staged.bytes);
});

it("E5 reclaims expired unattached rows and rejects stale handles without publishing", () => {
  const db = open();
  let now = 0;
  const store = createReplicaStagingStore({
    db,
    repositoryId: "repo-a",
    owner: "owner-a",
    now: () => now,
  });
  const staged = stage(store);
  now += store.leaseMs + 1;

  expect(store.cleanup()).toBe(1);
  expect(() => store.attach(staged.handle, staged.expected)).toThrow();
  expect(
    (
      db
        .prepare(
          "SELECT count(*) AS count FROM pdpp_transport_staged_objects WHERE state='attached'",
        )
        .get() as { count: number }
    ).count,
  ).toBe(0);
  expect(
    (
      db
        .prepare(
          "SELECT count(*) AS count FROM pdpp_binary_manifests WHERE namespace='staging'",
        )
        .get() as { count: number }
    ).count,
  ).toBe(0);
});

it("serializes attach and cleanup so an attached object is never reclaimed", () => {
  const db = open();
  let now = 0;
  const store = createReplicaStagingStore({
    db,
    repositoryId: "repo-a",
    owner: "owner-a",
    now: () => now,
  });
  const staged = stage(store);
  db.transaction(() => store.attach(staged.handle, staged.expected))();
  now += store.leaseMs + 1;

  expect(store.cleanup()).toBe(0);
  const attachedKey = (
    db
      .prepare(
        "SELECT namespace_key FROM pdpp_transport_staged_objects WHERE state='attached'",
      )
      .get() as {
      namespace_key: string;
    }
  ).namespace_key;
  expect(readBinary(db, "staging", attachedKey)).toEqual(staged.bytes);
});

it("R1 closes the door between admission and the first chunk without retaining rows", () => {
  const db = open();
  const budget = new ReplicaByteBudget(100);
  const admitted = makeAdmission("owner-a", "repo-a", budget);
  let doorOpen = true;
  const store = createReplicaStagingStore({
    db,
    repositoryId: "repo-a",
    owner: "owner-a",
    assertOpen: () => {
      if (!doorOpen) throw new Error("replication door is closed");
    },
  });
  const writer = store.begin(admitted);
  doorOpen = false;

  expect(() => writer.write(new Uint8Array([1]))).toThrow("door is closed");
  writer.abort();
  expect(
    (
      db
        .prepare("SELECT count(*) AS count FROM pdpp_transport_staged_objects")
        .get() as { count: number }
    ).count,
  ).toBe(0);
  expect(budget.reserved).toBe(0);
});

it("R2 aborts a partially written stream and releases its reservation once", () => {
  const db = open();
  const budget = new ReplicaByteBudget(100);
  const admitted = makeAdmission("owner-a", "repo-a", budget);
  const controller = new AbortController();
  const store = createReplicaStagingStore({
    db,
    repositoryId: "repo-a",
    owner: "owner-a",
    assertOpen: () => controller.signal.throwIfAborted(),
  });
  const writer = store.begin(admitted);
  writer.write(new Uint8Array([1]));
  controller.abort();

  expect(() => writer.write(new Uint8Array([2]))).toThrow();
  writer.abort();
  store.abort(admitted);
  expect(
    (
      db
        .prepare("SELECT count(*) AS count FROM pdpp_transport_staged_objects")
        .get() as { count: number }
    ).count,
  ).toBe(0);
  expect(budget.reserved).toBe(0);
});

it("R3 makes attach and cleanup mutually exclusive in either transaction order", () => {
  const db = open();
  let now = 0;
  const store = createReplicaStagingStore({
    db,
    repositoryId: "repo-a",
    owner: "owner-a",
    now: () => now,
  });
  const attachWins = stage(store);
  now += store.leaseMs + 1;
  db.transaction(() => store.attach(attachWins.handle, attachWins.expected))();
  expect(store.cleanup()).toBe(0);

  const cleanupWins = stage(store);
  now += store.leaseMs + 1;
  expect(store.cleanup()).toBe(1);
  expect(() =>
    db.transaction(() =>
      store.attach(cleanupWins.handle, cleanupWins.expected),
    )(),
  ).toThrow();
  expect(
    (
      db
        .prepare(
          "SELECT count(*) AS count FROM pdpp_transport_staged_objects WHERE state='attached'",
        )
        .get() as { count: number }
    ).count,
  ).toBe(1);
});

it("R4 reopens a verified orphan, reclaims it, and attaches one replay", () => {
  const directory = mkdtempSync(join(tmpdir(), "replica-stage-r4-"));
  directories.push(directory);
  const path = join(directory, "records.sqlite");
  const now = 0;
  const firstDb = new Database(path);
  firstDb.exec(BINARY_CHUNKS_MIGRATION);
  databases.push(firstDb);
  const firstStore = createReplicaStagingStore({
    db: firstDb,
    repositoryId: "repo-a",
    owner: "owner-a",
    now: () => now,
  });
  const oldStage = stage(firstStore);
  firstDb.close();

  const reopened = new Database(path);
  reopened.exec(BINARY_CHUNKS_MIGRATION);
  databases.push(reopened);
  const replayStore = createReplicaStagingStore({
    db: reopened,
    repositoryId: "repo-a",
    owner: "owner-a",
    now: () => now,
  });
  expect(replayStore.reclaimAdmission(makeAdmission())).toBe(1);
  expect(() =>
    replayStore.attach(oldStage.handle, oldStage.expected),
  ).toThrow();

  const replay = stage(replayStore);
  reopened.transaction(() =>
    replayStore.attach(replay.handle, replay.expected),
  )();
  expect(
    (
      reopened
        .prepare(
          "SELECT count(*) AS count FROM pdpp_transport_staged_objects WHERE state='attached'",
        )
        .get() as { count: number }
    ).count,
  ).toBe(1);
  const attachedKey = (
    reopened
      .prepare(
        "SELECT namespace_key FROM pdpp_transport_staged_objects WHERE state='attached'",
      )
      .get() as {
      namespace_key: string;
    }
  ).namespace_key;
  expect(readBinary(reopened, "staging", attachedKey)).toEqual(replay.bytes);
});

it("R5 reopens after attach and reclaims leftover temporary bytes only", () => {
  const directory = mkdtempSync(join(tmpdir(), "replica-stage-r5-"));
  directories.push(directory);
  const path = join(directory, "records.sqlite");
  const firstDb = new Database(path);
  firstDb.exec(BINARY_CHUNKS_MIGRATION);
  databases.push(firstDb);
  const store = createReplicaStagingStore({
    db: firstDb,
    repositoryId: "repo-a",
    owner: "owner-a",
  });
  const staged = stage(store);
  firstDb.transaction(() => store.attach(staged.handle, staged.expected))();
  const key = (
    firstDb
      .prepare(
        "SELECT namespace_key FROM pdpp_transport_staged_objects WHERE state='attached'",
      )
      .get() as {
      namespace_key: string;
    }
  ).namespace_key;
  firstDb.close();

  const reopened = new Database(path);
  reopened.exec(BINARY_CHUNKS_MIGRATION);
  databases.push(reopened);
  const reopenedStore = createReplicaStagingStore({
    db: reopened,
    repositoryId: "repo-a",
    owner: "owner-a",
  });

  expect(reopenedStore.cleanupAttachedTemporaryBytes()).toBe(1);
  expect(
    (
      reopened
        .prepare("SELECT state FROM pdpp_transport_staged_objects")
        .get() as { state: string }
    ).state,
  ).toBe("attached");
  expect(
    (
      reopened
        .prepare(
          "SELECT count(*) AS count FROM pdpp_binary_manifests WHERE namespace='staging'",
        )
        .get() as { count: number }
    ).count,
  ).toBe(0);
  expect(readBinary(reopened, "staging", key)).toBeUndefined();
});
