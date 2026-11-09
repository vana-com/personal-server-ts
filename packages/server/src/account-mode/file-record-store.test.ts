import {
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ModeStoreConflictError,
  ModeStoreOwnedError,
  tombstoneRecord,
  type DurableModeRecord,
  type ModeRecordStore,
  type ModeStoreLease,
} from "@opendatalabs/personal-server-ts-core/sync/account-mode";
import { createFileModeRecordStore } from "./file-record-store.js";

const A = "0x1111111111111111111111111111111111111111";

const ON: DurableModeRecord = {
  switched: true,
  switchedAt: 12,
  cleanOffAt: null,
  offFetchStartMono: null,
  bootId: "b",
  importPending: false,
};
const ON_OWED: DurableModeRecord = { ...ON, importPending: true };
const OFF: DurableModeRecord = {
  switched: false,
  switchedAt: null,
  cleanOffAt: 3,
  offFetchStartMono: 3,
  bootId: "b",
  importPending: false,
};

const ASIDE = /\.corrupt-/;
const LOCK_FILES = [".mode-owner.lock.db", ".mode-owner.lock.db-journal"];

/** The folder's entries without the lock database's own files. */
async function entries(dir: string): Promise<string[]> {
  return (await readdir(dir)).filter((n) => !LOCK_FILES.includes(n)).sort();
}

describe("the file record store", () => {
  let dir: string;
  const leases: ModeStoreLease[] = [];
  /** A store that holds the folder until the test ends. */
  async function owner(
    folder = dir,
    options?: Parameters<typeof createFileModeRecordStore>[1],
  ): Promise<ModeRecordStore> {
    const store = createFileModeRecordStore(folder, options);
    leases.push(await store.claim());
    return store;
  }
  beforeEach(async () => {
    dir = await mkdtemp(join(process.env.HOME ?? "", ".tmp", "mode-records-"));
  });
  afterEach(async () => {
    for (const lease of leases.splice(0)) await lease.release();
    await rm(dir, { recursive: true, force: true });
  });

  it("loads nothing from a folder that does not exist yet", async () => {
    const store = await owner(join(dir, "fresh"));
    expect((await store.load()).size).toBe(0);
  });

  it("round-trips a record per owner", async () => {
    const store = await owner();
    await store.save(A, ON, null);
    await store.save("b", OFF, null);
    const loaded = await store.load();
    expect(loaded.get(A)).toEqual(ON);
    expect(loaded.get("b")?.switched).toBe(false);
  });

  it("leaves no temp file behind and replaces a record in place", async () => {
    const store = await owner();
    await store.save(A, OFF, null);
    await store.save(A, ON, OFF);
    expect(await entries(dir)).toEqual([`${A}.json`]);
    expect(JSON.parse(await readFile(join(dir, `${A}.json`), "utf8"))).toEqual(
      ON,
    );
  });

  it("refuses an owner name that is not a safe file name", async () => {
    const store = await owner();
    for (const owner of ["../escape", "a/b", "", "A B", "x".repeat(101)]) {
      await expect(store.save(owner, ON, null), owner).rejects.toThrow();
    }
    expect(await entries(dir)).toEqual([]);
  });

  it("sweeps the temp file of a crashed save when it becomes the owner, and at no other time", async () => {
    await writeFile(join(dir, `.tmp-${A}-abc`), "half");
    const store = createFileModeRecordStore(dir);
    // Not owning: nothing is read and nothing is deleted.
    await expect(store.load()).rejects.toBeInstanceOf(ModeStoreOwnedError);
    expect(await readdir(dir)).toEqual([`.tmp-${A}-abc`]);
    const lease = await store.claim();
    leases.push(lease);
    expect(await entries(dir)).toEqual([]);
    await writeFile(join(dir, `.tmp-${A}-def`), "in progress");
    await store.load();
    expect(await entries(dir)).toEqual([`.tmp-${A}-def`]);
  });

  // SECOND_RUNTIME_ADMITTED
  it("lets one store own the folder, and a second touches none of its files", async () => {
    const first = createFileModeRecordStore(dir);
    const lease = await first.claim();
    // The owner is mid-save: its temp file is on disk.
    await writeFile(join(dir, `.tmp-${A}-active`), "being written");
    const second = createFileModeRecordStore(dir);
    await expect(second.claim()).rejects.toBeInstanceOf(ModeStoreOwnedError);
    await expect(second.load()).rejects.toBeInstanceOf(ModeStoreOwnedError);
    expect(await readdir(dir)).toContain(`.tmp-${A}-active`);
    await first.save(A, ON, null);
    await lease.release();
    const taken = await second.claim();
    await taken.release();
  });

  // BLIND_OFF_OVERWRITES_ON
  it("rejects an Off over a stored On and a write based on a stale read, leaving the file as it was", async () => {
    const store = await owner();
    await store.save(A, OFF, null);
    await store.save(A, ON, OFF);
    await expect(store.save(A, OFF, ON)).rejects.toBeInstanceOf(
      ModeStoreConflictError,
    );
    await expect(
      store.save(A, { ...ON, switchedAt: 99 }, OFF),
    ).rejects.toBeInstanceOf(ModeStoreConflictError);
    await expect(store.save(A, ON, null)).rejects.toBeInstanceOf(
      ModeStoreConflictError,
    );
    expect(JSON.parse(await readFile(join(dir, `${A}.json`), "utf8"))).toEqual(
      ON,
    );
    expect((await readdir(dir)).filter((n) => n.startsWith(".tmp-"))).toEqual(
      [],
    );
  });

  // GENERATION_NOT_PERSISTED
  it("keeps a generation on disk, reads a record without one as generation 0, and lets only a higher Off replace an On", async () => {
    const store = await owner();
    const at3 = { ...ON, generation: 3 };
    await store.save(A, at3, null);
    expect(JSON.parse(await readFile(join(dir, `${A}.json`), "utf8"))).toEqual(
      at3,
    );
    const lowerOff = { ...OFF, generation: 3 };
    await expect(store.save(A, lowerOff, at3)).rejects.toBeInstanceOf(
      ModeStoreConflictError,
    );
    await expect(store.save(A, OFF, at3)).rejects.toBeInstanceOf(
      ModeStoreConflictError,
    );
    const reset = { ...OFF, generation: 4 };
    await store.save(A, reset, at3);
    expect((await store.load()).get(A)).toEqual(reset);
    expect(JSON.parse(await readFile(join(dir, `${A}.json`), "utf8"))).toEqual(
      reset,
    );
  });

  it("sets aside a record whose generation is not a non-negative integer", async () => {
    await writeFile(
      join(dir, `${A}.json`),
      JSON.stringify({ ...ON, generation: -1 }),
    );
    const store = await owner();
    expect((await store.load()).get(A)).toEqual(tombstoneRecord());
  });

  it("reads a record written before importPending existed as having none", async () => {
    const { importPending: _drop, ...old } = ON;
    await writeFile(join(dir, `${A}.json`), JSON.stringify(old));
    const store = await owner();
    expect((await store.load()).get(A)).toEqual(ON);
  });
});

describe("an unreadable record in the file store", () => {
  let dir: string;
  const leases: ModeStoreLease[] = [];
  async function owner(
    options?: Parameters<typeof createFileModeRecordStore>[1],
  ): Promise<ModeRecordStore> {
    const store = createFileModeRecordStore(dir, options);
    leases.push(await store.claim());
    return store;
  }
  const restart = async () => {
    for (const lease of leases.splice(0)) await lease.release();
    return owner();
  };
  beforeEach(async () => {
    dir = await mkdtemp(join(process.env.HOME ?? "", ".tmp", "mode-records-"));
  });
  afterEach(async () => {
    for (const lease of leases.splice(0)) await lease.release();
    await rm(dir, { recursive: true, force: true });
  });

  // QUARANTINE_FORGETS_ON
  it("is kept aside, never deleted, and its owner loads as a tombstone, not as never seen", async () => {
    await writeFile(join(dir, `${A}.json`), "{not json");
    await writeFile(
      join(dir, "b.json"),
      JSON.stringify({ ...ON, switched: "yes" }),
    );
    await writeFile(join(dir, "c.json"), JSON.stringify(ON));
    const onCorrupt = vi.fn();
    const store = await owner({ onCorrupt });
    const loaded = await store.load();
    expect([...loaded.keys()].sort()).toEqual([A, "b", "c"]);
    expect(loaded.get(A)).toEqual(tombstoneRecord());
    expect(loaded.get("b")).toEqual(tombstoneRecord());
    expect(loaded.get("c")).toEqual(ON);
    expect(onCorrupt).toHaveBeenCalledTimes(2);
    const names = await readdir(dir);
    const aside = names.filter((n) => ASIDE.test(n));
    expect(aside).toHaveLength(2);
    // The bytes that could not be read are still there.
    const kept = await Promise.all(
      aside.map((n) => readFile(join(dir, n), "utf8")),
    );
    expect(kept).toContain("{not json");
    // The record files themselves now hold tombstones.
    expect(JSON.parse(await readFile(join(dir, `${A}.json`), "utf8"))).toEqual(
      tombstoneRecord(),
    );
  });

  it("stays a tombstone across restarts and makes no further copies", async () => {
    await writeFile(join(dir, `${A}.json`), "garbage");
    const first = await owner();
    await first.load();
    for (let i = 0; i < 3; i += 1) {
      const store = await restart();
      expect((await store.load()).get(A)).toEqual(tombstoneRecord());
    }
    expect((await readdir(dir)).filter((n) => ASIDE.test(n))).toHaveLength(1);
  });

  it("accepts an On with the import owed over a tombstone, and nothing else", async () => {
    await writeFile(join(dir, `${A}.json`), "garbage");
    const store = await owner();
    const tomb = (await store.load()).get(A)!;
    await expect(store.save(A, OFF, tomb)).rejects.toBeInstanceOf(
      ModeStoreConflictError,
    );
    await expect(store.save(A, ON, tomb)).rejects.toBeInstanceOf(
      ModeStoreConflictError,
    );
    await expect(store.save(A, tomb, tomb)).rejects.toBeInstanceOf(
      ModeStoreConflictError,
    );
    await store.save(A, ON_OWED, tomb);
    expect((await store.load()).get(A)).toEqual(ON_OWED);
    expect(
      JSON.parse(await readFile(join(dir, `${A}.json`), "utf8")),
    ).not.toHaveProperty("historyUnknown");
  });

  it("never lets save write a tombstone over an On", async () => {
    const store = await owner();
    await store.save(A, ON, null);
    await expect(store.save(A, tombstoneRecord(), ON)).rejects.toBeInstanceOf(
      ModeStoreConflictError,
    );
    expect((await store.load()).get(A)).toEqual(ON);
  });

  it("is stable through a second corrupt-then-heal cycle", async () => {
    await writeFile(join(dir, `${A}.json`), "garbage one");
    let store = await owner();
    let tomb = (await store.load()).get(A)!;
    await store.save(A, ON_OWED, tomb);
    store = await restart();
    expect((await store.load()).get(A)).toEqual(ON_OWED);

    await writeFile(join(dir, `${A}.json`), "garbage two");
    store = await restart();
    tomb = (await store.load()).get(A)!;
    expect(tomb).toEqual(tombstoneRecord());
    await store.save(A, ON_OWED, tomb);
    store = await restart();
    expect((await store.load()).get(A)).toEqual(ON_OWED);
    const kept = await Promise.all(
      (await readdir(dir))
        .filter((n) => ASIDE.test(n))
        .map((n) => readFile(join(dir, n), "utf8")),
    );
    expect(kept.sort()).toEqual(["garbage one", "garbage two"]);
  });

  it("an unreadable file at a record's name that is not a file stops the load rather than guessing", async () => {
    await mkdir(join(dir, "x.json"));
    const store = await owner();
    await expect(store.load()).rejects.toThrow();
    expect((await readdir(dir)).filter((n) => ASIDE.test(n))).toEqual([]);
  });
});
