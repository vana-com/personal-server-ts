import { spawnSync } from "node:child_process";
import { mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { hostname, tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ModeStoreConflictError,
  ModeStoreOwnedError,
  createModeAuthority,
  type DurableModeRecord,
} from "@opendatalabs/personal-server-ts-core/sync/account-mode";
import { createFileModeRecordStore } from "./file-record-store.js";

const A = "0x1111111111111111111111111111111111111111";
const hostnameOf = () => hostname();

const ON: DurableModeRecord = {
  switched: true,
  switchedAt: 12,
  cleanOffAt: null,
  offFetchStartMono: null,
  bootId: "b",
  importPending: false,
};
const OFF: DurableModeRecord = {
  switched: false,
  switchedAt: null,
  cleanOffAt: 3,
  offFetchStartMono: 3,
  bootId: "b",
  importPending: false,
};

describe("the file record store", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "mode-records-"));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("loads nothing from a folder that does not exist yet", async () => {
    const store = createFileModeRecordStore(join(dir, "fresh"));
    expect((await store.load()).size).toBe(0);
  });

  it("round-trips a record per owner", async () => {
    const store = createFileModeRecordStore(dir);
    await store.save(A, ON, null);
    await store.save("b", OFF, null);
    const loaded = await createFileModeRecordStore(dir).load();
    expect(loaded.get(A)).toEqual(ON);
    expect(loaded.get("b")?.switched).toBe(false);
  });

  it("leaves no temp file behind and replaces a record in place", async () => {
    const store = createFileModeRecordStore(dir);
    await store.save(A, OFF, null);
    await store.save(A, ON, OFF);
    expect((await readdir(dir)).sort()).toEqual([`${A}.json`]);
    expect(JSON.parse(await readFile(join(dir, `${A}.json`), "utf8"))).toEqual(
      ON,
    );
  });

  it("refuses an owner name that is not a safe file name", async () => {
    const store = createFileModeRecordStore(dir);
    for (const owner of ["../escape", "a/b", "", "A B", "x".repeat(101)]) {
      await expect(store.save(owner, ON, null), owner).rejects.toThrow();
    }
    expect(await readdir(dir)).toEqual([]);
  });

  it("moves a corrupt record aside, never deletes it, and loads that owner as never seen", async () => {
    await writeFile(join(dir, `${A}.json`), "{not json");
    await writeFile(
      join(dir, "b.json"),
      JSON.stringify({ ...ON, switched: "yes" }),
    );
    await writeFile(join(dir, "c.json"), JSON.stringify(ON));
    const onCorrupt = vi.fn();
    const loaded = await createFileModeRecordStore(dir, { onCorrupt }).load();
    expect([...loaded.keys()]).toEqual(["c"]);
    expect(onCorrupt).toHaveBeenCalledTimes(2);
    const names = await readdir(dir);
    expect(names.filter((n) => n.includes(".corrupt-"))).toHaveLength(2);
    expect(names).not.toContain(`${A}.json`);
  });

  it("sweeps the temp file of a crashed save when it becomes the owner, and at no other time", async () => {
    await writeFile(join(dir, `.tmp-${A}-abc`), "half");
    const store = createFileModeRecordStore(dir);
    // Reading is not owning: it deletes nothing.
    await store.load();
    expect(await readdir(dir)).toEqual([`.tmp-${A}-abc`]);
    const lease = await store.claim();
    expect(await readdir(dir)).toEqual([".owner.lock"]);
    await writeFile(join(dir, `.tmp-${A}-def`), "in progress");
    await store.load();
    expect((await readdir(dir)).sort()).toEqual([
      ".owner.lock",
      `.tmp-${A}-def`,
    ]);
    await lease.release();
  });

  // SECOND_RUNTIME_ADMITTED
  it("lets one runtime own the folder, and refuses a second without touching its files", async () => {
    const first = createFileModeRecordStore(dir);
    const lease = await first.claim();
    // The owner is mid-save: its temp file is on disk.
    await writeFile(join(dir, `.tmp-${A}-active`), "being written");
    const second = createFileModeRecordStore(dir);
    await expect(second.claim()).rejects.toBeInstanceOf(ModeStoreOwnedError);
    await second.load();
    expect(await readdir(dir)).toContain(`.tmp-${A}-active`);
    await lease.release();
    const taken = await second.claim();
    await taken.release();
  });

  it("takes over a lock whose process is gone, and keeps one held by a live process", async () => {
    const dead = spawnSync(process.execPath, ["-e", ""]).pid;
    const hold = (pid: number) =>
      writeFile(
        join(dir, ".owner.lock"),
        JSON.stringify({ pid, host: hostnameOf(), token: "t" }),
      );
    await hold(dead);
    const lease = await createFileModeRecordStore(dir).claim();
    await lease.release();
    await hold(process.pid);
    await expect(createFileModeRecordStore(dir).claim()).rejects.toBeInstanceOf(
      ModeStoreOwnedError,
    );
    // A lock from another machine is never judged stale.
    await writeFile(
      join(dir, ".owner.lock"),
      JSON.stringify({ pid: dead, host: "elsewhere", token: "t" }),
    );
    await expect(createFileModeRecordStore(dir).claim()).rejects.toBeInstanceOf(
      ModeStoreOwnedError,
    );
  });

  it("two authorities on the folder: the second is refused and its Off never reaches the disk", async () => {
    const first = createModeAuthority({
      store: createFileModeRecordStore(dir),
      bootId: "boot-1",
    });
    await first.ready;
    const second = createModeAuthority({
      store: createFileModeRecordStore(dir),
      bootId: "boot-2",
    });
    await second.ready.catch(() => undefined);
    const off = {
      owner: A,
      authOwner: A,
      state: "off" as const,
      fetchStartedAt: Date.now(),
      rawStatus: 200,
    };
    expect(await second.submitEvidence(off)).toMatchObject({
      code: "ACCOUNT_MODE_STORE_OWNED",
    });
    expect(second.admit(A, "op").kind).toBe("refuse");
    expect(await readdir(dir)).toEqual([".owner.lock"]);
    await first.submitEvidence({ ...off, state: "on" });
    expect(second.read(A)).toMatchObject({ code: "ACCOUNT_MODE_STORE_OWNED" });
    await first.close();
  });

  // BLIND_OFF_OVERWRITES_ON
  it("rejects an Off over a stored On and a write based on a stale read, leaving the file as it was", async () => {
    const store = createFileModeRecordStore(dir);
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

  it("reads a record written before importPending existed as having none", async () => {
    const { importPending: _drop, ...old } = ON;
    await writeFile(join(dir, `${A}.json`), JSON.stringify(old));
    expect((await createFileModeRecordStore(dir).load()).get(A)).toEqual(ON);
  });

  // LATCH_NOT_DURABLE
  it("keeps an On across a restart that wipes the data folder", async () => {
    const modeDir = join(dir, "account-mode");
    const dataDir = join(dir, "data");
    const first = createModeAuthority({
      store: createFileModeRecordStore(modeDir),
      bootId: "boot-1",
    });
    await first.ready;
    await first.submitEvidence({
      owner: A,
      authOwner: A,
      state: "on",
      fetchStartedAt: Date.now(),
      rawStatus: 200,
    });
    await rm(dataDir, { recursive: true, force: true });
    await first.close();
    const second = createModeAuthority({
      store: createFileModeRecordStore(modeDir),
      bootId: "boot-2",
    });
    await second.ready;
    expect(second.read(A).kind).toBe("streams");
  });
});
