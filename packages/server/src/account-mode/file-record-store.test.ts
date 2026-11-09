import { mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  createModeAuthority,
  type OwnerModeRecord,
} from "@opendatalabs/personal-server-ts-core/sync/account-mode";
import { createFileModeRecordStore } from "./file-record-store.js";

const A = "0x1111111111111111111111111111111111111111";

const ON: OwnerModeRecord = {
  switched: true,
  switchedAt: 12,
  cleanOffAt: null,
  offFetchStartMono: null,
  bootId: "b",
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
    await store.save(A, ON);
    await store.save("b", { ...ON, switched: false });
    const loaded = await createFileModeRecordStore(dir).load();
    expect(loaded.get(A)).toEqual(ON);
    expect(loaded.get("b")?.switched).toBe(false);
  });

  it("leaves no temp file behind and replaces a record in place", async () => {
    const store = createFileModeRecordStore(dir);
    await store.save(A, { ...ON, switched: false });
    await store.save(A, ON);
    expect((await readdir(dir)).sort()).toEqual([`${A}.json`]);
    expect(JSON.parse(await readFile(join(dir, `${A}.json`), "utf8"))).toEqual(
      ON,
    );
  });

  it("refuses an owner name that is not a safe file name", async () => {
    const store = createFileModeRecordStore(dir);
    for (const owner of ["../escape", "a/b", "", "A B", "x".repeat(101)]) {
      await expect(store.save(owner, ON), owner).rejects.toThrow();
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

  it("sweeps the temp file of a crashed save on the first load only", async () => {
    await writeFile(join(dir, `.tmp-${A}-abc`), "half");
    const store = createFileModeRecordStore(dir);
    await store.load();
    expect(await readdir(dir)).toEqual([]);
    await writeFile(join(dir, `.tmp-${A}-def`), "in progress");
    await store.load();
    expect(await readdir(dir)).toEqual([`.tmp-${A}-def`]);
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
    const second = createModeAuthority({
      store: createFileModeRecordStore(modeDir),
      bootId: "boot-2",
    });
    await second.ready;
    expect(second.read(A).kind).toBe("streams");
  });
});
