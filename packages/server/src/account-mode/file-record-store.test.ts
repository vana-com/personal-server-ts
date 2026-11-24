import {
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createFileModeRecordStore } from "./file-record-store.js";

describe("the file mode record store", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "mode-store-"));
  });
  afterEach(() => rm(dir, { recursive: true, force: true }));

  it("loads nothing from a folder that does not exist yet", async () => {
    const store = createFileModeRecordStore(join(dir, "none"));
    expect((await store.load()).size).toBe(0);
  });

  it("round-trips a record and leaves no temp file", async () => {
    const store = createFileModeRecordStore(join(dir, "records"));
    const record = { answer: "on" as const, generation: 2, receivedAt: 5 };
    await store.save("0xabc", record);
    expect((await store.load()).get("0xabc")).toEqual(record);
    expect(await readdir(join(dir, "records"))).toEqual(["0xabc.json"]);
  });

  it("ignores a record that does not parse and reports it", async () => {
    const bad: string[] = [];
    const store = createFileModeRecordStore(dir, {
      onCorrupt: (f) => bad.push(f),
    });
    await writeFile(join(dir, "broken.json"), "{nope");
    await writeFile(
      join(dir, "shape.json"),
      JSON.stringify({ answer: "maybe" }),
    );
    await store.save("good", { answer: "off", generation: 0, receivedAt: 1 });
    const loaded = await store.load();
    expect([...loaded.keys()]).toEqual(["good"]);
    expect(bad.sort()).toEqual(["broken.json", "shape.json"]);
  });

  it("propagates a non-directory storage root instead of treating it as empty", async () => {
    const blocked = join(dir, "not-a-directory");
    await writeFile(blocked, "fixture");
    const store = createFileModeRecordStore(blocked);

    await expect(store.load()).rejects.toMatchObject({ code: "ENOTDIR" });
  });

  it("round-trips the maximum owner name without accepting one character more", async () => {
    const owner = "a".repeat(100);
    const tooLong = owner + "a";
    const record = { answer: "off" as const, generation: 0, receivedAt: 1 };
    const store = createFileModeRecordStore(dir);
    await store.save(owner, record);

    await expect(store.save(tooLong, record)).rejects.toThrow("safe file name");
    const loaded = await createFileModeRecordStore(dir).load();
    expect([...loaded]).toEqual([[owner, record]]);
  });

  it("refuses an owner that is not a safe file name", async () => {
    const store = createFileModeRecordStore(dir);
    await expect(
      store.save("../x", { answer: "on", generation: 0, receivedAt: 0 }),
    ).rejects.toThrow();
  });

  it("surfaces a records path that is a file instead of silently loading nothing", async () => {
    const blocker = join(dir, "not-a-dir");
    await writeFile(blocker, "not a directory");
    const store = createFileModeRecordStore(blocker);
    await expect(store.load()).rejects.toMatchObject({ code: "ENOTDIR" });
  });

  it("reports a directory named like a record file and keeps the good records", async () => {
    const bad: string[] = [];
    const store = createFileModeRecordStore(dir, {
      onCorrupt: (f) => bad.push(f),
    });
    await mkdir(join(dir, "weird.json"));
    await store.save("good", { answer: "off", generation: 0, receivedAt: 1 });
    const loaded = await store.load();
    expect([...loaded.keys()]).toEqual(["good"]);
    expect(bad).toEqual(["weird.json"]);
  });

  it("refuses to save when the records path is blocked by a file and leaves it untouched", async () => {
    const blocker = join(dir, "not-a-dir");
    await writeFile(blocker, "keep me");
    const store = createFileModeRecordStore(blocker);
    await expect(
      store.save("good", { answer: "on", generation: 0, receivedAt: 0 }),
    ).rejects.toThrow();
    expect(await readFile(blocker, "utf8")).toBe("keep me");
  });

  it("ignores a leftover temp file from an interrupted save", async () => {
    const store = createFileModeRecordStore(dir);
    await writeFile(
      join(dir, ".good.0123456789ab.tmp"),
      JSON.stringify({ answer: "on", generation: 9, receivedAt: 9 }),
    );
    await store.save("good", { answer: "off", generation: 0, receivedAt: 1 });
    const loaded = await store.load();
    expect([...loaded.keys()]).toEqual(["good"]);
    expect(loaded.get("good")).toEqual({
      answer: "off",
      generation: 0,
      receivedAt: 1,
    });
  });
});
