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

  it("rejects owner names that only look safe: capitals, dots, empty", async () => {
    const store = createFileModeRecordStore(dir);
    const record = { answer: "off" as const, generation: 0, receivedAt: 1 };
    await expect(store.save("Good", record)).rejects.toThrow("safe file name");
    await expect(store.save("a.b", record)).rejects.toThrow("safe file name");
    await expect(store.save("", record)).rejects.toThrow("safe file name");
    expect(await readdir(dir)).toEqual([]);
  });

  it("silently skips record files whose names cannot be owners", async () => {
    const bad: string[] = [];
    const store = createFileModeRecordStore(dir, {
      onCorrupt: (f) => bad.push(f),
    });
    const record = { answer: "on" as const, generation: 3, receivedAt: 7 };
    await writeFile(join(dir, "GOOD.json"), JSON.stringify(record));
    await writeFile(
      join(dir, `${"b".repeat(101)}.json`),
      JSON.stringify(record),
    );
    await store.save("good", { answer: "off", generation: 0, receivedAt: 1 });
    const loaded = await store.load();
    expect([...loaded.keys()]).toEqual(["good"]);
    expect(bad).toEqual([]);
  });

  it("reports binary garbage, an empty file and a JSON scalar as corrupt and keeps the good records", async () => {
    const bad: string[] = [];
    const store = createFileModeRecordStore(dir, {
      onCorrupt: (f) => bad.push(f),
    });
    await writeFile(join(dir, "binary.json"), Buffer.from([0xff, 0xfe, 0x7b]));
    await writeFile(join(dir, "empty.json"), "");
    await writeFile(join(dir, "scalar.json"), "123");
    await store.save("good", { answer: "off", generation: 0, receivedAt: 1 });
    const loaded = await store.load();
    expect([...loaded.keys()]).toEqual(["good"]);
    expect(bad.sort()).toEqual(["binary.json", "empty.json", "scalar.json"]);
  });

  it("refuses to save over a directory wearing a record name and leaves it alone", async () => {
    const store = createFileModeRecordStore(dir);
    await mkdir(join(dir, "good.json"));
    const record = { answer: "on" as const, generation: 0, receivedAt: 0 };
    await expect(store.save("good", record)).rejects.toThrow();
    expect((await store.load()).size).toBe(0);
    expect(await readdir(join(dir, "good.json"))).toEqual([]);
    expect(await readdir(dir)).toEqual(["good.json"]);
  });

  it("loads a valid owner even when reporting invalid JSON throws", async () => {
    const reported: string[] = [];
    const store = createFileModeRecordStore(dir, {
      onCorrupt: (name) => {
        reported.push(name);
        throw new Error("synthetic diagnostic failure");
      },
    });
    await writeFile(join(dir, "broken.json"), "{nope");
    const good = { answer: "off" as const, generation: 2, receivedAt: 1 };
    await store.save("good", good);

    expect([...(await store.load())]).toEqual([["good", good]]);
    expect(reported).toEqual(["broken.json"]);
  });

  it("reports a schema-invalid record exactly once even when the sink throws", async () => {
    const reported: string[] = [];
    const store = createFileModeRecordStore(dir, {
      onCorrupt: (name) => {
        reported.push(name);
        throw new Error("synthetic diagnostic failure");
      },
    });
    await writeFile(
      join(dir, "shape.json"),
      JSON.stringify({ answer: "maybe" }),
    );

    expect((await store.load()).size).toBe(0);
    expect(reported).toEqual(["shape.json"]);
  });
});
