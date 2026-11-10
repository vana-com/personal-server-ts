import { mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createFileModeRecordStore } from "./file-record-store.js";

describe("the file mode record store", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(process.env.HOME ?? "", ".tmp", "mode-store-"));
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

  it("refuses an owner that is not a safe file name", async () => {
    const store = createFileModeRecordStore(dir);
    await expect(
      store.save("../x", { answer: "on", generation: 0, receivedAt: 0 }),
    ).rejects.toThrow();
  });
});
