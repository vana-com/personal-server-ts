import { describe, expect, it } from "vitest";
import { MemoryFixtureSink, writeJsonArray } from "./sink.js";

describe("MemoryFixtureSink", () => {
  it("round-trips written chunks", async () => {
    const sink = new MemoryFixtureSink();
    const file = await sink.open("a.json");
    await file.write("[1,");
    await file.write("2]");
    await file.close();
    expect(await sink.read("a.json")).toBe("[1,2]");
    expect(await sink.list()).toEqual(["a.json"]);
    expect(await sink.size("a.json")).toBe(5);
  });

  it("refuses to write the same file twice", async () => {
    const sink = new MemoryFixtureSink();
    await sink.open("a.json");
    await expect(sink.open("a.json")).rejects.toThrow(/already written/);
  });

  it("throws for an unknown file", async () => {
    const sink = new MemoryFixtureSink();
    await expect(sink.read("missing.json")).rejects.toThrow(
      /no such fixture file/,
    );
  });
});

describe("writeJsonArray", () => {
  it("emits a valid JSON array and returns the record count", async () => {
    const sink = new MemoryFixtureSink();
    const count = await writeJsonArray(sink, "rows.json", [{ a: 1 }, { a: 2 }]);
    expect(count).toBe(2);
    expect(JSON.parse(await sink.read("rows.json"))).toEqual([
      { a: 1 },
      { a: 2 },
    ]);
  });

  it("emits an empty array for no records", async () => {
    const sink = new MemoryFixtureSink();
    const count = await writeJsonArray(sink, "empty.json", []);
    expect(count).toBe(0);
    expect(JSON.parse(await sink.read("empty.json"))).toEqual([]);
  });
});
