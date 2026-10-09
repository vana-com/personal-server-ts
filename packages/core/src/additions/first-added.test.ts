import { describe, expect, it } from "vitest";

import {
  buildFirstAddedLedger,
  extractRecordKeys,
  FIRST_ADDED_KEY,
  hasReservedFirstAddedKey,
  listFirstAddedTimestamps,
  readFirstAddedLedger,
  stampFirstAdded,
  type FirstAddedLedger,
} from "./first-added.js";

const T1 = "2024-01-01T00:00:00.000Z";
const T2 = "2024-01-02T00:00:00.000Z";
const T3 = "2024-01-03T00:00:00.000Z";

const HASH_KEY = /^h:[0-9a-f]{32}$/;

describe("extractRecordKeys", () => {
  it("uses id for legacy array objects", async () => {
    await expect(
      extractRecordKeys({ conversations: [{ id: "a" }, { id: "b" }] }),
    ).resolves.toEqual(["conversations:i:a", "conversations:i:b"]);
  });

  it("accepts a numeric id and falls back through uuid, key, uri, url in order", async () => {
    await expect(extractRecordKeys({ items: [{ id: 7 }] })).resolves.toEqual([
      "items:i:7",
    ]);
    await expect(
      extractRecordKeys({
        items: [
          { id: "id", uuid: "uuid", key: "key", uri: "uri", url: "url" },
          { uuid: "uuid", key: "key", uri: "uri", url: "url" },
          { key: "key", uri: "uri", url: "url" },
          { uri: "uri", url: "url" },
          { url: "url" },
        ],
      }),
    ).resolves.toEqual([
      "items:i:id",
      "items:i:uuid",
      "items:i:key",
      "items:i:uri",
      "items:i:url",
    ]);
  });

  it("skips non-qualifying id candidates", async () => {
    await expect(
      extractRecordKeys({ items: [{ id: "", uuid: 5 }] }),
    ).resolves.toEqual(["items:i:5"]);
    await expect(
      extractRecordKeys({ items: [{ id: Number.NaN }] }),
    ).resolves.toEqual([expect.stringMatching(/^items:h:[0-9a-f]{32}$/)]);
  });

  it("hashes objects without an id with 32 hex chars, stable across property order", async () => {
    const [first] = await extractRecordKeys({
      items: [{ a: 1, b: 2 }],
    });
    const [reordered] = await extractRecordKeys({
      items: [{ b: 2, a: 1 }],
    });
    const [different] = await extractRecordKeys({
      items: [{ a: 1, b: 3 }],
    });
    expect(first.slice("items:".length)).toMatch(HASH_KEY);
    expect(first).toBe(reordered);
    expect(first).not.toBe(different);
  });

  it("hashes non-object array elements", async () => {
    const keys = await extractRecordKeys({
      tags: ["x", 5, null, [1, 2]],
    });
    expect(keys).not.toBeNull();
    for (const key of keys ?? []) {
      expect(key.slice("tags:".length)).toMatch(HASH_KEY);
    }
  });

  it("de-duplicates keys keeping first-seen order", async () => {
    await expect(
      extractRecordKeys({
        conversations: [{ id: "a" }, { id: "a" }, { id: "b" }],
      }),
    ).resolves.toEqual(["conversations:i:a", "conversations:i:b"]);
  });

  it("reads the PDPP records form", async () => {
    await expect(
      extractRecordKeys({ records: [{ stream: "posts", data: { id: 1 } }] }),
    ).resolves.toEqual(["posts:i:1"]);
  });

  it("ignores $ prefixed top-level keys", async () => {
    await expect(
      extractRecordKeys({
        $lineage: [{ id: "a" }],
        conversations: [{ id: "a" }],
      }),
    ).resolves.toEqual(["conversations:i:a"]);
    await expect(
      extractRecordKeys({ $lineage: [{ id: "a" }] }),
    ).resolves.toEqual(["_"]);
  });

  it("returns null when $binary is present", async () => {
    await expect(extractRecordKeys({ $binary: "AAAA" })).resolves.toBeNull();
    await expect(
      extractRecordKeys({ $binary: undefined, conversations: [{ id: "a" }] }),
    ).resolves.toBeNull();
  });

  it("returns ['_'] when there are no top-level arrays and [] when all are empty", async () => {
    await expect(extractRecordKeys({ name: "Bob", age: 3 })).resolves.toEqual([
      "_",
    ]);
    await expect(
      extractRecordKeys({ conversations: [], messages: [] }),
    ).resolves.toEqual([]);
  });
});

describe("buildFirstAddedLedger", () => {
  it("Case C marks every first-snapshot record with collectedAt", async () => {
    const ledger = await buildFirstAddedLedger({
      previousData: null,
      newData: { conversations: [{ id: "a" }, { id: "b" }] },
      collectedAt: T1,
    });
    expect(ledger).toEqual({
      version: 1,
      trackedSince: T1,
      records: { "conversations:i:a": T1, "conversations:i:b": T1 },
    });
  });

  it("Case A adds nothing on an unchanged re-import", async () => {
    const data = { conversations: [{ id: "a" }] };
    const previous = await buildFirstAddedLedger({
      previousData: null,
      newData: data,
      collectedAt: T1,
    });
    const ledger = await buildFirstAddedLedger({
      previousData: stampFirstAdded(data, previous!),
      newData: { conversations: [{ id: "a" }] },
      collectedAt: T2,
    });
    expect(ledger?.records).toEqual(previous?.records);
    expect(ledger?.trackedSince).toBe(T1);
  });

  it("Case A dates a new record now while old records keep theirs", async () => {
    const previous = await buildFirstAddedLedger({
      previousData: null,
      newData: { conversations: [{ id: "a" }] },
      collectedAt: T1,
    });
    const ledger = await buildFirstAddedLedger({
      previousData: stampFirstAdded(
        { conversations: [{ id: "a" }] },
        previous!,
      ),
      newData: { conversations: [{ id: "a" }, { id: "b" }] },
      collectedAt: T2,
    });
    expect(ledger?.records).toEqual({
      "conversations:i:a": T1,
      "conversations:i:b": T2,
    });
  });

  it("Case A keeps a record missing from a snapshot and restores its original timestamp", async () => {
    const snap1 = { conversations: [{ id: "a" }, { id: "b" }] };
    const ledger1 = await buildFirstAddedLedger({
      previousData: null,
      newData: snap1,
      collectedAt: T1,
    });
    const snap2 = { conversations: [{ id: "a" }] };
    const ledger2 = await buildFirstAddedLedger({
      previousData: stampFirstAdded(snap1, ledger1!),
      newData: snap2,
      collectedAt: T2,
    });
    expect(ledger2?.records["conversations:i:b"]).toBe(T1);
    const ledger3 = await buildFirstAddedLedger({
      previousData: stampFirstAdded(snap2, ledger2!),
      newData: { conversations: [{ id: "a" }, { id: "b" }] },
      collectedAt: T3,
    });
    expect(ledger3?.records["conversations:i:b"]).toBe(T1);
    expect(ledger3?.trackedSince).toBe(T1);
  });

  it("Case B nulls pre-tracking records and dates genuinely new ones", async () => {
    const ledger = await buildFirstAddedLedger({
      previousData: { conversations: [{ id: "a" }] },
      newData: { conversations: [{ id: "a" }, { id: "b" }] },
      collectedAt: T2,
    });
    expect(ledger).toEqual({
      version: 1,
      trackedSince: T2,
      records: {
        "conversations:i:a": null,
        "conversations:i:b": T2,
      },
    });
  });

  it("Case B then Case A keeps a pre-tracking record null", async () => {
    const preTracking = { conversations: [{ id: "a" }] };
    const caseB = await buildFirstAddedLedger({
      previousData: preTracking,
      newData: { conversations: [{ id: "a" }, { id: "b" }] },
      collectedAt: T2,
    });
    const caseA = await buildFirstAddedLedger({
      previousData: stampFirstAdded(
        { conversations: [{ id: "a" }, { id: "b" }] },
        caseB!,
      ),
      newData: { conversations: [{ id: "a" }, { id: "b" }] },
      collectedAt: T3,
    });
    expect(caseA?.records["conversations:i:a"]).toBeNull();
    expect(caseA?.records["conversations:i:b"]).toBe(T2);
  });

  it("returns null for untrackable newData", async () => {
    await expect(
      buildFirstAddedLedger({
        previousData: null,
        newData: { $binary: "AAAA" },
        collectedAt: T1,
      }),
    ).resolves.toBeNull();
  });

  it("treats a malformed previous ledger as Case B", async () => {
    const ledger = await buildFirstAddedLedger({
      previousData: {
        conversations: [{ id: "a" }],
        [FIRST_ADDED_KEY]: "nope",
      },
      newData: { conversations: [{ id: "a" }, { id: "b" }] },
      collectedAt: T2,
    });
    expect(ledger).toEqual({
      version: 1,
      trackedSince: T2,
      records: {
        "conversations:i:a": null,
        "conversations:i:b": T2,
      },
    });
  });

  it("does not mutate its inputs", async () => {
    const previousData = {
      conversations: [{ id: "a" }],
      [FIRST_ADDED_KEY]: {
        version: 1,
        trackedSince: T1,
        records: { "conversations:i:a": T1 },
      },
    };
    const newData = { conversations: [{ id: "a" }, { id: "b" }] };
    const previousClone = structuredClone(previousData);
    const newClone = structuredClone(newData);
    await buildFirstAddedLedger({ previousData, newData, collectedAt: T2 });
    expect(previousData).toEqual(previousClone);
    expect(newData).toEqual(newClone);
  });

  it("stores a __proto__ id as an own property without polluting prototypes", async () => {
    const ledger = await buildFirstAddedLedger({
      previousData: null,
      newData: { conversations: [{ id: "__proto__" }] },
      collectedAt: T1,
    });
    const key = "conversations:i:__proto__";
    expect(ledger).not.toBeNull();
    expect(Object.prototype.hasOwnProperty.call(ledger!.records, key)).toBe(
      true,
    );
    expect(ledger!.records[key]).toBe(T1);
    expect(Object.getPrototypeOf(ledger!.records)).toBe(Object.prototype);
    expect((Object.prototype as Record<string, unknown>)[key]).toBeUndefined();
  });
});

describe("first-added helpers", () => {
  it("stampFirstAdded returns a new object and mutates nothing", () => {
    const data = { conversations: [] };
    const ledger: FirstAddedLedger = {
      version: 1,
      trackedSince: T1,
      records: {},
    };
    const stamped = stampFirstAdded(data, ledger);
    expect(stamped).not.toBe(data);
    expect(stamped.conversations).toBe(data.conversations);
    expect(stamped[FIRST_ADDED_KEY]).toBe(ledger);
    expect(hasReservedFirstAddedKey(data)).toBe(false);
    expect(data).toEqual({ conversations: [] });
  });

  it("hasReservedFirstAddedKey is true only for an own property", () => {
    expect(hasReservedFirstAddedKey({})).toBe(false);
    expect(hasReservedFirstAddedKey({ [FIRST_ADDED_KEY]: "x" })).toBe(true);
    const inherited = Object.create({
      [FIRST_ADDED_KEY]: { version: 1 },
    }) as Record<string, unknown>;
    expect(hasReservedFirstAddedKey(inherited)).toBe(false);
  });

  it("readFirstAddedLedger rejects missing or malformed ledgers", () => {
    expect(readFirstAddedLedger({})).toBeNull();
    expect(
      readFirstAddedLedger({
        [FIRST_ADDED_KEY]: { version: 2, trackedSince: T1, records: {} },
      }),
    ).toBeNull();
    expect(
      readFirstAddedLedger({
        [FIRST_ADDED_KEY]: { version: 1, trackedSince: 5, records: {} },
      }),
    ).toBeNull();
    expect(
      readFirstAddedLedger({
        [FIRST_ADDED_KEY]: { version: 1, trackedSince: "", records: {} },
      }),
    ).toBeNull();
    expect(
      readFirstAddedLedger({
        [FIRST_ADDED_KEY]: { version: 1, trackedSince: T1, records: 5 },
      }),
    ).toBeNull();
    expect(
      readFirstAddedLedger({
        [FIRST_ADDED_KEY]: { version: 1, trackedSince: T1, records: { a: 5 } },
      }),
    ).toBeNull();
  });

  it("readFirstAddedLedger returns a valid ledger", () => {
    const ledger = {
      version: 1,
      trackedSince: T1,
      records: { a: T1, b: null },
    };
    expect(readFirstAddedLedger({ [FIRST_ADDED_KEY]: ledger })).toEqual(ledger);
  });

  it("listFirstAddedTimestamps returns only non-null values", () => {
    expect(
      listFirstAddedTimestamps({
        version: 1,
        trackedSince: T1,
        records: { a: T1, b: null, c: T2 },
      }),
    ).toEqual([T1, T2]);
  });
});
