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
      extractRecordKeys("test.scope", {
        conversations: [{ id: "a" }, { id: "b" }],
      }),
    ).resolves.toEqual(["conversations:i:a", "conversations:i:b"]);
  });

  it("accepts a numeric id and falls back through uuid, key, uri, url in order", async () => {
    await expect(
      extractRecordKeys("test.scope", { items: [{ id: 7 }] }),
    ).resolves.toEqual(["items:i:7"]);
    await expect(
      extractRecordKeys("test.scope", {
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
      extractRecordKeys("test.scope", { items: [{ id: "", uuid: 5 }] }),
    ).resolves.toEqual(["items:i:5"]);
    await expect(
      extractRecordKeys("test.scope", { items: [{ id: Number.NaN }] }),
    ).resolves.toEqual([expect.stringMatching(/^items:h:[0-9a-f]{32}$/)]);
  });

  it("hashes objects without an id with 32 hex chars, stable across property order", async () => {
    const [first] = await extractRecordKeys("test.scope", {
      items: [{ a: 1, b: 2 }],
    });
    const [reordered] = await extractRecordKeys("test.scope", {
      items: [{ b: 2, a: 1 }],
    });
    const [different] = await extractRecordKeys("test.scope", {
      items: [{ a: 1, b: 3 }],
    });
    expect(first.slice("items:".length)).toMatch(HASH_KEY);
    expect(first).toBe(reordered);
    expect(first).not.toBe(different);
  });

  it("hashes non-object array elements", async () => {
    const keys = await extractRecordKeys("test.scope", {
      tags: ["x", 5, null, [1, 2]],
    });
    expect(keys).not.toBeNull();
    for (const key of keys ?? []) {
      expect(key.slice("tags:".length)).toMatch(HASH_KEY);
    }
  });

  it("de-duplicates keys keeping first-seen order", async () => {
    await expect(
      extractRecordKeys("test.scope", {
        conversations: [{ id: "a" }, { id: "a" }, { id: "b" }],
      }),
    ).resolves.toEqual(["conversations:i:a", "conversations:i:b"]);
  });

  it("reads the PDPP records form", async () => {
    await expect(
      extractRecordKeys("test.scope", {
        records: [{ stream: "posts", data: { id: 1 } }],
      }),
    ).resolves.toEqual(["posts:i:1"]);
  });

  it("ignores $ prefixed top-level keys", async () => {
    await expect(
      extractRecordKeys("test.scope", {
        $lineage: [{ id: "a" }],
        conversations: [{ id: "a" }],
      }),
    ).resolves.toEqual(["conversations:i:a"]);
    await expect(
      extractRecordKeys("test.scope", { $lineage: [{ id: "a" }] }),
    ).resolves.toEqual(["_"]);
  });

  it("returns null when $binary is present", async () => {
    await expect(
      extractRecordKeys("test.scope", { $binary: "AAAA" }),
    ).resolves.toBeNull();
    await expect(
      extractRecordKeys("test.scope", {
        $binary: undefined,
        conversations: [{ id: "a" }],
      }),
    ).resolves.toBeNull();
  });

  it("returns ['_'] when there are no top-level arrays and [] when all are empty", async () => {
    await expect(
      extractRecordKeys("test.scope", { name: "Bob", age: 3 }),
    ).resolves.toEqual(["_"]);
    await expect(
      extractRecordKeys("test.scope", { conversations: [], messages: [] }),
    ).resolves.toEqual([]);
  });
});

describe("buildFirstAddedLedger", () => {
  it("Case C marks every first-snapshot record with collectedAt", async () => {
    const ledger = await buildFirstAddedLedger({
      scope: "test.scope",
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
      scope: "test.scope",
      previousData: null,
      newData: data,
      collectedAt: T1,
    });
    const ledger = await buildFirstAddedLedger({
      scope: "test.scope",
      previousData: stampFirstAdded(data, previous!),
      newData: { conversations: [{ id: "a" }] },
      collectedAt: T2,
    });
    expect(ledger?.records).toEqual(previous?.records);
    expect(ledger?.trackedSince).toBe(T1);
  });

  it("Case A dates a new record now while old records keep theirs", async () => {
    const previous = await buildFirstAddedLedger({
      scope: "test.scope",
      previousData: null,
      newData: { conversations: [{ id: "a" }] },
      collectedAt: T1,
    });
    const ledger = await buildFirstAddedLedger({
      scope: "test.scope",
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
      scope: "test.scope",
      previousData: null,
      newData: snap1,
      collectedAt: T1,
    });
    const snap2 = { conversations: [{ id: "a" }] };
    const ledger2 = await buildFirstAddedLedger({
      scope: "test.scope",
      previousData: stampFirstAdded(snap1, ledger1!),
      newData: snap2,
      collectedAt: T2,
    });
    expect(ledger2?.records["conversations:i:b"]).toBe(T1);
    const ledger3 = await buildFirstAddedLedger({
      scope: "test.scope",
      previousData: stampFirstAdded(snap2, ledger2!),
      newData: { conversations: [{ id: "a" }, { id: "b" }] },
      collectedAt: T3,
    });
    expect(ledger3?.records["conversations:i:b"]).toBe(T1);
    expect(ledger3?.trackedSince).toBe(T1);
  });

  it("Case B nulls pre-tracking records and dates genuinely new ones", async () => {
    const ledger = await buildFirstAddedLedger({
      scope: "test.scope",
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
      scope: "test.scope",
      previousData: preTracking,
      newData: { conversations: [{ id: "a" }, { id: "b" }] },
      collectedAt: T2,
    });
    const caseA = await buildFirstAddedLedger({
      scope: "test.scope",
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
        scope: "test.scope",
        previousData: null,
        newData: { $binary: "AAAA" },
        collectedAt: T1,
      }),
    ).resolves.toBeNull();
  });

  it("treats a malformed previous ledger as Case B", async () => {
    const ledger = await buildFirstAddedLedger({
      scope: "test.scope",
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
    await buildFirstAddedLedger({
      scope: "test.scope",
      previousData,
      newData,
      collectedAt: T2,
    });
    expect(previousData).toEqual(previousClone);
    expect(newData).toEqual(newClone);
  });

  it("stores a __proto__ id as an own property without polluting prototypes", async () => {
    const ledger = await buildFirstAddedLedger({
      scope: "test.scope",
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

describe("ruled scopes", () => {
  it("returns [] for a scope with an empty rule list", async () => {
    await expect(
      extractRecordKeys("github.profile", {
        organizations: [{ id: "org-1" }],
        pinnedRepositories: [{ id: "repo-1" }],
      }),
    ).resolves.toEqual([]);
    // Not the generic single-record ["_"] default.
    await expect(extractRecordKeys("github.profile", {})).resolves.toEqual([]);
  });

  it("keys icloud_notes.notes by recordName, ignoring mutable fields", async () => {
    const before = await extractRecordKeys("icloud_notes.notes", {
      notes: [
        { recordName: "n1", title: "First", textContent: "a" },
        { recordName: "n2", title: "Second", textContent: "b" },
      ],
    });
    const after = await extractRecordKeys("icloud_notes.notes", {
      notes: [
        { recordName: "n1", title: "Edited", textContent: "changed" },
        { recordName: "n2", title: "Second", textContent: "b" },
      ],
    });
    expect(before).toEqual(["notes:i:n1", "notes:i:n2"]);
    expect(after).toEqual(before);
  });

  it("keys instagram.posts by taken_at when id and shortcode are absent", async () => {
    const before = await extractRecordKeys("instagram.posts", {
      posts: [{ taken_at: "2024-01-01T00:00:00.000Z", num_of_likes: 1 }],
    });
    const after = await extractRecordKeys("instagram.posts", {
      posts: [{ taken_at: "2024-01-01T00:00:00.000Z", num_of_likes: 99 }],
    });
    expect(before).toEqual(["posts:i:2024-01-01T00:00:00.000Z"]);
    expect(after).toEqual(before);
  });

  it("keys github.repositories by url, then fullName, then name", async () => {
    await expect(
      extractRecordKeys("github.repositories", {
        repositories: [
          { url: "u1", fullName: "f1", name: "n1" },
          { fullName: "f2", name: "n2" },
          { name: "n3" },
        ],
      }),
    ).resolves.toEqual([
      "repositories:i:u1",
      "repositories:i:f2",
      "repositories:i:n3",
    ]);
  });

  it("keys github.history issues and pullRequests, ignoring unrelated arrays", async () => {
    await expect(
      extractRecordKeys("github.history", {
        issues: [{ id: "i1" }],
        pullRequests: [{ id: "pr1" }],
        labels: [{ id: "l1" }],
      }),
    ).resolves.toEqual(["issues:i:i1", "pullRequests:i:pr1"]);
  });

  it("keys github.contributions days only", async () => {
    await expect(
      extractRecordKeys("github.contributions", {
        days: [{ date: "2024-01-01" }],
        monthlyTotals: [{ date: "2024-01" }],
        yearTotals: [{ date: "2024" }],
      }),
    ).resolves.toEqual(["days:i:2024-01-01"]);
  });

  it("keeps instagram.ads ad_topics and advertisers keys distinct", async () => {
    await expect(
      extractRecordKeys("instagram.ads", {
        ad_topics: [{ name: "shoes" }],
        advertisers: [{ name: "shoes" }],
      }),
    ).resolves.toEqual(["ad_topics:i:shoes", "advertisers:i:shoes"]);
  });

  it("splits PDPP ads by kind into ad_topics and advertisers", async () => {
    const keys = await extractRecordKeys("instagram.ads", {
      records: [
        { stream: "ads", data: { name: "acme", kind: "advertiser" } },
        { stream: "ads", data: { name: "shoes", kind: "ad_topic" } },
        { stream: "ads", data: { name: "toys", kind: "ad_category" } },
      ],
    });
    expect(keys).toEqual(["ad_topics:i:shoes", "advertisers:i:acme"]);
  });

  it("gives PDPP and legacy instagram.ads the same keys", async () => {
    const pdpp = await extractRecordKeys("instagram.ads", {
      records: [
        { stream: "ads", data: { name: "acme", kind: "advertiser" } },
        { stream: "ads", data: { name: "shoes", kind: "ad_topic" } },
      ],
    });
    const legacy = await extractRecordKeys("instagram.ads", {
      advertisers: [{ name: "acme" }],
      ad_topics: [{ name: "shoes" }],
    });
    expect([...pdpp!].sort()).toEqual([...legacy!].sort());
    expect(legacy).toEqual(["ad_topics:i:shoes", "advertisers:i:acme"]);
  });

  it("gives PDPP pull_requests the same canonical keys as the legacy form", async () => {
    const pdpp = await extractRecordKeys("github.history", {
      records: [
        { stream: "issues", data: { id: "i1" } },
        { stream: "pull_requests", data: { id: "pr1" } },
      ],
    });
    const legacy = await extractRecordKeys("github.history", {
      issues: [{ id: "i1" }],
      pull_requests: [{ id: "pr1" }],
    });
    expect(pdpp).toEqual(["issues:i:i1", "pullRequests:i:pr1"]);
    expect(legacy).toEqual(pdpp);
  });

  it("resolves spotify.savedTracks track.id then falls back to id", async () => {
    await expect(
      extractRecordKeys("spotify.savedTracks", {
        savedTracks: [{ track: { id: "t1" }, id: "outer1" }, { id: "outer2" }],
      }),
    ).resolves.toEqual(["savedTracks:i:t1", "savedTracks:i:outer2"]);
  });

  it("falls back to a content hash when no id field qualifies", async () => {
    const keys = await extractRecordKeys("github.repositories", {
      repositories: [{ description: "no id" }],
    });
    expect(keys).toEqual([
      expect.stringMatching(/^repositories:h:[0-9a-f]{32}$/),
    ]);
  });

  it("ignores non-object elements in a ruled collection", async () => {
    await expect(
      extractRecordKeys("github.events", {
        events: [{ id: "e1" }, "not-an-object", 5, null],
      }),
    ).resolves.toEqual(["events:i:e1"]);
  });

  it("dates only a genuinely new note and not an edited one", async () => {
    const first = await buildFirstAddedLedger({
      scope: "icloud_notes.notes",
      previousData: null,
      newData: {
        notes: [{ recordName: "n1", title: "A", textContent: "one" }],
      },
      collectedAt: T1,
    });
    const edited = await buildFirstAddedLedger({
      scope: "icloud_notes.notes",
      previousData: stampFirstAdded(
        { notes: [{ recordName: "n1", title: "A", textContent: "one" }] },
        first!,
      ),
      newData: {
        notes: [{ recordName: "n1", title: "B", textContent: "two" }],
      },
      collectedAt: T2,
    });
    expect(edited?.records).toEqual({ "notes:i:n1": T1 });

    const added = await buildFirstAddedLedger({
      scope: "icloud_notes.notes",
      previousData: stampFirstAdded(
        { notes: [{ recordName: "n1", title: "B", textContent: "two" }] },
        edited!,
      ),
      newData: {
        notes: [
          { recordName: "n1", title: "B", textContent: "two" },
          { recordName: "n2", title: "New", textContent: "three" },
        ],
      },
      collectedAt: T3,
    });
    expect(added?.records).toEqual({ "notes:i:n1": T1, "notes:i:n2": T3 });
  });
});
