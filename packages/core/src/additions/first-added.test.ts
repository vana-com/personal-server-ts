import { describe, expect, it, vi } from "vitest";

import {
  LedgerFold,
  MAX_COLLECTION_LENGTH,
  MAX_ID_LENGTH,
  MAX_TRACKED_KEYS,
  extractRecordKeys,
  foldVersion,
  foldVersions,
  isPreTracking,
  isPresent,
  listAddedTimestamps,
  readScopeFirstSeenLedger,
  type ScopeFirstSeenLedger,
  type VersionToFold,
} from "./first-added.js";

const T1 = "2026-01-01T00:00:00.000Z";
const T2 = "2026-01-02T00:00:00.000Z";
const T3 = "2026-01-03T00:00:00.000Z";

async function keysOf(scope: string, data: Record<string, unknown>) {
  const result = await extractRecordKeys(scope, data);
  if (result === null) throw new Error("expected trackable data");
  return result;
}

const rows = (...ids: string[]) => ids.map((id) => ({ id }));

describe("extractRecordKeys", () => {
  it("keys a generic legacy collection by its name and the record id", async () => {
    expect(
      await keysOf("test.scope", { conversations: rows("a", "b"), total: 2 }),
    ).toEqual({
      keys: ["conversations:i:a", "conversations:i:b"],
      total: 2,
    });
  });

  it("accepts a numeric id and tries id, uuid, key, uri, url in order", async () => {
    expect((await keysOf("test.scope", { items: [{ id: 7 }] })).keys).toEqual([
      "items:n:7",
    ]);
    expect(
      (
        await keysOf("test.scope", {
          items: [
            { id: "id", uuid: "uuid", key: "key", uri: "uri", url: "url" },
            { uuid: "uuid", key: "key", uri: "uri", url: "url" },
            { key: "key", uri: "uri", url: "url" },
            { uri: "uri", url: "url" },
            { url: "url" },
          ],
        })
      ).keys,
    ).toEqual([
      "items:i:id",
      "items:i:uuid",
      "items:i:key",
      "items:i:uri",
      "items:i:url",
    ]);
  });

  it("counts records with no usable id toward the total but never tracks them", async () => {
    const result = await keysOf("test.scope", {
      items: [
        { id: "" },
        { id: Number.NaN },
        { id: { nested: true } },
        { name: "no id" },
        { id: "keep" },
      ],
    });
    expect(result.total).toBe(5);
    expect(result.keys).toEqual(["items:i:keep"]);
  });

  it("de-duplicates keys but counts every record", async () => {
    const result = await keysOf("test.scope", { items: rows("a", "a", "b") });
    expect(result).toEqual({ keys: ["items:i:a", "items:i:b"], total: 3 });
  });

  it("replaces an id longer than 64 characters by a bounded hash", async () => {
    expect(MAX_ID_LENGTH).toBe(64);
    const long = "x".repeat(100);
    const { keys } = await keysOf("test.scope", { items: [{ id: long }] });
    expect(keys).toHaveLength(1);
    expect(keys[0]).toMatch(/^items:h:[0-9a-f]{32}$/);
    // An id of exactly 64 characters is kept verbatim.
    const edge = "y".repeat(64);
    expect(
      (await keysOf("test.scope", { items: [{ id: edge }] })).keys,
    ).toEqual([`items:i:${edge}`]);
    expect(
      (await keysOf("test.scope", { items: [{ id: `${edge}!` }] })).keys[0],
    ).toMatch(/^items:h:/);
    // Different long ids hash differently, the same id hashes the same.
    const other = await keysOf("test.scope", { items: [{ id: `${long}!` }] });
    expect(other.keys).not.toEqual(keys);
    expect(
      (await keysOf("test.scope", { items: [{ id: long }] })).keys,
    ).toEqual(keys);
  });

  it("bounds a caller-controlled collection name (security F1)", async () => {
    expect(MAX_COLLECTION_LENGTH).toBe(64);
    const name = "k".repeat(20_000);
    const { keys, total } = await keysOf("myapp.notes", {
      [name]: Array.from({ length: 3000 }, (_, i) => ({ id: 1_000_000 + i })),
    });
    expect(total).toBe(3000);
    expect(keys).toHaveLength(3000);
    // Every key is short, so the Set never hashes 20 KB strings.
    expect(Math.max(...keys.map((key) => key.length))).toBeLessThanOrEqual(200);
    expect(keys[0]).toMatch(/^#[0-9a-f]{32}:n:1000000$/);
    // A name of exactly 64 characters stays readable.
    const edge = "c".repeat(64);
    expect(
      (await keysOf("myapp.notes", { [edge]: [{ id: "a" }] })).keys,
    ).toEqual([`${edge}:i:a`]);
  });

  it("bounds the key of a 65 KB hostile body", async () => {
    const body = {
      ["k".repeat(65_000)]: [{ id: "a" }],
      items: [{ id: "z".repeat(65_000) }],
    };
    const { keys } = await keysOf("myapp.notes", body);
    expect(keys).toHaveLength(2);
    for (const key of keys) expect(key.length).toBeLessThanOrEqual(200);
  });

  describe("keys are unambiguous within a scope (aliasing)", () => {
    const distinct = async (data: Record<string, unknown>) => {
      const { keys } = await keysOf("myapp.notes", data);
      return new Set(keys).size === keys.length ? keys : null;
    };

    it("a collection literally named like a hash differs from the long name it hashes to", async () => {
      const long = "k".repeat(70);
      const hashed = (await keysOf("myapp.notes", { [long]: [{ id: "a" }] }))
        .keys[0]!;
      const literal = hashed.slice(0, hashed.indexOf(":n:") + 0).split(":")[0]!;
      const keys = await distinct({
        [long]: [{ id: "a" }],
        [literal]: [{ id: "a" }],
        [`h:${literal.slice(1)}`]: [{ id: "a" }],
      });
      expect(keys).toHaveLength(3);
    });

    it("collection a with id b:i:c differs from collection a:i:b with id c", async () => {
      const keys = await distinct({
        a: [{ id: "b:i:c" }],
        "a:i:b": [{ id: "c" }],
        "a:i": [{ id: "b:c" }],
      });
      expect(keys).toHaveLength(3);
    });

    it("a number and its string differ", async () => {
      const keys = await distinct({ items: [{ id: 1 }, { id: "1" }] });
      expect(keys).toEqual(["items:n:1", "items:i:1"]);
    });

    it("a hashed id differs from a string that looks like one", async () => {
      const long = "x".repeat(100);
      const hashed = (await keysOf("myapp.notes", { items: [{ id: long }] }))
        .keys[0]!;
      const lookalike = hashed.replace("items:h:", "");
      const keys = await distinct({
        items: [{ id: long }, { id: `h:${lookalike}` }, { id: lookalike }],
      });
      expect(keys).toHaveLength(3);
    });

    it("escapes the separator, backslash and hash in a collection name", async () => {
      const { keys } = await keysOf("myapp.notes", {
        "a:b": [{ id: "x" }],
        "a\\b": [{ id: "x" }],
        "#c": [{ id: "x" }],
      });
      expect(keys).toEqual(["a\\:b:i:x", "a\\\\b:i:x", "\\#c:i:x"]);
    });
  });

  it("stops collecting once the tracked keys pass the cap, but still counts", async () => {
    const count = MAX_TRACKED_KEYS + 5_000;
    const result = await extractRecordKeys("myapp.notes", {
      items: Array.from({ length: count }, (_, i) => ({ id: i })),
    });
    expect(result).toEqual({ keys: [], total: count, tooMany: true });
  }, 30_000);

  it("yields to the event loop while extracting a large body", async () => {
    let ticks = 0;
    const timer = setInterval(() => {
      ticks += 1;
    }, 0);
    try {
      await extractRecordKeys("myapp.notes", {
        items: Array.from({ length: 30_000 }, (_, i) => ({ id: i })),
      });
    } finally {
      clearInterval(timer);
    }
    expect(ticks).toBeGreaterThan(0);
  });

  it("counts a scope with no arrays as one untracked record", async () => {
    expect(await keysOf("test.profile", { name: "Ada", age: 3 })).toEqual({
      keys: [],
      total: 1,
    });
  });

  it("returns null for a binary payload", async () => {
    expect(await extractRecordKeys("test.scope", { $binary: {} })).toBeNull();
  });

  it("ignores server-stamped $ keys", async () => {
    const result = await keysOf("test.scope", {
      items: rows("a"),
      $writtenBy: { builder: "0x1" },
      $lineage: { sources: [] },
    });
    expect(result.keys).toEqual(["items:i:a"]);
  });

  describe("stored PDPP rows form", () => {
    it("keys chatgpt.conversations rows like its legacy form", async () => {
      const legacy = await keysOf("chatgpt.conversations", {
        conversations: rows("c1", "c2"),
        total: 2,
      });
      const pdpp = await keysOf("chatgpt.conversations", {
        records: rows("c1", "c2"),
      });
      expect(pdpp.keys.length).toBe(2);
      expect(pdpp).toEqual({ keys: legacy.keys, total: 2 });
    });

    it("tolerates the server stamps beside records", async () => {
      const pdpp = await keysOf("chatgpt.conversations", {
        records: rows("c1"),
        $writtenBy: { builder: "0x1" },
        $lineage: { sources: [] },
      });
      expect(pdpp.keys).toEqual(["conversations:i:c1"]);
    });

    it("keys a generic scope identically in both forms", async () => {
      const legacy = await keysOf("test.posts", { posts: rows("a", "b") });
      const pdpp = await keysOf("test.posts", { records: rows("a", "b") });
      expect(pdpp).toEqual(legacy);
      expect(pdpp.keys).toEqual(["posts:i:a", "posts:i:b"]);
    });

    it("uses the dataset name, not the literal records, for a generic scope", async () => {
      const { keys } = await keysOf("acme.widgets", { records: rows("w") });
      expect(keys).toEqual(["widgets:i:w"]);
    });

    it("treats a records key beside other keys as a legacy collection", async () => {
      const { keys } = await keysOf("test.scope", {
        records: rows("a"),
        total: 1,
        extra: "yes",
      });
      expect(keys).toEqual(["records:i:a"]);
    });

    it("keeps x.posts keys stable across both forms", async () => {
      const pdpp = await keysOf("x.posts", { records: rows("1", "2") });
      const legacy = await keysOf("x.posts", { posts: rows("1", "2") });
      expect(pdpp.keys).toEqual(["records:i:1", "records:i:2"]);
      expect(legacy).toEqual(pdpp);
      const likes = await keysOf("x.likes", { records: rows("9") });
      expect(likes.keys).toEqual(["records:i:9"]);
    });

    it("uses the rule whose alias is the dataset name", async () => {
      // The PDPP stream is `saved_tracks`; its keys equal the legacy ones.
      const rows = await keysOf("spotify.saved_tracks", {
        records: [{ uri: "spotify:track:1" }, { uri: "spotify:track:2" }],
      });
      const legacy = await keysOf("spotify.savedTracks", {
        savedTracks: [{ uri: "spotify:track:1" }, { uri: "spotify:track:2" }],
      });
      expect(rows).toEqual(legacy);
      expect(rows.keys).toEqual([
        "savedTracks:i:spotify:track:1",
        "savedTracks:i:spotify:track:2",
      ]);
    });

    it("counts but never tracks a collection no field identifies in both forms", async () => {
      expect(
        await keysOf("linkedin.experience", { records: rows("e1", "e2") }),
      ).toEqual({ keys: [], total: 2 });
      expect(
        await keysOf("linkedin.experience", {
          experiences: [{ jobTitle: "a" }, { jobTitle: "b" }],
        }),
      ).toEqual({ keys: [], total: 2 });
    });

    it("counts join-only streams like the owner app, but never tracks them", async () => {
      for (const scope of ["claude.messages", "instagram.post_likes"]) {
        expect(await keysOf(scope, { records: rows("a") })).toEqual({
          keys: [],
          total: 1,
        });
      }
    });

    it("counts a profile as one record in either form, whatever arrays it carries", async () => {
      expect(
        await keysOf("spotify.profile", {
          id: "u",
          images: [{ url: "a" }, { url: "b" }],
        }),
      ).toEqual({ keys: [], total: 1 });
      expect(await keysOf("spotify.profile", { records: rows("u") })).toEqual({
        keys: [],
        total: 1,
      });
      expect(await keysOf("youtube.profile", {})).toEqual({
        keys: [],
        total: 0,
      });
    });

    it("counts a binary file as 0 in a scope whose rules hold nothing, like a rebuild", async () => {
      expect(
        await extractRecordKeys("chatgpt.messages", { $binary: {} }),
      ).toEqual({
        keys: [],
        total: 0,
      });
    });

    it("applies the stream filter to rows", async () => {
      const { keys, total } = await keysOf("instagram.ads", {
        records: [
          { kind: "ad_topic", name: "Cars" },
          { kind: "advertiser", name: "Acme" },
          { kind: "other", name: "Skip" },
        ],
      });
      expect(keys).toEqual(["ad_topics:i:Cars", "advertisers:i:Acme"]);
      expect(total).toBe(2);
    });

    it("tracks nothing for a ruled scope that holds no memory records", async () => {
      expect(
        await keysOf("chatgpt.messages", { records: rows("m1", "m2") }),
      ).toEqual({ keys: [], total: 0 });
    });

    it("counts rows of an ambiguous multi-rule scope without tracking them", async () => {
      const result = await keysOf("github.history", {
        records: rows("1", "2"),
      });
      expect(result).toEqual({ keys: [], total: 2 });
    });
  });

  describe("ruled legacy form", () => {
    it("reads the rule's collection, then its aliases", async () => {
      expect(
        (
          await keysOf("github.history", {
            issues: rows("i1"),
            pull_requests: rows("p1"),
          })
        ).keys,
      ).toEqual(["issues:i:i1", "pullRequests:i:p1"]);
    });

    it("ignores arrays no rule names", async () => {
      expect(
        await keysOf("github.repositories", {
          repositories: [{ url: "u1" }],
          other: rows("z"),
        }),
      ).toEqual({ keys: ["repositories:i:u1"], total: 1 });
    });
  });
});

function version(
  collectedAt: string,
  items: string[],
  scope = "notes.entries",
): VersionToFold {
  return { scope, collectedAt, data: { items: rows(...items) } };
}

const binary = (collectedAt: string): VersionToFold => ({
  scope: "notes.entries",
  collectedAt,
  data: { $binary: { mimeType: "application/pdf" } },
});

async function fold(
  versions: VersionToFold[],
  start: ScopeFirstSeenLedger | null = null,
) {
  let ledger = start;
  for (const v of versions) ledger = await foldVersion(ledger, v);
  if (!ledger) throw new Error("expected a ledger");
  return ledger;
}

const DAY = 24 * 60 * 60 * 1000;
const iso = (days: number) =>
  new Date(Date.parse(T1) + days * DAY).toISOString();

describe("foldVersion", () => {
  it("starts a ledger at the first version, dating nothing as new", async () => {
    const ledger = await fold([version(T1, ["a", "b"])]);
    expect(ledger).toEqual({
      version: 3,
      scope: "notes.entries",
      baseline: T1,
      current: T1,
      latest: { collectedAt: T1, total: 2 },
      through: T1,
      records: { "items:i:a": [T1, T1], "items:i:b": [T1, T1] },
    });
    expect(isPreTracking(ledger, "items:i:a")).toBe(true);
    expect(isPresent(ledger, "items:i:a")).toBe(true);
    expect(listAddedTimestamps(ledger)).toEqual([]);
  });

  it("dates only the record a later version adds", async () => {
    const ledger = await fold([
      version(T1, ["a", "b"]),
      version(T2, ["a", "b", "c"]),
    ]);
    expect(ledger.records["items:i:c"]).toEqual([T2, T2]);
    expect(ledger.records["items:i:a"]).toEqual([T1, T2]);
    expect(isPreTracking(ledger, "items:i:c")).toBe(false);
    expect(ledger.latest).toEqual({ collectedAt: T2, total: 3 });
    expect(listAddedTimestamps(ledger)).toEqual([T2]);
  });

  it("keeps a record's first date when it is absent for a version and returns", async () => {
    const ledger = await fold([
      version(T1, ["a", "b"]),
      version(T2, ["a"]),
      version(T3, ["a", "b"]),
    ]);
    expect(ledger.records["items:i:b"]).toEqual([T1, T3]);
    expect(isPresent(ledger, "items:i:b")).toBe(true);
  });

  it("marks a record absent from the newest version as not present", async () => {
    const ledger = await fold([version(T1, ["a", "b"]), version(T2, ["a"])]);
    expect(isPresent(ledger, "items:i:a")).toBe(true);
    expect(isPresent(ledger, "items:i:b")).toBe(false);
  });

  it("is idempotent: folding the same version twice changes nothing", async () => {
    const once = await fold([version(T1, ["a"]), version(T2, ["a", "b"])]);
    const twice = await fold([version(T2, ["a", "b"])], once);
    expect(twice).toEqual(once);
  });

  it("is order independent over every permutation of three versions", async () => {
    const versions = [
      version(T1, ["a", "b"]),
      version(T2, ["b", "c"]),
      version(T3, ["c", "d"]),
    ];
    const permutations = [
      [0, 1, 2],
      [0, 2, 1],
      [1, 0, 2],
      [1, 2, 0],
      [2, 0, 1],
      [2, 1, 0],
    ];
    const expected = await fold(versions);
    for (const order of permutations) {
      expect(await fold(order.map((i) => versions[i]!))).toEqual(expected);
    }
    expect(expected.baseline).toBe(T1);
    expect(expected.latest.collectedAt).toBe(T3);
    expect(expected.records["items:i:c"]).toEqual([T2, T3]);
  });

  it("is order independent only within the 90-day pruning window", async () => {
    // Four versions spanning 210 days (the reviewer's case). Pruning is
    // relative to the newest version folded so far, so a record already
    // pruned can return with a later first date in another fold order. The
    // documented guarantee stops at the window: chronological order is the
    // reference, and it is deterministic.
    const spread = [
      version(iso(0), ["a", "b"]),
      version(iso(150), ["a"]),
      version(iso(200), ["b"]),
      version(iso(210), ["a", "b"]),
    ];
    const chronological = await fold(spread);
    expect(await fold(spread)).toEqual(chronological);
    // One pass prunes once at the end, so it keeps b's original date: the
    // pruning point, not the fold order alone, decides these edge cases.
    expect((await foldVersions(null, spread))!.records["items:i:b"]).toEqual([
      iso(0),
      iso(210),
    ]);
    // b was pruned between day 0 and 200, so it re-dates from day 200.
    expect(chronological.records["items:i:b"]).toEqual([iso(200), iso(210)]);

    // Within the window every permutation agrees.
    const close = [
      version(iso(0), ["a", "b"]),
      version(iso(30), ["a"]),
      version(iso(60), ["b"]),
      version(iso(85), ["a", "b"]),
    ];
    const reference = await fold(close);
    for (const rotation of [1, 2, 3]) {
      const rotated = [...close.slice(rotation), ...close.slice(0, rotation)];
      expect(await fold(rotated)).toEqual(reference);
    }
  });

  it("compares instants, not strings, for mixed fractional seconds", async () => {
    const whole = "2026-01-01T00:00:00Z";
    const half = "2026-01-01T00:00:00.500Z";
    // As strings "…00.500Z" < "…00Z", but the instant 00.500 is later.
    const ledger = await fold([
      version(half, ["a"]),
      version(whole, ["a", "b"]),
    ]);
    expect(ledger.baseline).toBe(whole);
    expect(ledger.latest.collectedAt).toBe(half);
    expect(ledger.records["items:i:b"]).toEqual([whole, whole]);
    expect(ledger.records["items:i:a"]).toEqual([whole, half]);
    const reversed = await fold([
      version(whole, ["a", "b"]),
      version(half, ["a"]),
    ]);
    expect(reversed).toEqual(ledger);
  });

  it("treats strings of one instant as one version, folded the same in either order (F6)", async () => {
    const plain = "2026-01-05T12:00:00Z";
    const millis = "2026-01-05T12:00:00.000Z";
    const first = version(plain, ["a", "b", "c"]);
    const second = version(millis, ["a"]);
    const base = version(T1, ["a"]);
    const one = await fold([base, first, second]);
    const two = await fold([base, second, first]);
    expect(one).toEqual(two);
    // The greater string names the newest version; additions fit its total.
    expect(one.latest.collectedAt).toBe(plain);
    expect(listAddedTimestamps(one).length).toBeLessThanOrEqual(
      one.latest.total,
    );
  });

  it("ignores a version whose collectedAt does not parse", async () => {
    const base = await fold([version(T1, ["a"])]);
    expect(await foldVersion(base, version("not a date", ["z"]))).toEqual(base);
    expect(await foldVersion(null, version("not a date", ["z"]))).toBeNull();
  });

  it("counts a binary file as one record without hiding the scope's history", async () => {
    const base = await fold([version(T1, ["a"]), version(T2, ["a", "b"])]);
    const afterBinary = (await foldVersion(base, binary(T3)))!;
    expect(afterBinary.latest).toEqual({ collectedAt: T3, total: 1 });
    // History and the presence of the last JSON snapshot are untouched.
    expect(afterBinary.baseline).toBe(T1);
    expect(afterBinary.current).toBe(T2);
    expect(afterBinary.records).toEqual(base.records);
    // While the newest version is the binary file the scope reports its
    // total and no additions, so `added` can never exceed `total`.
    expect(listAddedTimestamps(afterBinary)).toEqual([]);

    const t4 = "2026-01-04T00:00:00.000Z";
    const after = (await foldVersion(
      afterBinary,
      version(t4, ["a", "b", "c"]),
    ))!;
    expect(after.records["items:i:b"]).toEqual([T2, t4]);
    expect(after.records["items:i:c"]).toEqual([t4, t4]);
    expect(isPreTracking(after, "items:i:b")).toBe(false);
  });

  it("dates nothing after a binary-first scope until a trackable version exists", async () => {
    const first = await fold([binary(T1)]);
    expect(first.baseline).toBeNull();
    expect(first.current).toBeNull();
    expect(first.latest).toEqual({ collectedAt: T1, total: 1 });
    expect(listAddedTimestamps(first)).toEqual([]);

    const json = await fold([version(T2, ["a", "b", "c"])], first);
    // The first trackable version is the baseline: nothing is "added".
    expect(json.baseline).toBe(T2);
    expect(listAddedTimestamps(json)).toEqual([]);
    const more = await fold([version(T3, ["a", "b", "c", "d"])], json);
    expect(listAddedTimestamps(more)).toEqual([T3]);
  });

  it("does not baseline a snapshot whose records have no usable id", async () => {
    const idless: VersionToFold = {
      scope: "notes.entries",
      collectedAt: T1,
      data: { items: [{ name: "x" }, { name: "y" }] },
    };
    const first = await fold([idless]);
    expect(first.baseline).toBeNull();
    expect(first.latest.total).toBe(2);
    const next = await fold([version(T2, ["a", "b"])], first);
    expect(next.baseline).toBe(T2);
    expect(listAddedTimestamps(next)).toEqual([]);
  });

  it("baselines an empty snapshot, so later records are real additions", async () => {
    const empty = await fold([version(T1, [])]);
    expect(empty.baseline).toBe(T1);
    const next = await fold([version(T2, ["a"])], empty);
    expect(listAddedTimestamps(next)).toEqual([T2]);
  });

  it("does not mutate its inputs", async () => {
    const base = await fold([version(T1, ["a"])]);
    const snapshot = structuredClone(base);
    await foldVersion(base, version(T2, ["a", "b"]));
    expect(base).toEqual(snapshot);
  });

  it("prunes records absent for more than 90 days and keeps others", async () => {
    const ledger = await fold([
      version(iso(0), ["old", "kept", "back"]),
      version(iso(60), ["kept", "back"]),
      version(iso(100), ["kept"]),
    ]);
    // `old` was last seen 100 days before the newest version: pruned.
    expect(ledger.records["items:i:old"]).toBeUndefined();
    // `back` was last seen 40 days before: kept, though absent.
    expect(ledger.records["items:i:back"]).toEqual([iso(0), iso(60)]);
    expect(isPresent(ledger, "items:i:back")).toBe(false);
    // A record that returns after being kept keeps its original date.
    const returned = await foldVersion(ledger, version(iso(110), ["back"]));
    expect(returned!.records["items:i:back"]).toEqual([iso(0), iso(110)]);
  });

  it("treats a snapshot over the cap as untrackable for that version only", async () => {
    const many = Array.from({ length: MAX_TRACKED_KEYS + 1 }, (_, i) => ({
      id: `k${i}`,
    }));
    const base = await fold([version(T1, ["a"])]);
    const capped = (await foldVersion(base, {
      scope: "notes.entries",
      collectedAt: T2,
      data: { items: many },
    }))!;
    // Its total is kept, but it adds no keys and is not the newest tracked one.
    expect(capped.skipped).toBeUndefined();
    expect(capped.records).toEqual(base.records);
    expect(capped.latest).toEqual({
      collectedAt: T2,
      total: MAX_TRACKED_KEYS + 1,
    });
    expect(capped.current).toBe(T1);
    expect(listAddedTimestamps(capped)).toEqual([]);
    expect(readScopeFirstSeenLedger(capped)).toEqual(capped);

    // Normal imports then resume tracking and date genuinely new records.
    const next = (await foldVersion(capped, version(T3, ["a", "b"])))!;
    expect(next.latest).toEqual({ collectedAt: T3, total: 2 });
    expect(next.records["items:i:b"]).toEqual([T3, T3]);
    expect(listAddedTimestamps(next)).toEqual([T3]);
  }, 30_000);

  it("never baselines an over-cap first snapshot", async () => {
    const many = Array.from({ length: MAX_TRACKED_KEYS + 1 }, (_, i) => ({
      id: `k${i}`,
    }));
    const capped = (await foldVersion(null, {
      scope: "notes.entries",
      collectedAt: T1,
      data: { items: many },
    }))!;
    expect(capped.baseline).toBeNull();
    const next = (await foldVersion(capped, version(T2, ["a", "b"])))!;
    expect(next.baseline).toBe(T2);
    expect(listAddedTimestamps(next)).toEqual([]);
  }, 30_000);

  describe("at the key cap", () => {
    const ids = (prefix: string, count: number, from = 0) =>
      Array.from({ length: count }, (_, i) => ({ id: `${prefix}${from + i}` }));
    const at = (n: number) =>
      `2026-01-${String(n).padStart(2, "0")}T00:00:00.000Z`;
    const v = (n: number, items: { id: string }[]): VersionToFold => ({
      scope: "notes.entries",
      collectedAt: at(n),
      data: { items },
    });
    const KEEP = 150_000;

    it("does not re-date records present in the version being folded, whatever their order (F1)", async () => {
      // v1 is an empty baseline, so A (first seen at v2) is not pre-tracking.
      const base = await fold([v(1, []), v(2, ids("A", KEEP))]);
      const news = ids("N", 100_000);
      const olds = ids("A", 100_000);
      const newFirst = (await foldVersion(base, v(3, [...news, ...olds])))!;
      const oldFirst = (await foldVersion(base, v(3, [...olds, ...news])))!;

      // 50,000 absent A records make room; the 100,000 present ones keep v2.
      expect(newFirst).toEqual(oldFirst);
      const keys = Object.keys(newFirst.records);
      expect(keys.length).toBe(200_000);
      const redated = Object.entries(newFirst.records).filter(
        ([key, pair]) => key.startsWith("items:i:A") && pair[0] !== at(2),
      );
      expect(redated).toHaveLength(0);
      const added = listAddedTimestamps(newFirst);
      expect(added.filter((when) => when === at(3))).toHaveLength(100_000);
      expect(added.filter((when) => when === at(2))).toHaveLength(100_000);
    }, 120_000);

    it("folding an older version into a full ledger evicts and sorts at most once (F2)", async () => {
      const full = (await fold([v(5, ids("K", 200_000))]))!;
      expect(Object.keys(full.records)).toHaveLength(200_000);
      const sort = vi.spyOn(Array.prototype, "sort");
      let ticks = 0;
      const timer = setInterval(() => {
        ticks += 1;
      }, 0);
      let older: ScopeFirstSeenLedger | null;
      let sorts = 0;
      try {
        older = await foldVersion(full, v(3, ids("unknown", 4_000)));
        sorts = sort.mock.calls.length;
      } finally {
        clearInterval(timer);
        sort.mockRestore();
      }
      // One sort for the new ids and at most one for the eviction candidates.
      expect(sorts).toBeGreaterThan(0);
      expect(sorts).toBeLessThanOrEqual(3);
      expect(ticks).toBeGreaterThan(0);
      // Nothing was evictable (every record is in the newest version), so the
      // unknown ids are left out rather than evicting each other.
      expect(Object.keys(older!.records)).toHaveLength(200_000);
      expect(
        Object.keys(older!.records).some((key) => key.includes("unknown")),
      ).toBe(false);
    }, 120_000);

    it("gives the same ledger whatever the order of the ids in a version", async () => {
      const base = await fold([v(1, []), v(2, ids("A", KEEP))]);
      const items = [...ids("N", 90_000), ...ids("A", 60_000)];
      const forward = await foldVersion(base, v(3, items));
      const shuffled = await foldVersion(
        base,
        v(
          3,
          [...items].sort(() => 0.5 - Math.random()),
        ),
      );
      expect(shuffled).toEqual(forward);
    }, 120_000);

    it("never evicts established (pre-tracking) records: a flood displaces itself (F3)", async () => {
      const owner = ids("owner", 5_001);
      const base = await fold([v(1, owner)]);
      const flooded = (await foldVersion(base, v(2, ids("junk", 200_000))))!;
      const ownerKept = Object.keys(flooded.records).filter((key) =>
        key.startsWith("items:i:owner"),
      );
      expect(ownerKept).toHaveLength(5_001);
      expect(Object.keys(flooded.records).length).toBeLessThanOrEqual(
        MAX_TRACKED_KEYS,
      );
      // The owner imports the same records again: nothing is new to them.
      const again = (await foldVersion(flooded, v(3, owner)))!;
      expect(listAddedTimestamps(again)).toEqual([]);
    }, 120_000);

    it("keeps returning baseline records dated at the baseline after a disjoint version (F1b)", async () => {
      const x = ids("x", KEEP);
      const ledger = await fold([v(1, x), v(2, ids("y", KEEP))]);
      expect(Object.keys(ledger.records).length).toBeLessThanOrEqual(
        MAX_TRACKED_KEYS,
      );
      const back = (await foldVersion(ledger, v(3, x)))!;
      // All of x is still known and pre-tracking: none of it is an addition.
      expect(listAddedTimestamps(back)).toEqual([]);
    }, 120_000);

    it("KNOWN LIMITATION, not a guarantee: dated (not pre-tracking) records can be evicted and re-dated near the cap", async () => {
      // Day 1: a one-record baseline. Day 2: the owner's 5,001 records, which
      // are dated, so NOT pre-tracking. Day 3: a version of 199,000 other ids
      // brings the ledger to the cap; the owner's records are absent from it
      // and can be evicted. Day 4: the owner imports the same 5,001 again.
      const owner = ids("owner", 5_001);
      const ledger = (await fold([
        v(1, ids("seed", 1)),
        v(2, owner),
        v(3, ids("junk", 199_000)),
      ]))!;
      const kept = Object.keys(ledger.records).filter((key) =>
        key.startsWith("items:i:owner"),
      ).length;
      expect(kept).toBe(999);
      const again = (await foldVersion(ledger, v(4, owner)))!;
      const added = listAddedTimestamps(again);
      // 999 kept their day-2 date; 4,002 were forgotten and are dated as new.
      expect(added.filter((when) => when === at(2))).toHaveLength(999);
      expect(added.filter((when) => when === at(4))).toHaveLength(4_002);
    }, 120_000);

    it("evicts the most recently first-seen absent records first", async () => {
      const ledger = (await fold([
        v(1, []),
        v(2, ids("old", 100_000)),
        v(3, ids("mid", 50_000)),
        v(4, ids("new", 40_000)),
        v(5, ids("fresh", 30_000)),
      ]))!;
      const count = (prefix: string) =>
        Object.keys(ledger.records).filter((key) =>
          key.startsWith(`items:i:${prefix}`),
        ).length;
      // 20,000 had to go: the newest-first-seen absent ones.
      expect(count("old")).toBe(100_000);
      expect(count("mid")).toBe(50_000);
      expect(count("new")).toBe(20_000);
      expect(count("fresh")).toBe(30_000);
    }, 120_000);
  });

  it("holds __proto__ ids as ordinary own keys", async () => {
    const ledger = await fold([
      {
        scope: "notes.entries",
        collectedAt: T1,
        data: { items: rows("__proto__") },
      },
      {
        scope: "notes.entries",
        collectedAt: T2,
        data: { items: rows("__proto__", "x") },
      },
    ]);
    expect(Object.getPrototypeOf(ledger.records)).toBe(Object.prototype);
    expect(Object.keys(ledger.records)).toEqual([
      "items:i:__proto__",
      "items:i:x",
    ]);
    const odd = await foldVersion(null, {
      scope: "notes.entries",
      collectedAt: T1,
      data: JSON.parse('{"__proto__": [{"id": "a"}]}'),
    });
    expect(Object.keys(odd!.records)).toEqual(["__proto__:i:a"]);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    const round = readScopeFirstSeenLedger(JSON.parse(JSON.stringify(odd)));
    expect(round).toEqual(odd);
  });

  it("yields to the event loop while folding a large version", async () => {
    let ticks = 0;
    const timer = setInterval(() => {
      ticks += 1;
    }, 0);
    try {
      await fold([
        version(
          T1,
          Array.from({ length: 30_000 }, (_, i) => `r${i}`),
        ),
      ]);
    } finally {
      clearInterval(timer);
    }
    expect(ticks).toBeGreaterThan(0);
  });
});

describe("a partial ledger", () => {
  it("never moves its baseline back over versions it did not fold (reviewer: 107 false additions)", async () => {
    // Rebuilt from the newest versions only: day 100 is the oldest folded.
    const fold1 = new LedgerFold(null, "notes.entries");
    await fold1.add(
      version(
        iso(100),
        Array.from({ length: 107 }, (_, i) => `r${i}`),
      ),
    );
    await fold1.add(
      version(
        iso(101),
        Array.from({ length: 108 }, (_, i) => `r${i}`),
      ),
    );
    const partial = (await fold1.finish({ partial: true }))!;
    expect(partial.partial).toBe(true);
    expect(partial.baseline).toBe(iso(100));
    expect(listAddedTimestamps(partial)).toEqual([iso(101)]);

    // An older download arrives: it must not re-baseline the unfolded gap.
    const withOlder = (await foldVersion(partial, version(iso(0), ["r0"])))!;
    expect(withOlder.baseline).toBe(iso(100));
    expect(withOlder.records["items:i:r0"]).toEqual([iso(0), iso(101)]);
    expect(listAddedTimestamps(withOlder)).toEqual([iso(101)]);
  });

  it("a complete ledger still lowers its baseline for an older version", async () => {
    const complete = await fold([version(iso(10), ["a"])]);
    const older = (await foldVersion(complete, version(iso(0), ["a"])))!;
    expect(older.baseline).toBe(iso(0));
  });
});

describe("foldVersions", () => {
  it("equals folding one version at a time", async () => {
    const versions = [
      version(T3, ["c"]),
      version(T1, ["a"]),
      version(T2, ["a", "b"]),
    ];
    expect(await foldVersions(null, versions)).toEqual(await fold(versions));
  });
});

describe("readScopeFirstSeenLedger", () => {
  const valid: ScopeFirstSeenLedger = {
    version: 3,
    scope: "notes.entries",
    baseline: T1,
    current: T2,
    latest: { collectedAt: T2, total: 2 },
    through: T2,
    records: { "items:i:a": [T1, T2] },
  };

  it("accepts a well-formed document, copying it", () => {
    expect(readScopeFirstSeenLedger(valid)).toEqual(valid);
    expect(readScopeFirstSeenLedger(valid)).not.toBe(valid);
  });

  it("accepts a ledger without a baseline and the negative-outcome markers", () => {
    const empty = { ...valid, baseline: null, current: null, records: {} };
    expect(readScopeFirstSeenLedger(empty)).toEqual(empty);
    for (const skipped of ["too_large", "unreadable"]) {
      expect(readScopeFirstSeenLedger({ ...empty, skipped })?.skipped).toBe(
        skipped,
      );
    }
    expect(readScopeFirstSeenLedger({ ...valid, partial: true })?.partial).toBe(
      true,
    );
  });

  it.each<[string, unknown]>([
    ["null", null],
    ["a string", "x"],
    ["an array", []],
    ["a wrong version", { ...valid, version: 1 }],
    ["a version-2 sidecar (old key encoding)", { ...valid, version: 2 }],
    ["a missing through marker", { ...valid, through: undefined }],
    ["the retired too_many_keys state", { ...valid, skipped: "too_many_keys" }],
    ["a missing scope", { ...valid, scope: undefined }],
    ["an unparseable baseline", { ...valid, baseline: "nope" }],
    ["an unparseable current", { ...valid, current: "nope" }],
    ["a missing latest", { ...valid, latest: undefined }],
    [
      "a bad latest total",
      { ...valid, latest: { collectedAt: T2, total: -1 } },
    ],
    ["a bad skipped reason", { ...valid, skipped: "x" }],
    ["a bad partial flag", { ...valid, partial: false }],
    ["records as an array", { ...valid, records: [] }],
    ["a record that is not a pair", { ...valid, records: { a: [T1] } }],
    [
      "a record with an unparseable date",
      { ...valid, records: { a: [T1, "x"] } },
    ],
    ["a record with a number", { ...valid, records: { a: [1, 2] } }],
  ])("rejects %s", (_name, value) => {
    expect(readScopeFirstSeenLedger(value)).toBeNull();
  });

  it("never throws on hostile input", () => {
    const hostile = new Proxy(
      {},
      {
        get() {
          throw new Error("boom");
        },
        has() {
          throw new Error("boom");
        },
        ownKeys() {
          throw new Error("boom");
        },
        getOwnPropertyDescriptor() {
          throw new Error("boom");
        },
      },
    );
    expect(readScopeFirstSeenLedger(hostile)).toBeNull();
  });
});
