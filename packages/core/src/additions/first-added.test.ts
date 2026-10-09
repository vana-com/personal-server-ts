import { describe, expect, it } from "vitest";

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
      "items:i:7",
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
    expect(Math.max(...keys.map((key) => key.length))).toBeLessThanOrEqual(140);
    expect(keys[0]).toMatch(/^h:[0-9a-f]{32}:i:1000000$/);
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
    for (const key of keys) expect(key.length).toBeLessThanOrEqual(140);
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

    it("keeps join-only streams untracked", async () => {
      for (const scope of ["claude.messages", "instagram.post_likes"]) {
        expect(await keysOf(scope, { records: rows("a") })).toEqual({
          keys: [],
          total: 0,
        });
      }
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
      version: 2,
      scope: "notes.entries",
      baseline: T1,
      current: T1,
      latest: { collectedAt: T1, total: 2 },
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
    expect(listAddedTimestamps(afterBinary)).toEqual([T2]);

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

  it("enters a terminal skipped state when one snapshot is over the cap", async () => {
    const many = Array.from({ length: MAX_TRACKED_KEYS + 1 }, (_, i) => ({
      id: `k${i}`,
    }));
    const base = await fold([version(T1, ["a"])]);
    const capped = (await foldVersion(base, {
      scope: "notes.entries",
      collectedAt: T2,
      data: { items: many },
    }))!;
    expect(capped.skipped).toBe("too_many_keys");
    expect(capped.records).toEqual({});
    expect(capped.latest).toEqual({
      collectedAt: T2,
      total: MAX_TRACKED_KEYS + 1,
    });
    expect(listAddedTimestamps(capped)).toEqual([]);
    expect(readScopeFirstSeenLedger(capped)).toEqual(capped);

    // Later folds stay cheap: `latest` moves, keys never accumulate again.
    const next = (await foldVersion(capped, version(T3, ["a", "b"])))!;
    expect(next.skipped).toBe("too_many_keys");
    expect(next.records).toEqual({});
    expect(next.latest).toEqual({ collectedAt: T3, total: 2 });
  }, 30_000);

  it("enters the skipped state when the union over time passes the cap", async () => {
    const half = Math.floor(MAX_TRACKED_KEYS * 0.6);
    const batch = (prefix: string) => ({
      scope: "notes.entries",
      collectedAt: prefix === "a" ? T1 : T2,
      data: {
        items: Array.from({ length: half }, (_, i) => ({
          id: `${prefix}${i}`,
        })),
      },
    });
    const ledger = (await fold([batch("a"), batch("b")]))!;
    expect(ledger.skipped).toBe("too_many_keys");
    expect(ledger.records).toEqual({});
    expect(ledger.latest.total).toBe(half);
    // A document the reader accepts, so it is never rebuilt per request.
    expect(
      readScopeFirstSeenLedger(JSON.parse(JSON.stringify(ledger))),
    ).toEqual(ledger);
  }, 60_000);

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
    version: 2,
    scope: "notes.entries",
    baseline: T1,
    current: T2,
    latest: { collectedAt: T2, total: 2 },
    records: { "items:i:a": [T1, T2] },
  };

  it("accepts a well-formed document, copying it", () => {
    expect(readScopeFirstSeenLedger(valid)).toEqual(valid);
    expect(readScopeFirstSeenLedger(valid)).not.toBe(valid);
  });

  it("accepts a ledger without a baseline and the terminal skipped states", () => {
    const empty = { ...valid, baseline: null, current: null, records: {} };
    expect(readScopeFirstSeenLedger(empty)).toEqual(empty);
    for (const skipped of ["too_many_keys", "too_large", "unreadable"]) {
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
