import { describe, expect, it } from "vitest";

import {
  MAX_TRACKED_KEYS,
  extractRecordKeys,
  foldVersion,
  foldVersions,
  isPreTracking,
  isPresent,
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

  it("replaces an id longer than 128 characters by a bounded hash", async () => {
    const long = "x".repeat(200);
    const { keys } = await keysOf("test.scope", { items: [{ id: long }] });
    expect(keys).toHaveLength(1);
    expect(keys[0]).toMatch(/^items:h:[0-9a-f]{32}$/);
    expect(keys[0]!.length).toBeLessThan(60);
    // An id of exactly 128 characters is kept verbatim.
    const edge = "y".repeat(128);
    expect(
      (await keysOf("test.scope", { items: [{ id: edge }] })).keys,
    ).toEqual([`items:i:${edge}`]);
    // Different long ids hash differently, the same id hashes the same.
    const other = await keysOf("test.scope", { items: [{ id: `${long}!` }] });
    expect(other.keys).not.toEqual(keys);
    expect(
      (await keysOf("test.scope", { items: [{ id: long }] })).keys,
    ).toEqual(keys);
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

    it("uses the only rule of a scope whose dataset names no collection", async () => {
      // spotify.savedTracks rows are nested track objects.
      const { keys, total } = await keysOf("spotify.savedTracks", {
        records: [{ track: { id: "t1" } }, { track: { id: "t2" } }],
      });
      expect(keys).toEqual(["savedTracks:i:t1", "savedTracks:i:t2"]);
      expect(total).toBe(2);
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

async function fold(
  versions: VersionToFold[],
  start: ScopeFirstSeenLedger | null = null,
) {
  let ledger = start;
  for (const v of versions) ledger = await foldVersion(ledger, v);
  if (!ledger) throw new Error("expected a ledger");
  return ledger;
}

describe("foldVersion", () => {
  it("starts a ledger at the first version, dating nothing as new", async () => {
    const ledger = await fold([version(T1, ["a", "b"])]);
    expect(ledger).toEqual({
      version: 2,
      scope: "notes.entries",
      baseline: T1,
      latest: { collectedAt: T1, total: 2 },
      records: { "items:i:a": [T1, T1], "items:i:b": [T1, T1] },
    });
    expect(isPreTracking(ledger, "items:i:a")).toBe(true);
    expect(isPresent(ledger, "items:i:a")).toBe(true);
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
  });

  it("keeps a record's first date when it is absent for a version and returns", async () => {
    const ledger = await fold([
      version(T1, ["a", "b"]),
      version(T2, ["a"]),
      version(T3, ["a", "b"]),
    ]);
    expect(ledger.records["items:i:b"]).toEqual([T1, T3]);
    // b was absent from T2 but is present again at T3.
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
      const ledger = await fold(order.map((i) => versions[i]!));
      expect(ledger).toEqual(expected);
    }
    expect(expected.baseline).toBe(T1);
    expect(expected.latest.collectedAt).toBe(T3);
    expect(expected.records["items:i:c"]).toEqual([T2, T3]);
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

  it("lets a binary version move latest without resetting history", async () => {
    const base = await fold([version(T1, ["a"]), version(T2, ["a", "b"])]);
    const afterBinary = await foldVersion(base, {
      scope: "notes.entries",
      collectedAt: T3,
      data: { $binary: { mimeType: "application/pdf" } },
    });
    expect(afterBinary!.latest).toEqual({ collectedAt: T3, total: 0 });
    expect(afterBinary!.baseline).toBe(T1);
    expect(afterBinary!.records["items:i:b"]).toEqual([T2, T2]);
    const after = await foldVersion(
      afterBinary,
      version("2026-01-04T00:00:00.000Z", ["a", "b", "c"]),
    );
    expect(after!.records["items:i:b"]).toEqual([
      T2,
      "2026-01-04T00:00:00.000Z",
    ]);
    expect(after!.records["items:i:c"]![0]).toBe("2026-01-04T00:00:00.000Z");
    expect(isPreTracking(after!, "items:i:b")).toBe(false);
  });

  it("an older binary version changes nothing", async () => {
    const base = await fold([version(T2, ["a"])]);
    const next = await foldVersion(base, {
      scope: "notes.entries",
      collectedAt: T1,
      data: { $binary: {} },
    });
    expect(next!.latest).toEqual(base.latest);
    expect(next!.records).toEqual(base.records);
    // The earlier instant still moves the baseline back.
    expect(next!.baseline).toBe(T1);
  });

  it("does not mutate its inputs", async () => {
    const base = await fold([version(T1, ["a"])]);
    const snapshot = structuredClone(base);
    await foldVersion(base, version(T2, ["a", "b"]));
    expect(base).toEqual(snapshot);
  });

  it("prunes records absent for more than 90 days and keeps others", async () => {
    const day = 24 * 60 * 60 * 1000;
    const t0 = Date.parse(T1);
    const iso = (days: number) => new Date(t0 + days * day).toISOString();
    const ledger = await fold([
      version(iso(0), ["old", "kept", "back"]),
      version(iso(60), ["kept", "back"]),
      version(iso(100), ["kept"]),
    ]);
    // `old` was last seen 100 days before latest: pruned.
    expect(ledger.records["items:i:old"]).toBeUndefined();
    // `back` was last seen 40 days before latest: kept, though absent.
    expect(ledger.records["items:i:back"]).toEqual([iso(0), iso(60)]);
    expect(isPresent(ledger, "items:i:back")).toBe(false);
    // A record that returns after being kept keeps its original date.
    const returned = await foldVersion(ledger, version(iso(110), ["back"]));
    expect(returned!.records["items:i:back"]).toEqual([iso(0), iso(110)]);
  });

  it("skips tracking above the key cap and records the reason", async () => {
    const many = Array.from({ length: MAX_TRACKED_KEYS + 1 }, (_, i) => ({
      id: `k${i}`,
    }));
    const base = await fold([version(T1, ["a"])]);
    const capped = await foldVersion(base, {
      scope: "notes.entries",
      collectedAt: T2,
      data: { items: many },
    });
    expect(capped!.latest).toEqual({
      collectedAt: T2,
      total: MAX_TRACKED_KEYS + 1,
      skipped: "too_many_keys",
    });
    expect(Object.keys(capped!.records)).toEqual(["items:i:a"]);
  }, 30_000);

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
    // A collection literally named __proto__ must not pollute either.
    const odd = await foldVersion(null, {
      scope: "notes.entries",
      collectedAt: T1,
      data: JSON.parse('{"__proto__": [{"id": "a"}]}'),
    });
    expect(Object.keys(odd!.records)).toEqual(["__proto__:i:a"]);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    const round = readScopeFirstSeenLedger(JSON.parse(JSON.stringify(odd)));
    expect(round).toEqual(odd);
    expect(Object.keys(round!.records)).toEqual(["__proto__:i:a"]);
  });
});

describe("foldVersions", () => {
  it("equals folding one version at a time", async () => {
    const versions = [
      version(T3, ["c"]),
      version(T1, ["a"]),
      version(T2, ["a", "b"]),
    ];
    const batch = await foldVersions(null, versions);
    expect(batch).toEqual(await fold(versions));
  });
});

describe("readScopeFirstSeenLedger", () => {
  const valid: ScopeFirstSeenLedger = {
    version: 2,
    scope: "notes.entries",
    baseline: T1,
    latest: { collectedAt: T2, total: 2 },
    records: { "items:i:a": [T1, T2] },
  };

  it("accepts a well-formed document", () => {
    expect(readScopeFirstSeenLedger(valid)).toEqual(valid);
    expect(readScopeFirstSeenLedger(valid)).not.toBe(valid);
    expect(
      readScopeFirstSeenLedger({
        ...valid,
        latest: { ...valid.latest, skipped: "too_many_keys" },
      })?.latest.skipped,
    ).toBe("too_many_keys");
  });

  it.each<[string, unknown]>([
    ["null", null],
    ["a string", "x"],
    ["an array", []],
    ["a wrong version", { ...valid, version: 1 }],
    ["a missing scope", { ...valid, scope: undefined }],
    ["an unparseable baseline", { ...valid, baseline: "nope" }],
    ["a missing latest", { ...valid, latest: undefined }],
    [
      "a bad latest total",
      { ...valid, latest: { collectedAt: T2, total: -1 } },
    ],
    [
      "a bad skipped reason",
      { ...valid, latest: { collectedAt: T2, total: 1, skipped: "x" } },
    ],
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
