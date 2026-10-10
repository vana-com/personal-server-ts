import { describe, expect, it, vi } from "vitest";
import { createDataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";
import type { DataStoragePort } from "../ports/index.js";
import {
  ingestBinaryDataContract,
  ingestDataContract,
} from "../contracts/data.js";
import {
  LedgerFold,
  MAX_TRACKED_KEYS,
  listAddedTimestamps,
  readScopeFirstSeenLedger,
} from "./first-added.js";
import { ensureScopeLedger, recordStoredVersion } from "./ledger-store.js";
import { withScopeLock } from "./scope-lock.js";

const SCOPE = "notes.entries";
const HOUR = 3_600_000;
const T0 = Date.parse("2026-09-01T12:00:00Z");
const at = (index: number) =>
  new Date(T0 + index * HOUR).toISOString().replace(".000Z", "Z");
const items = (...ids: string[]) => ({ items: ids.map((id) => ({ id })) });
const upTo = (count: number) =>
  Array.from({ length: count }, (_, i) => `r${i}`);

/** Store a version straight into the index, as an old install or a sync would. */
async function put(
  storage: DataStoragePort,
  scope: string,
  collectedAt: string,
  data: Record<string, unknown>,
  sizeBytes = 100,
  extra: { version?: number; afterTombstoneVersion?: number | null } = {},
) {
  const written = await storage.writeEnvelope(
    createDataFileEnvelope(scope, collectedAt, data),
  );
  await storage.insertEntry({
    fileId: null,
    schemaId: null,
    path: written.relativePath,
    scope,
    collectedAt,
    sizeBytes,
    afterTombstoneVersion: extra.afterTombstoneVersion ?? null,
    ...(extra.version !== undefined ? { version: extra.version } : {}),
  });
}

async function stored(storage: DataStoragePort, scope = SCOPE) {
  return readScopeFirstSeenLedger(await storage.readFirstSeenLedger!(scope));
}

describe("a rebuild folds one envelope at a time", () => {
  it("alternates read and fold, never holding the history", async () => {
    const storage = createMemoryDataStorage();
    for (let i = 0; i < 12; i += 1)
      await put(storage, SCOPE, at(i), items(...upTo(i + 1)));
    const events: string[] = [];
    const readEnvelope = storage.readEnvelope.bind(storage);
    storage.readEnvelope = async (scope, collectedAt) => {
      events.push("read");
      return readEnvelope(scope, collectedAt);
    };
    const add = LedgerFold.prototype.add;
    const spy = vi
      .spyOn(LedgerFold.prototype, "add")
      .mockImplementation(async function (this: LedgerFold, version) {
        events.push("fold");
        return add.call(this, version);
      });
    try {
      await ensureScopeLedger(storage, SCOPE);
    } finally {
      spy.mockRestore();
    }
    expect(events).toEqual(
      Array.from({ length: 12 }, () => ["read", "fold"]).flat(),
    );
  });

  it("does not read any envelope of a scope whose rules track nothing", async () => {
    const storage = createMemoryDataStorage();
    for (let i = 0; i < 5; i += 1) {
      await put(storage, "chatgpt.messages", at(i), {
        records: [{ id: `m${i}` }],
      });
    }
    const readEnvelope = vi.spyOn(storage, "readEnvelope");
    const ledger = await ensureScopeLedger(storage, "chatgpt.messages");
    expect(readEnvelope).not.toHaveBeenCalled();
    expect(ledger).toMatchObject({
      baseline: at(0),
      latest: { collectedAt: at(4), total: 0 },
      records: {},
    });
  });

  it("stops at the byte budget, newest versions first, and clamps the baseline", async () => {
    const storage = createMemoryDataStorage();
    for (let i = 0; i < 6; i += 1) {
      await put(storage, SCOPE, at(i), items(...upTo(i + 1)), 100);
    }
    const readEnvelope = vi.spyOn(storage, "readEnvelope");

    const ledger = await ensureScopeLedger(storage, SCOPE, { byteBudget: 350 });

    // Versions 5, 4 and 3 fit (300 bytes); 2, 1 and 0 stay unread.
    expect(readEnvelope).toHaveBeenCalledTimes(3);
    expect(ledger?.partial).toBe(true);
    expect(ledger?.baseline).toBe(at(3));
    // r3 and r4 appeared in versions that were not folded: not "added".
    expect(listAddedTimestamps(ledger!)).toEqual([at(4), at(5)]);
    expect(ledger?.records["items:i:r0"]).toEqual([at(3), at(5)]);
  });

  it("clamps to the 200 newest versions", async () => {
    const storage = createMemoryDataStorage();
    for (let i = 0; i < 230; i += 1)
      await put(storage, SCOPE, at(i), items(...upTo(2)));
    const ledger = await ensureScopeLedger(storage, SCOPE);
    expect(ledger?.baseline).toBe(at(30));
    expect(ledger?.partial).toBe(true);
  });

  it("an older download cannot jump the baseline over unfolded versions", async () => {
    const storage = createMemoryDataStorage();
    for (let i = 0; i < 230; i += 1) {
      await put(storage, SCOPE, at(i), items(...upTo(Math.min(i + 1, 150))));
    }
    await ensureScopeLedger(storage, SCOPE);
    const before = await stored(storage);
    expect(before?.partial).toBe(true);

    await put(storage, SCOPE, at(-5), items("r0"));
    await recordStoredVersion(storage, {
      scope: SCOPE,
      collectedAt: at(-5),
      data: items("r0"),
    });
    const after = await ensureScopeLedger(storage, SCOPE);
    expect(after?.baseline).toBe(before?.baseline);
    expect(listAddedTimestamps(after!).length).toBe(
      listAddedTimestamps(before!).length,
    );
  });
});

describe("negative outcomes are persisted", () => {
  it("does not retry an oversized rebuild on every request", async () => {
    const storage = createMemoryDataStorage();
    await put(storage, SCOPE, at(0), items("a"), 10_000);
    await put(storage, SCOPE, at(1), items("a", "b"), 10_000);
    const readEnvelope = vi.spyOn(storage, "readEnvelope");

    const first = await ensureScopeLedger(storage, SCOPE, { byteBudget: 500 });
    expect(first).toMatchObject({
      skipped: "too_large",
      baseline: null,
      latest: { collectedAt: at(1), total: 0 },
    });
    expect(await stored(storage)).toEqual(first);
    for (let i = 0; i < 3; i += 1) {
      await ensureScopeLedger(storage, SCOPE, { byteBudget: 500 });
    }
    expect(readEnvelope).not.toHaveBeenCalled();

    // A newer version earns exactly one more attempt.
    await put(storage, SCOPE, at(2), items("a", "b", "c"), 10);
    const retried = await ensureScopeLedger(storage, SCOPE, {
      byteBudget: 500,
    });
    expect(retried?.skipped).toBeUndefined();
    expect(retried?.latest.collectedAt).toBe(at(2));
  });

  it("does not retry a rebuild where no version could be read", async () => {
    const storage = createMemoryDataStorage();
    await put(storage, SCOPE, at(0), items("a"));
    vi.spyOn(storage, "readEnvelope").mockRejectedValue(new Error("gone"));
    const first = await ensureScopeLedger(storage, SCOPE);
    expect(first?.skipped).toBe("unreadable");
    (storage.readEnvelope as ReturnType<typeof vi.fn>).mockClear();
    await ensureScopeLedger(storage, SCOPE);
    expect(storage.readEnvelope).not.toHaveBeenCalled();
  });

  it("an over-cap version never disables tracking: normal imports resume (B1)", async () => {
    const storage = createMemoryDataStorage();
    const ingest = (body: Record<string, unknown>, collectedAt: string) =>
      ingestDataContract({
        storage,
        scopeParam: SCOPE,
        body,
        collectedAt,
        status: "stored",
      });
    await ingest(items("a"), at(0));
    await ingest(
      {
        items: Array.from({ length: MAX_TRACKED_KEYS + 1 }, (_, i) => ({
          id: `k${i}`,
        })),
      },
      at(1),
    );
    await ingest(items("a", "b"), at(2));

    const ledger = await stored(storage);
    expect(ledger?.skipped).toBeUndefined();
    expect(ledger?.records["items:i:b"]).toEqual([at(2), at(2)]);
    expect(listAddedTimestamps(ledger!)).toEqual([at(0), at(2)]);

    // Rebuilding with the offending version inside the window ends the same
    // way, and repeated reads make no envelope reads.
    await storage.deleteFirstSeenLedger!(SCOPE);
    const rebuilt = await ensureScopeLedger(storage, SCOPE);
    expect(rebuilt?.skipped).toBeUndefined();
    expect(listAddedTimestamps(rebuilt!)).toEqual([at(0), at(2)]);
    const readEnvelope = vi.spyOn(storage, "readEnvelope");
    for (let i = 0; i < 3; i += 1) await ensureScopeLedger(storage, SCOPE);
    expect(readEnvelope).not.toHaveBeenCalled();
  }, 60_000);

  it("two disjoint versions beyond the cap stay readable, bounded and tracking", async () => {
    const storage = createMemoryDataStorage();
    const part = Math.floor(MAX_TRACKED_KEYS * 0.75);
    const batch = (prefix: string) => ({
      items: Array.from({ length: part }, (_, i) => ({ id: `${prefix}${i}` })),
    });
    const ingest = (body: Record<string, unknown>, collectedAt: string) =>
      ingestDataContract({
        storage,
        scopeParam: SCOPE,
        body,
        collectedAt,
        status: "stored",
      });
    await ingest(batch("a"), at(0));
    await ingest(batch("b"), at(1));

    const ledger = await stored(storage);
    expect(ledger).not.toBeNull();
    expect(Object.keys(ledger!.records).length).toBeLessThanOrEqual(
      MAX_TRACKED_KEYS,
    );
    expect(ledger?.skipped).toBeUndefined();
    expect(ledger?.latest.total).toBe(part);

    const readEnvelope = vi.spyOn(storage, "readEnvelope");
    for (let i = 0; i < 3; i += 1) {
      expect(
        (await ensureScopeLedger(storage, SCOPE))?.skipped,
      ).toBeUndefined();
    }
    expect(readEnvelope).not.toHaveBeenCalled();
    // The established records stay known: returning is not an addition.
    await ingest(batch("a"), at(2));
    expect(
      listAddedTimestamps((await stored(storage))!).filter(
        (when) => when === at(2),
      ),
    ).toEqual([]);
  }, 90_000);
});

describe("catch-up folds every missed version", () => {
  it("equals a full rebuild when ten versions were missed", async () => {
    const storage = createMemoryDataStorage();
    await put(storage, SCOPE, at(0), items("r0"));
    await ensureScopeLedger(storage, SCOPE);
    for (let i = 1; i <= 10; i += 1) {
      await put(storage, SCOPE, at(i), items(...upTo(i + 1)));
    }
    const caughtUp = await ensureScopeLedger(storage, SCOPE);
    await storage.deleteFirstSeenLedger!(SCOPE);
    const rebuilt = await ensureScopeLedger(storage, SCOPE);
    expect(caughtUp).toEqual(rebuilt);
    expect(caughtUp?.records["items:i:r9"]).toEqual([at(9), at(10)]);
  });
});

describe("version deletion never leaves a stale sidecar", () => {
  async function seeded() {
    const storage = createMemoryDataStorage();
    for (let i = 0; i < 3; i += 1) {
      await ingestDataContract({
        storage,
        scopeParam: SCOPE,
        body: items(...upTo(i + 1), "secret-id"),
        collectedAt: at(i),
        status: "stored",
      });
    }
    await ensureScopeLedger(storage, SCOPE);
    expect(await stored(storage)).not.toBeNull();
    return storage;
  }

  it("drops it when deleteVersion removes the last version", async () => {
    const storage = createMemoryDataStorage();
    await ingestDataContract({
      storage,
      scopeParam: SCOPE,
      body: items("secret-id"),
      collectedAt: at(0),
      status: "stored",
    });
    expect(await stored(storage)).not.toBeNull();
    await storage.deleteVersion(SCOPE, at(0));
    expect(await storage.readFirstSeenLedger!(SCOPE)).toBeNull();
  });

  it("drops it when deleteByFileId removes the last version", async () => {
    const storage = createMemoryDataStorage();
    await ingestDataContract({
      storage,
      scopeParam: SCOPE,
      body: items("secret-id"),
      collectedAt: at(0),
      status: "stored",
    });
    storage.updateFileId(storage.entries[0]!.path, "file-1");
    await storage.deleteByFileId("file-1");
    expect(await storage.readFirstSeenLedger!(SCOPE)).toBeNull();
  });

  it("drops it when dropUnsyncedEntry removes the last row", async () => {
    const storage = createMemoryDataStorage();
    await ingestDataContract({
      storage,
      scopeParam: SCOPE,
      body: items("secret-id"),
      collectedAt: at(0),
      status: "stored",
    });
    expect(await storage.dropUnsyncedEntry!(storage.entries[0]!.path)).toBe(
      true,
    );
    expect(await storage.readFirstSeenLedger!(SCOPE)).toBeNull();
  });

  it("keeps it while other versions remain", async () => {
    const storage = await seeded();
    await storage.deleteVersion(SCOPE, at(0));
    expect(await stored(storage)).not.toBeNull();
  });

  it("stops reporting a deleted newest version's records", async () => {
    const storage = await seeded();
    await storage.deleteVersion(SCOPE, at(2));

    const ledger = await ensureScopeLedger(storage, SCOPE);
    expect(ledger?.latest).toMatchObject({ collectedAt: at(1), total: 3 });
    expect(ledger?.records["items:i:r2"]).toBeUndefined();
    expect(ledger?.current).toBe(at(1));
  });

  it("also discards a stale sidecar on the write path", async () => {
    const storage = await seeded();
    await storage.deleteVersion(SCOPE, at(2));
    await ingestDataContract({
      storage,
      scopeParam: SCOPE,
      body: items("a"),
      collectedAt: at(5),
      status: "stored",
    });
    // The stale sidecar is gone; the owner's read rebuilds without r2.
    expect(await storage.readFirstSeenLedger!(SCOPE)).toBeNull();
    const ledger = await ensureScopeLedger(storage, SCOPE);
    expect(ledger?.records["items:i:r2"]).toBeUndefined();
  });

  it("a delete racing a rebuild leaves no sidecar (lock)", async () => {
    const storage = createMemoryDataStorage();
    await put(storage, SCOPE, at(0), items("secret-id"));
    const readEnvelope = storage.readEnvelope.bind(storage);
    let deletion: Promise<number> | undefined;
    storage.readEnvelope = async (scope, collectedAt) => {
      const envelope = await readEnvelope(scope, collectedAt);
      // The owner's delete lands while the rebuild is reading.
      deletion ??= storage.deleteScope(scope);
      return envelope;
    };
    await ensureScopeLedger(storage, SCOPE);
    await deletion;
    expect(storage.entries).toHaveLength(0);
    expect(await storage.readFirstSeenLedger!(SCOPE)).toBeNull();
  });

  it("a delete racing a rebuild leaves no sidecar (re-check, no lock)", async () => {
    const storage = createMemoryDataStorage();
    await put(storage, SCOPE, at(0), items("secret-id"));
    const readEnvelope = storage.readEnvelope.bind(storage);
    storage.readEnvelope = async (scope, collectedAt) => {
      const envelope = await readEnvelope(scope, collectedAt);
      // A port whose deletes know nothing of the lock.
      storage.entries.length = 0;
      return envelope;
    };
    expect(await ensureScopeLedger(storage, SCOPE)).toBeNull();
    expect(await storage.readFirstSeenLedger!(SCOPE)).toBeNull();
  });

  it("scope deletion waits for the sidecar lock", async () => {
    const storage = createMemoryDataStorage();
    await put(storage, SCOPE, at(0), items("a"));
    let releaseLock!: () => void;
    const held = withScopeLock(
      SCOPE,
      () => new Promise<void>((resolve) => (releaseLock = resolve)),
    );
    let finished = false;
    const deletion = storage.deleteScope(SCOPE).then(() => {
      finished = true;
    });
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(finished).toBe(false);
    releaseLock();
    await held;
    await deletion;
    expect(finished).toBe(true);
  });
});

describe("binary writes", () => {
  it("count as one record and leave the sidecar current", async () => {
    const storage = createMemoryDataStorage();
    await ingestDataContract({
      storage,
      scopeParam: SCOPE,
      body: items("a"),
      collectedAt: at(0),
      status: "stored",
    });
    await ingestBinaryDataContract({
      storage,
      scopeParam: SCOPE,
      bytes: new TextEncoder().encode("%PDF"),
      mimeType: "application/pdf",
      collectedAt: at(1),
      status: "stored",
    });
    expect((await stored(storage))?.latest).toEqual({
      collectedAt: at(1),
      total: 1,
    });
  });
});

describe("a sidecar far behind is not mistaken for a deleted one (B4)", () => {
  it("keeps a ledger whose latest version is older than the 200 newest", async () => {
    const storage = createMemoryDataStorage();
    await put(storage, SCOPE, at(0), items("r0"));
    await ensureScopeLedger(storage, SCOPE);
    for (let i = 1; i <= 230; i += 1)
      await put(storage, SCOPE, at(i), items("r0", "r1"));

    // `latest` (version 0) lies beyond the 200-version window; it still exists.
    const caught = await ensureScopeLedger(storage, SCOPE);
    expect(caught?.baseline).toBe(at(0));
    expect(caught?.records["items:i:r0"]![0]).toBe(at(0));
    expect(caught?.latest.collectedAt).toBe(at(230));
  });
});

describe("added never exceeds total (B10)", () => {
  it("reports no additions while the newest version is a binary file", async () => {
    const storage = createMemoryDataStorage();
    const ingest = (body: Record<string, unknown>, collectedAt: string) =>
      ingestDataContract({
        storage,
        scopeParam: SCOPE,
        body,
        collectedAt,
        status: "stored",
      });
    await ingest(items("a"), at(0));
    await ingest(items("a", "b", "c"), at(1));
    expect(listAddedTimestamps((await stored(storage))!)).toHaveLength(3);

    await ingestBinaryDataContract({
      storage,
      scopeParam: SCOPE,
      bytes: new TextEncoder().encode("%PDF"),
      mimeType: "application/pdf",
      collectedAt: at(2),
      status: "stored",
    });
    const ledger = (await stored(storage))!;
    expect(ledger.latest.total).toBe(1);
    expect(listAddedTimestamps(ledger)).toEqual([]);

    // The next JSON version brings the numbers back in step.
    await ingest(items("a", "b", "c", "d"), at(3));
    const after = (await stored(storage))!;
    expect(after.latest.total).toBe(4);
    expect(listAddedTimestamps(after).length).toBeLessThanOrEqual(
      after.latest.total,
    );
    expect(listAddedTimestamps(after)).toHaveLength(4);
  });

  it("a too_large marker reports no additions and total 0", async () => {
    const storage = createMemoryDataStorage();
    await put(storage, SCOPE, at(0), items("a"), 10_000);
    const marker = await ensureScopeLedger(storage, SCOPE, { byteBudget: 10 });
    expect(marker).toMatchObject({ skipped: "too_large" });
    expect(listAddedTimestamps(marker!)).toEqual([]);
  });
});

describe("versions at the same instant (F6)", () => {
  it("fold to the same ledger in either order, and added never exceeds total", async () => {
    const a = createMemoryDataStorage();
    const b = createMemoryDataStorage();
    const plain = "2026-09-01T12:00:00Z";
    const millis = "2026-09-01T12:00:00.000Z";
    await put(a, SCOPE, plain, items("x", "y", "z"));
    await put(a, SCOPE, millis, items("x"));
    await put(b, SCOPE, millis, items("x"));
    await put(b, SCOPE, plain, items("x", "y", "z"));
    await put(a, SCOPE, at(5), items("x", "y", "z", "w"));
    await put(b, SCOPE, at(5), items("x", "y", "z", "w"));
    const one = await ensureScopeLedger(a, SCOPE);
    const two = await ensureScopeLedger(b, SCOPE);
    expect(one).toEqual(two);

    // A newest pair at one instant: the greater string decides, and the
    // additions it reports fit its total.
    await put(a, SCOPE, "2026-10-01T00:00:00Z", items("x", "y", "z", "w", "v"));
    await put(a, SCOPE, "2026-10-01T00:00:00.000Z", items("x"));
    const ledger = await ensureScopeLedger(a, SCOPE);
    expect(ledger?.latest.collectedAt).toBe("2026-10-01T00:00:00Z");
    expect(listAddedTimestamps(ledger!).length).toBeLessThanOrEqual(
      ledger!.latest.total,
    );
  });
});

describe("edges (F7)", () => {
  it("counts a binary file in an empty-rule scope as 0 on the write and after a rebuild", async () => {
    const storage = createMemoryDataStorage();
    await ingestBinaryDataContract({
      storage,
      scopeParam: "chatgpt.messages",
      bytes: new TextEncoder().encode("%PDF"),
      mimeType: "application/pdf",
      collectedAt: at(0),
      status: "stored",
    });
    const written = await stored(storage, "chatgpt.messages");
    await storage.deleteFirstSeenLedger!("chatgpt.messages");
    const rebuilt = await ensureScopeLedger(storage, "chatgpt.messages");
    expect(written?.latest.total).toBe(0);
    expect(rebuilt?.latest.total).toBe(0);
  });

  it("is not partial when exactly 200 versions were folded and none skipped", async () => {
    const storage = createMemoryDataStorage();
    for (let i = 0; i < 200; i += 1)
      await put(storage, SCOPE, at(i), items("a"));
    expect((await ensureScopeLedger(storage, SCOPE))?.partial).toBeUndefined();

    const caught = createMemoryDataStorage();
    await put(caught, SCOPE, at(0), items("a"));
    await ensureScopeLedger(caught, SCOPE);
    for (let i = 1; i <= 200; i += 1)
      await put(caught, SCOPE, at(i), items("a"));
    // 200 newer versions plus the folded one: the window covers all but one
    // that was already folded; nothing is skipped.
    expect((await ensureScopeLedger(caught, SCOPE))?.partial).toBeUndefined();
  });

  it("rejects a through marker later than the latest version, so catch-up is not suppressed", async () => {
    const storage = createMemoryDataStorage();
    await put(storage, SCOPE, at(0), items("a"));
    const ledger = (await ensureScopeLedger(storage, SCOPE))!;
    expect(readScopeFirstSeenLedger({ ...ledger, through: at(9) })).toBeNull();
    await put(storage, SCOPE, at(1), items("a", "b"));
    await storage.writeFirstSeenLedger!(SCOPE, { ...ledger, through: at(9) });
    // The forged marker is discarded: the read rebuilds and sees version 1.
    expect((await ensureScopeLedger(storage, SCOPE))?.latest.collectedAt).toBe(
      at(1),
    );
  });

  describe("an unreadable version is retried cheaply (P2)", () => {
    const HOUR_MS = 60 * 60 * 1000;
    const clock = (hours: number) =>
      new Date(Date.parse(at(0)) + hours * HOUR_MS);

    /** A scope whose version 2 cannot be read until `fix()` is called. */
    async function brokenScope() {
      const storage = createMemoryDataStorage();
      await put(storage, SCOPE, at(0), items("a"));
      await ensureScopeLedger(storage, SCOPE, { now: clock(0) });
      await put(storage, SCOPE, at(1), items("a", "b"));
      await put(storage, SCOPE, at(2), items("a", "b", "c"));
      const readEnvelope = storage.readEnvelope.bind(storage);
      let broken = true;
      let reads = 0;
      storage.readEnvelope = async (scope, collectedAt) => {
        reads += 1;
        if (broken && collectedAt === at(2)) throw new Error("not yet");
        return readEnvelope(scope, collectedAt);
      };
      return {
        storage,
        fix: () => {
          broken = false;
        },
        reads: () => reads,
        resetReads: () => {
          reads = 0;
        },
      };
    }

    it("(a) reads only on the first of three polls within the hour", async () => {
      const scope = await brokenScope();
      const first = await ensureScopeLedger(scope.storage, SCOPE, {
        now: clock(1),
      });
      expect(first?.latest.collectedAt).toBe(at(1));
      expect(first?.retry).toEqual({
        versions: [at(2)],
        attemptedAt: clock(1).toISOString(),
      });
      expect(first?.through).toBe(at(2));
      expect(scope.reads()).toBeGreaterThan(0);

      scope.resetReads();
      for (const minutes of [1, 30, 59]) {
        const again = await ensureScopeLedger(scope.storage, SCOPE, {
          now: new Date(clock(1).getTime() + minutes * 60_000),
        });
        expect(again?.latest.collectedAt).toBe(at(1));
      }
      expect(scope.reads()).toBe(0);
    });

    it("(b) retries once after an hour, and not again straight after", async () => {
      const scope = await brokenScope();
      await ensureScopeLedger(scope.storage, SCOPE, { now: clock(1) });
      scope.resetReads();

      await ensureScopeLedger(scope.storage, SCOPE, { now: clock(2) });
      expect(scope.reads()).toBe(1);
      const stored = await scope.storage.readFirstSeenLedger!(SCOPE);
      expect(
        (stored as { retry: { attemptedAt: string } }).retry.attemptedAt,
      ).toBe(clock(2).toISOString());
      await ensureScopeLedger(scope.storage, SCOPE, { now: clock(2.5) });
      expect(scope.reads()).toBe(1);
    });

    it("(c) converges to a full rebuild once readable, and the marker clears", async () => {
      const scope = await brokenScope();
      await ensureScopeLedger(scope.storage, SCOPE, { now: clock(1) });
      scope.fix();
      const healed = (await ensureScopeLedger(scope.storage, SCOPE, {
        now: clock(3),
      }))!;
      expect(healed.retry).toBeUndefined();
      expect(healed.latest.collectedAt).toBe(at(2));

      await scope.storage.deleteFirstSeenLedger!(SCOPE);
      const rebuilt = (await ensureScopeLedger(scope.storage, SCOPE, {
        now: clock(3),
      }))!;
      expect({ ...healed, through: undefined }).toEqual({
        ...rebuilt,
        through: undefined,
      });
    });

    it("(c) converges too when the unreadable version is deleted, without reading", async () => {
      const scope = await brokenScope();
      await ensureScopeLedger(scope.storage, SCOPE, { now: clock(1) });
      await scope.storage.deleteVersion(SCOPE, at(2));
      scope.resetReads();
      const after = (await ensureScopeLedger(scope.storage, SCOPE, {
        now: clock(1.1),
      }))!;
      expect(after.retry).toBeUndefined();
      expect(scope.reads()).toBe(0);
      expect(after.latest.collectedAt).toBe(at(1));
    });

    it("(d) a version arriving after the unreadable one is folded on the write with zero reads", async () => {
      const scope = await brokenScope();
      await ensureScopeLedger(scope.storage, SCOPE, { now: clock(1) });
      scope.resetReads();

      await ingestDataContract({
        storage: scope.storage,
        scopeParam: SCOPE,
        body: items("a", "b", "d"),
        collectedAt: at(3),
        status: "stored",
      });
      expect(scope.reads()).toBe(0);
      const ledger = (await stored(scope.storage))!;
      expect(ledger.latest).toEqual({ collectedAt: at(3), total: 3 });
      expect(ledger.records["items:i:d"]).toEqual([at(3), at(3)]);
      expect(ledger.retry?.versions).toEqual([at(2)]);

      // A poll with nothing new reads nothing, even with the version pending.
      await ensureScopeLedger(scope.storage, SCOPE, { now: clock(1.2) });
      expect(scope.reads()).toBe(0);
    });
  });
});

describe("when the baseline's records count as added (first-import rule)", () => {
  const ingest = (
    storage: DataStoragePort,
    body: Record<string, unknown>,
    collectedAt: string,
  ) =>
    ingestDataContract({
      storage,
      scopeParam: SCOPE,
      body,
      collectedAt,
      status: "stored",
    });

  it("(a) a sidecar started from the scope's only version is complete: its records count", async () => {
    const storage = createMemoryDataStorage();
    await ingest(storage, items("a", "b", "c"), at(0));
    const ledger = (await stored(storage))!;
    expect(ledger.partial).toBeUndefined();
    expect(listAddedTimestamps(ledger)).toEqual([at(0), at(0), at(0)]);
  });

  it("(a) but not when that only version is not the scope's first (its number is above 1)", async () => {
    const storage = createMemoryDataStorage();
    await put(storage, SCOPE, at(0), items("a", "b"), 100, { version: 5 });
    await recordStoredVersion(storage, {
      scope: SCOPE,
      collectedAt: at(0),
      data: items("a", "b"),
    });
    const ledger = (await stored(storage))!;
    expect(ledger.partial).toBe(true);
    expect(listAddedTimestamps(ledger)).toEqual([]);
  });

  it("(b) a rebuild after the write path left the sidecar absent is complete", async () => {
    const storage = createMemoryDataStorage();
    await put(storage, SCOPE, at(0), items("a", "b"));
    await put(storage, SCOPE, at(1), items("a", "b", "c"));
    await ingest(storage, items("a", "b", "c", "d"), at(2));
    expect(await storage.readFirstSeenLedger!(SCOPE)).toBeNull();
    const ledger = (await ensureScopeLedger(storage, SCOPE))!;
    expect(ledger.partial).toBeUndefined();
    expect(listAddedTimestamps(ledger)).toEqual([at(0), at(0), at(1), at(2)]);
  });

  it("(b) a rebuild that is cut short by the window or the budget is partial", async () => {
    const storage = createMemoryDataStorage();
    for (let i = 0; i < 6; i += 1)
      await put(storage, SCOPE, at(i), items(...upTo(i + 1)));
    const ledger = (await ensureScopeLedger(storage, SCOPE, {
      byteBudget: 350,
    }))!;
    expect(ledger.partial).toBe(true);
    expect(listAddedTimestamps(ledger)).toEqual([at(4), at(5)]);
  });

  it("(c) deleted older versions leave the oldest retained version number above 1: partial", async () => {
    const storage = createMemoryDataStorage();
    await put(storage, SCOPE, at(0), items("a"));
    await put(storage, SCOPE, at(1), items("a", "b"));
    await put(storage, SCOPE, at(2), items("a", "b", "c"));
    await storage.deleteVersion(SCOPE, at(0));
    const ledger = (await ensureScopeLedger(storage, SCOPE))!;
    expect(ledger.partial).toBe(true);
    expect(ledger.baseline).toBe(at(1));
    // The baseline's records have an unknown date; the later one counts.
    expect(listAddedTimestamps(ledger)).toEqual([at(2)]);
  });

  it("(c) a version written after a deletion starts afresh and counts, even above number 1", async () => {
    const storage = createMemoryDataStorage();
    await put(storage, SCOPE, at(0), items("a", "b"), 100, {
      version: 4,
      afterTombstoneVersion: 3,
    });
    const ledger = (await ensureScopeLedger(storage, SCOPE))!;
    expect(ledger.partial).toBeUndefined();
    expect(listAddedTimestamps(ledger)).toEqual([at(0), at(0)]);
  });

  it("(c) LIMITATION: a middle version deleted leaves no trace, so the baseline still counts", async () => {
    const storage = createMemoryDataStorage();
    await put(storage, SCOPE, at(0), items("a"));
    await put(storage, SCOPE, at(1), items("a", "b"));
    await put(storage, SCOPE, at(2), items("a", "b", "c"));
    await storage.deleteVersion(SCOPE, at(1));
    const ledger = (await ensureScopeLedger(storage, SCOPE))!;
    expect(ledger.partial).toBeUndefined();
    // "b" arrived in the deleted version but is dated by the next one.
    expect(ledger.records["items:i:b"]).toEqual([at(2), at(2)]);
  });

  it("(d) delete the scope and reimport: the reimport's records count on its day", async () => {
    const storage = createMemoryDataStorage();
    await ingest(storage, items("a"), at(0));
    await storage.deleteScope(SCOPE);
    await ingest(storage, items("a", "b"), at(9));
    const ledger = (await stored(storage))!;
    expect(ledger.baseline).toBe(at(9));
    expect(listAddedTimestamps(ledger)).toEqual([at(9), at(9)]);
  });

  it("(e) a version older than the baseline arriving later moves the baseline back", async () => {
    const storage = createMemoryDataStorage();
    await ingest(storage, items("a", "b"), at(5));
    await put(storage, SCOPE, at(2), items("a"));
    await recordStoredVersion(storage, {
      scope: SCOPE,
      collectedAt: at(2),
      data: items("a"),
    });
    const ledger = (await ensureScopeLedger(storage, SCOPE))!;
    expect(ledger.baseline).toBe(at(2));
    expect(ledger.records["items:i:a"]).toEqual([at(2), at(5)]);
    expect(listAddedTimestamps(ledger)).toEqual([at(2), at(5)]);
  });

  it("added never exceeds total over random sequences of writes, binaries and deletes", async () => {
    let seed = 7;
    const random = () => (seed = (seed * 1664525 + 1013904223) >>> 0) / 2 ** 32;
    for (let run = 0; run < 25; run += 1) {
      const storage = createMemoryDataStorage();
      let slot = 0;
      for (let step = 0; step < 8; step += 1) {
        const roll = random();
        slot += 1;
        if (roll < 0.15) {
          await ingestBinaryDataContract({
            storage,
            scopeParam: SCOPE,
            bytes: new TextEncoder().encode("%PDF"),
            mimeType: "application/pdf",
            collectedAt: at(slot),
            status: "stored",
          });
        } else if (roll < 0.25 && storage.entries.length > 1) {
          const entry =
            storage.entries[Math.floor(random() * storage.entries.length)]!;
          await storage.deleteVersion(SCOPE, entry.collectedAt);
        } else {
          const count = 1 + Math.floor(random() * 6);
          await ingest(storage, items(...upTo(count)), at(slot));
        }
        const ledger = await ensureScopeLedger(storage, SCOPE);
        if (!ledger) continue;
        expect(listAddedTimestamps(ledger).length).toBeLessThanOrEqual(
          ledger.latest.total,
        );
      }
    }
  });
});
