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
    afterTombstoneVersion: null,
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
    expect(listAddedTimestamps(ledger!)).toEqual([at(2)]);

    // Rebuilding with the offending version inside the window ends the same
    // way, and repeated reads make no envelope reads.
    await storage.deleteFirstSeenLedger!(SCOPE);
    const rebuilt = await ensureScopeLedger(storage, SCOPE);
    expect(rebuilt?.skipped).toBeUndefined();
    expect(listAddedTimestamps(rebuilt!)).toEqual([at(2)]);
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
    await ingest({ items: [...batch("b").items, { id: "fresh" }] }, at(2));
    expect(listAddedTimestamps((await stored(storage))!)).toContain(at(2));
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
    expect(listAddedTimestamps((await stored(storage))!)).toHaveLength(2);

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
    expect(listAddedTimestamps(after)).toHaveLength(3);
  });

  it("a too_large marker reports no additions and total 0", async () => {
    const storage = createMemoryDataStorage();
    await put(storage, SCOPE, at(0), items("a"), 10_000);
    const marker = await ensureScopeLedger(storage, SCOPE, { byteBudget: 10 });
    expect(marker).toMatchObject({ skipped: "too_large" });
    expect(listAddedTimestamps(marker!)).toEqual([]);
  });
});
