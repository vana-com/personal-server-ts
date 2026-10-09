import { describe, expect, it, vi } from "vitest";
import { createDataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import {
  readScopeFirstSeenLedger,
  type ScopeFirstSeenLedger,
} from "../additions/first-added.js";
import { recordStoredVersion } from "../additions/ledger-store.js";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";
import type { DataStoragePort } from "../ports/index.js";
import {
  deleteDataScopeContract,
  ingestBinaryDataContract,
  ingestDataContract,
  listDataScopesContract,
  listDataVersionsContract,
  readDataContract,
  summarizeDataAdditionsContract,
} from "./data.js";

const SCOPE = "notes.entries";
const T1 = "2026-10-01T12:00:00.000Z";
const T2 = "2026-10-08T12:00:00.000Z";
const T3 = "2026-10-09T08:00:00.000Z";
const NOW = new Date("2026-10-09T12:00:00.000Z");

const items = (...ids: string[]) => ({ items: ids.map((id) => ({ id })) });

function ingest(
  storage: DataStoragePort,
  body: Record<string, unknown>,
  collectedAt: string,
  scope = SCOPE,
) {
  return ingestDataContract({
    storage,
    scopeParam: scope,
    body,
    collectedAt,
    status: "stored",
  });
}

function ingestBinary(storage: DataStoragePort, collectedAt: string) {
  return ingestBinaryDataContract({
    storage,
    scopeParam: SCOPE,
    bytes: new TextEncoder().encode("%PDF-1.7 fake"),
    mimeType: "application/pdf",
    collectedAt,
    status: "stored",
  });
}

async function ledgerOf(storage: DataStoragePort, scope = SCOPE) {
  const ledger = readScopeFirstSeenLedger(
    await storage.readFirstSeenLedger!(scope),
  );
  if (!ledger) throw new Error("expected a sidecar");
  return ledger;
}

async function summarize(
  storage: DataStoragePort,
  extra: Partial<Parameters<typeof summarizeDataAdditionsContract>[0]> = {},
) {
  const result = await summarizeDataAdditionsContract({
    storage,
    timezone: "UTC",
    days: 7,
    now: NOW,
    ...extra,
  });
  if ("ok" in result)
    throw new Error(`expected a summary: ${result.body.message}`);
  return result;
}

describe("first-seen sidecar on ingest", () => {
  it("dates only the record a later ingest adds", async () => {
    const storage = createMemoryDataStorage();
    await ingest(storage, items("a", "b"), T1);
    await ingest(storage, items("a", "b", "c"), T2);

    const ledger = await ledgerOf(storage);
    expect(ledger.baseline).toBe(T1);
    expect(ledger.records["items:i:a"]).toEqual([T1, T2]);
    expect(ledger.records["items:i:c"]).toEqual([T2, T2]);

    const summary = await summarize(storage);
    expect(summary.total).toBe(3);
    expect(summary.trackedSince).toBe(T1);
    expect(summary.days.at(-1)).toEqual({ date: "2026-10-09", added: 0 });
    expect(summary.days.find((d) => d.date === "2026-10-08")?.added).toBe(1);
    expect(summary.days.reduce((sum, day) => sum + day.added, 0)).toBe(1);
  });

  it("stores the envelope exactly as it would be stored without a sidecar", async () => {
    const storage = createMemoryDataStorage();
    const body = { items: [{ id: "a" }], note: "hello" };
    await ingest(storage, body, T1);
    const read = await readDataContract({ storage, scopeParam: SCOPE });
    if (!read.ok) throw new Error("expected a read");
    expect(JSON.stringify(read.envelope)).toBe(
      JSON.stringify(createDataFileEnvelope(SCOPE, T1, body)),
    );
    expect(JSON.stringify(read.envelope)).not.toContain("first");
  });

  it("does not read the previous envelope on ingest", async () => {
    const storage = createMemoryDataStorage();
    await ingest(storage, items("a"), T1);
    const readEnvelope = vi.spyOn(storage, "readEnvelope");
    await ingest(storage, items("a", "b"), T2);
    expect(readEnvelope).not.toHaveBeenCalled();
  });

  it("keeps history across a binary write (finding 4)", async () => {
    const storage = createMemoryDataStorage();
    await ingest(storage, items("a", "b"), T1);
    await ingestBinary(storage, T2);
    expect((await ledgerOf(storage)).latest).toEqual({
      collectedAt: T2,
      total: 0,
    });
    await ingest(storage, items("a", "b", "c"), T3);

    const ledger = await ledgerOf(storage);
    expect(ledger.baseline).toBe(T1);
    expect(ledger.records["items:i:a"]![0]).toBe(T1);
    expect(ledger.records["items:i:c"]).toEqual([T3, T3]);
    const summary = await summarize(storage);
    expect(summary.days.at(-1)).toEqual({ date: "2026-10-09", added: 1 });
  });

  it("keeps history when the sidecar read fails or the sidecar is corrupt", async () => {
    const storage = createMemoryDataStorage();
    await ingest(storage, items("a"), T1);
    vi.spyOn(storage, "readFirstSeenLedger").mockRejectedValueOnce(
      new Error("boom"),
    );
    await ingest(storage, items("a", "b"), T2);
    // The corrupt/unreadable sidecar was rebuilt from the retained versions.
    const ledger = await ledgerOf(storage);
    expect(ledger.baseline).toBe(T1);
    expect(ledger.records["items:i:b"]).toEqual([T2, T2]);

    await storage.writeFirstSeenLedger!(SCOPE, { version: 2, junk: true });
    await ingest(storage, items("a", "b", "c"), T3);
    expect((await ledgerOf(storage)).records["items:i:a"]).toEqual([T1, T3]);
  });

  it("still succeeds when writing the sidecar fails", async () => {
    const storage = createMemoryDataStorage();
    vi.spyOn(storage, "writeFirstSeenLedger").mockRejectedValue(
      new Error("disk full"),
    );
    const result = await ingest(storage, items("a"), T1);
    expect(result.ok).toBe(true);
    expect(storage.listVersions(SCOPE, {})).toHaveLength(1);
  });

  it("keeps working on a storage without sidecar support", async () => {
    const storage = createMemoryDataStorage();
    delete (storage as Partial<DataStoragePort>).readFirstSeenLedger;
    delete (storage as Partial<DataStoragePort>).writeFirstSeenLedger;
    expect((await ingest(storage, items("a"), T1)).ok).toBe(true);
    const summary = await summarize(storage);
    expect(summary.total).toBe(1);
  });

  it("folds concurrent ingests of one scope without losing either", async () => {
    const storage = createMemoryDataStorage();
    const read = storage.readFirstSeenLedger!.bind(storage);
    storage.readFirstSeenLedger = async (scope) => {
      const value = await read(scope);
      await new Promise((resolve) => setTimeout(resolve, 5));
      return value;
    };
    await Promise.all([
      ingest(storage, items("a"), T1),
      ingest(storage, items("a", "b"), T2),
      ingest(storage, items("a", "b", "c"), T3),
    ]);
    const ledger = await ledgerOf(storage);
    expect(Object.keys(ledger.records).sort()).toEqual([
      "items:i:a",
      "items:i:b",
      "items:i:c",
    ]);
    expect(ledger.baseline).toBe(T1);
    expect(ledger.latest.collectedAt).toBe(T3);
  });

  it("repairs a lost newer fold on the next update", async () => {
    const storage = createMemoryDataStorage();
    await ingest(storage, items("a"), T1);
    const lagging = await ledgerOf(storage);
    await ingest(storage, items("a", "b"), T2);
    // Another process overwrote the sidecar with a view that missed T2.
    await storage.writeFirstSeenLedger!(SCOPE, lagging);

    await ingest(storage, items("a", "b", "c"), T3);
    expect((await ledgerOf(storage)).records["items:i:b"]).toEqual([T2, T3]);
  });

  it("repairs a lagging sidecar when /additions reads it", async () => {
    const storage = createMemoryDataStorage();
    await ingest(storage, items("a"), T1);
    const lagging = await ledgerOf(storage);
    await ingest(storage, items("a", "b"), T2);
    await storage.writeFirstSeenLedger!(SCOPE, lagging);

    const summary = await summarize(storage);
    expect(summary.total).toBe(2);
    expect((await ledgerOf(storage)).latest.collectedAt).toBe(T2);
  });
});

describe("first-seen sidecar backfill", () => {
  async function storeWithoutSidecar(
    storage: DataStoragePort,
    scope: string,
    collectedAt: string,
    data: Record<string, unknown>,
  ) {
    const envelope = createDataFileEnvelope(scope, collectedAt, data);
    const written = await storage.writeEnvelope(envelope);
    await storage.insertEntry({
      fileId: null,
      schemaId: null,
      path: written.relativePath,
      scope,
      collectedAt,
      sizeBytes: written.sizeBytes,
      afterTombstoneVersion: null,
    });
  }

  it("rebuilds a scope that has versions but no sidecar, with real dates", async () => {
    const storage = createMemoryDataStorage();
    await storeWithoutSidecar(storage, SCOPE, T1, items("a", "b"));
    await storeWithoutSidecar(storage, SCOPE, T2, items("a", "b", "c"));
    expect(await storage.readFirstSeenLedger!(SCOPE)).toBeNull();

    const summary = await summarize(storage);
    expect(summary.trackedSince).toBe(T1);
    expect(summary.total).toBe(3);
    expect(summary.days.find((d) => d.date === "2026-10-08")?.added).toBe(1);

    const ledger = await ledgerOf(storage);
    expect(ledger.records["items:i:c"]).toEqual([T2, T2]);
    expect(ledger.records["items:i:a"]).toEqual([T1, T2]);
  });

  it("backfills on the first ingest after an upgrade and folds the new version from memory", async () => {
    const storage = createMemoryDataStorage();
    await storeWithoutSidecar(storage, SCOPE, T1, items("a"));
    await ingest(storage, items("a", "b"), T2);
    const ledger = await ledgerOf(storage);
    expect(ledger.baseline).toBe(T1);
    expect(ledger.records["items:i:b"]).toEqual([T2, T2]);
  });

  it("two devices holding the same versions compute the same ledger", async () => {
    const one = createMemoryDataStorage();
    const two = createMemoryDataStorage();
    for (const storage of [one, two]) {
      await storeWithoutSidecar(storage, SCOPE, T1, items("a"));
      await storeWithoutSidecar(storage, SCOPE, T2, items("a", "b"));
    }
    await summarize(one);
    // The other device receives them in the opposite order via sync.
    await recordStoredVersion(two, {
      scope: SCOPE,
      collectedAt: T2,
      data: items("a", "b"),
    });
    expect(await ledgerOf(two)).toEqual(await ledgerOf(one));
  });

  it("skips a version that cannot be read instead of wiping history", async () => {
    const storage = createMemoryDataStorage();
    await storeWithoutSidecar(storage, SCOPE, T1, items("a"));
    await storeWithoutSidecar(storage, SCOPE, T2, items("a", "b"));
    const readEnvelope = storage.readEnvelope.bind(storage);
    vi.spyOn(storage, "readEnvelope").mockImplementation(
      async (scope, collectedAt) => {
        if (collectedAt === T2) throw new Error("gone");
        return readEnvelope(scope, collectedAt);
      },
    );
    const summary = await summarize(storage);
    expect(summary.total).toBe(1);
    expect(summary.trackedSince).toBe(T1);
  });
});

describe("first-seen sidecar deletion", () => {
  it("removes the sidecar with the scope and a reimport starts a fresh baseline", async () => {
    const storage = createMemoryDataStorage();
    await ingest(storage, items("a"), T1);
    await ingest(storage, items("a", "b"), T2);
    expect(await storage.readFirstSeenLedger!(SCOPE)).not.toBeNull();

    await deleteDataScopeContract({ storage, scopeParam: SCOPE });
    expect(await storage.readFirstSeenLedger!(SCOPE)).toBeNull();

    await ingest(storage, items("a", "b", "z"), T3);
    const ledger = await ledgerOf(storage);
    expect(ledger.baseline).toBe(T3);
    const summary = await summarize(storage);
    expect(summary.total).toBe(3);
    expect(summary.days.reduce((sum, day) => sum + day.added, 0)).toBe(0);
  });

  it("removes the sidecar even when the storage's deleteScope predates it", async () => {
    const storage = createMemoryDataStorage();
    await ingest(storage, items("a"), T1);
    const planted = await ledgerOf(storage);
    const deleteScope = storage.deleteScope.bind(storage);
    storage.deleteScope = async (scope) => {
      const count = await deleteScope(scope);
      // A port whose deleteScope knows nothing of the sidecar leaves it behind.
      await storage.writeFirstSeenLedger!(scope, planted);
      return count;
    };
    await deleteDataScopeContract({ storage, scopeParam: SCOPE });
    expect(await storage.readFirstSeenLedger!(SCOPE)).toBeNull();
  });
});

describe("first-seen sidecar is not data", () => {
  it("is never a version, a scope, or part of any listing", async () => {
    const storage = createMemoryDataStorage();
    await ingest(storage, items("a"), T1);
    expect(storage.entries).toHaveLength(1);
    expect(storage.findUnsynced()).toHaveLength(1);
    const versions = await listDataVersionsContract({
      storage,
      scopeParam: SCOPE,
    });
    expect(JSON.stringify(versions)).not.toContain("baseline");
    const scopes = await listDataScopesContract({ storage });
    expect(JSON.stringify(scopes)).not.toContain("records");
    expect(scopes.response.scopes.map((s) => s.scope)).toEqual([SCOPE]);
  });
});

describe("summarizeDataAdditionsContract", () => {
  it("validates days and the timezone before touching storage", async () => {
    const storage = createMemoryDataStorage();
    const touched = vi.fn();
    for (const method of [
      "listScopes",
      "listVersions",
      "findEntry",
      "readEnvelope",
      "readFirstSeenLedger",
    ] as const) {
      (storage as unknown as Record<string, unknown>)[method] = touched;
    }
    for (const days of [0, 32, Number.NaN, 1.5]) {
      expect(
        await summarizeDataAdditionsContract({
          storage,
          timezone: "UTC",
          days,
          now: NOW,
        }),
      ).toMatchObject({
        ok: false,
        status: 400,
        body: { error: "INVALID_QUERY" },
      });
    }
    expect(
      await summarizeDataAdditionsContract({
        storage,
        timezone: "Not/AZone",
        days: 7,
        now: NOW,
      }),
    ).toEqual({
      ok: false,
      status: 400,
      body: { error: "INVALID_QUERY", message: "Unknown timezone" },
    });
    expect(touched).not.toHaveBeenCalled();
  });

  it("counts a record on the local day of its first sight in each timezone", async () => {
    const storage = createMemoryDataStorage();
    await ingest(storage, items("a"), T1);
    // 03:30 UTC on 10-09 is still the evening of 10-08 in Toronto (EDT).
    await ingest(storage, items("a", "b"), "2026-10-09T03:30:00.000Z");

    const utc = await summarize(storage);
    const toronto = await summarize(storage, { timezone: "America/Toronto" });
    expect(utc.days.find((d) => d.date === "2026-10-09")?.added).toBe(1);
    expect(utc.days.find((d) => d.date === "2026-10-08")?.added).toBe(0);
    expect(toronto.days.find((d) => d.date === "2026-10-08")?.added).toBe(1);
    expect(toronto.days.find((d) => d.date === "2026-10-09")?.added).toBe(0);
  });

  it("excludes scopes the visibility filter hides", async () => {
    const storage = createMemoryDataStorage();
    await ingest(storage, items("a"), T1);
    const summary = await summarize(storage, { isVisible: () => false });
    expect(summary.total).toBe(0);
    expect(summary.scopes).toEqual([]);
    expect(summary.trackedSince).toBeNull();
  });

  it("does not parse stored envelopes when the sidecar is current", async () => {
    const storage = createMemoryDataStorage();
    await ingest(storage, items("a"), T1);
    await ingest(storage, items("a", "b"), T2);
    const readEnvelope = vi.spyOn(storage, "readEnvelope");
    await summarize(storage);
    expect(readEnvelope).not.toHaveBeenCalled();
  });
});

describe("sidecar shape", () => {
  it("is a version-2 document keyed by the scope", async () => {
    const storage = createMemoryDataStorage();
    await ingest(storage, items("a"), T1);
    const ledger: ScopeFirstSeenLedger = await ledgerOf(storage);
    expect(ledger).toEqual({
      version: 2,
      scope: SCOPE,
      baseline: T1,
      latest: { collectedAt: T1, total: 1 },
      records: { "items:i:a": [T1, T1] },
    });
  });
});
