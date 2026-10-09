import { describe, expect, it, vi } from "vitest";
import {
  createDataFileEnvelope,
  type DataFileEnvelope,
} from "@opendatalabs/vana-sdk/browser";
import type { DataStoragePort } from "../ports/index.js";
import type { IndexEntry } from "../storage/index/index.js";
import { readFirstAddedLedger } from "../additions/first-added.js";
import {
  deleteDataScopeContract,
  ingestDataContract,
  ingestBinaryDataContract,
  listDataScopesContract,
  listDataVersionsContract,
  readDataContract,
  summarizeDataAdditionsContract,
} from "./data.js";
import {
  decodeBinaryEnvelope,
  isBinaryEnvelope,
  parseMetadataHeader,
} from "./binary.js";

function createMemoryStorage(): DataStoragePort {
  const entries: IndexEntry[] = [];
  const envelopes = new Map<string, DataFileEnvelope>();
  const blockManifests = new Set<string>();
  let nextId = 1;

  function key(scope: string, collectedAt: string) {
    return `${scope}\n${collectedAt}`;
  }

  function entriesForScope(scope: string) {
    return entries
      .filter((entry) => entry.scope === scope)
      .sort((a, b) => b.collectedAt.localeCompare(a.collectedAt));
  }

  return {
    kind: "custom",
    listScopes({ scopePrefix, limit = 20, offset = 0 }) {
      const scopeMap = new Map<
        string,
        { scope: string; latestCollectedAt: string; versionCount: number }
      >();
      for (const entry of entries) {
        if (scopePrefix && !entry.scope.startsWith(scopePrefix)) continue;
        const existing = scopeMap.get(entry.scope);
        scopeMap.set(entry.scope, {
          scope: entry.scope,
          latestCollectedAt:
            existing &&
            existing.latestCollectedAt.localeCompare(entry.collectedAt) > 0
              ? existing.latestCollectedAt
              : entry.collectedAt,
          versionCount: (existing?.versionCount ?? 0) + 1,
        });
      }
      const scopes = Array.from(scopeMap.values());
      return {
        scopes: scopes.slice(offset, offset + limit),
        total: scopes.length,
      };
    },
    listVersions(scope, { limit = 20, offset = 0 }) {
      return entriesForScope(scope).slice(offset, offset + limit);
    },
    countVersions(scope) {
      return entriesForScope(scope).length;
    },
    findEntry({ scope, fileId, at }) {
      const scoped = entriesForScope(scope);
      if (fileId) return scoped.find((entry) => entry.fileId === fileId);
      if (at) return scoped.find((entry) => entry.collectedAt === at);
      return scoped[0];
    },
    async readEnvelope(scope, collectedAt) {
      const envelope = envelopes.get(key(scope, collectedAt));
      if (!envelope) throw new Error("missing envelope");
      return envelope;
    },
    async writeEnvelope(envelope) {
      envelopes.set(key(envelope.scope, envelope.collectedAt), envelope);
      const path = `${envelope.scope}/${envelope.collectedAt}.json`;
      return {
        path,
        relativePath: path,
        sizeBytes: JSON.stringify(envelope).length,
      };
    },
    hasScopeBlocks(scope, collectedAt) {
      return blockManifests.has(key(scope, collectedAt));
    },
    writeBlockManifest: vi.fn(async (scope: string, collectedAt: string) => {
      blockManifests.add(key(scope, collectedAt));
    }),
    insertEntry(entry) {
      const indexed = {
        ...entry,
        schemaId: entry.schemaId ?? null,
        id: nextId,
        createdAt: "2026-05-08T00:00:00.000Z",
      };
      nextId += 1;
      entries.push(indexed);
      return indexed;
    },
    async deleteScope(scope) {
      let deleted = 0;
      for (let index = entries.length - 1; index >= 0; index -= 1) {
        const entry = entries[index]!;
        if (entry.scope === scope) {
          entries.splice(index, 1);
          envelopes.delete(key(entry.scope, entry.collectedAt));
          deleted += 1;
        }
      }
      return deleted;
    },
  };
}

describe("data contract helpers", () => {
  it("ingests, lists, reads, and deletes data through a storage port", async () => {
    const storage = createMemoryStorage();

    const ingest = await ingestDataContract({
      storage,
      scopeParam: "instagram.profile",
      body: { username: "test_user" },
      collectedAt: "2026-05-08T00:00:00.000Z",
      status: "stored",
    });

    expect(ingest).toEqual({
      ok: true,
      scope: "instagram.profile",
      collectedAt: "2026-05-08T00:00:00.000Z",
      response: {
        scope: "instagram.profile",
        collectedAt: "2026-05-08T00:00:00.000Z",
        status: "stored",
      },
      writeResult: expect.objectContaining({
        relativePath: "instagram.profile/2026-05-08T00:00:00.000Z.json",
      }),
    });

    await expect(
      listDataScopesContract({
        storage,
        limit: 20,
        offset: 0,
      }),
    ).resolves.toMatchObject({
      ok: true,
      response: {
        scopes: [
          {
            dataStatus: "ready",
            sizeBytes: expect.any(Number),
            scope: "instagram.profile",
            latestCollectedAt: "2026-05-08T00:00:00.000Z",
            versionCount: 1,
          },
        ],
        total: 1,
      },
    });

    expect(
      await listDataVersionsContract({
        storage,
        scopeParam: "instagram.profile",
        limit: 20,
        offset: 0,
      }),
    ).toMatchObject({
      ok: true,
      response: {
        versions: [
          {
            collectedAt: "2026-05-08T00:00:00.000Z",
            schemaId: null,
          },
        ],
      },
    });

    await expect(
      readDataContract({
        storage,
        scopeParam: "instagram.profile",
      }),
    ).resolves.toMatchObject({
      ok: true,
      envelope: {
        data: { username: "test_user" },
      },
    });

    await expect(
      deleteDataScopeContract({ storage, scopeParam: "instagram.profile" }),
    ).resolves.toEqual({ ok: true, deletedCount: 1 });
  });

  it("writes bounded block sidecars when supported and continues on sidecar failure", async () => {
    const storage = createMemoryStorage();
    const writeBlockManifest = storage.writeBlockManifest as ReturnType<
      typeof vi.fn
    >;
    writeBlockManifest.mockRejectedValueOnce(new Error("sidecar write failed"));

    const ingest = await ingestDataContract({
      storage,
      scopeParam: "instagram.profile",
      body: { username: "test_user" },
      collectedAt: "2026-05-08T00:00:00.000Z",
      status: "stored",
    });

    expect(ingest).toMatchObject({ ok: true });
    expect(writeBlockManifest).toHaveBeenCalledWith(
      "instagram.profile",
      "2026-05-08T00:00:00.000Z",
      expect.objectContaining({
        scope: "instagram.profile",
        collectedAt: "2026-05-08T00:00:00.000Z",
      }),
      expect.any(Array),
    );
    expect(
      storage.findEntry({
        scope: "instagram.profile",
        at: "2026-05-08T00:00:00.000Z",
      }),
    ).toBeDefined();
    await expect(
      listDataScopesContract({
        storage,
        limit: 20,
        offset: 0,
      }),
    ).resolves.toMatchObject({
      response: {
        scopes: [
          {
            scope: "instagram.profile",
            dataStatus: "indexing",
            sizeBytes: expect.any(Number),
          },
        ],
      },
    });
  });

  it("returns compatibility-shaped validation errors", async () => {
    const storage = createMemoryStorage();

    expect(
      await ingestDataContract({
        storage,
        scopeParam: "bad scope",
        body: { username: "test_user" },
        collectedAt: "2026-05-08T00:00:00.000Z",
        status: "stored",
      }),
    ).toMatchObject({
      ok: false,
      status: 400,
      body: { error: "INVALID_SCOPE" },
    });

    expect(
      await ingestDataContract({
        storage,
        scopeParam: "instagram.profile",
        body: null,
        collectedAt: "2026-05-08T00:00:00.000Z",
        status: "stored",
      }),
    ).toEqual({
      ok: false,
      status: 400,
      body: {
        error: "INVALID_BODY",
        message: "Request body must be a JSON object",
      },
    });
  });

  it("ingests binary data and round-trips the bytes through read", async () => {
    const storage = createMemoryStorage();
    const bytes = new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2d, 0x31]); // %PDF-1

    const ingest = await ingestBinaryDataContract({
      storage,
      scopeParam: "documents.pdf",
      bytes,
      mimeType: "application/pdf",
      filename: "report.pdf",
      collectedAt: "2026-05-08T00:00:00.000Z",
      status: "syncing",
    });

    expect(ingest).toMatchObject({
      ok: true,
      scope: "documents.pdf",
      response: { status: "syncing" },
    });

    const read = await readDataContract({
      storage,
      scopeParam: "documents.pdf",
    });
    expect(read.ok).toBe(true);
    if (!read.ok) return;

    expect(isBinaryEnvelope(read.envelope)).toBe(true);
    expect(read.envelope.schemaId).toBeUndefined();

    const decoded = decodeBinaryEnvelope(read.envelope);
    expect(decoded.mimeType).toBe("application/pdf");
    expect(decoded.filename).toBe("report.pdf");
    expect(Array.from(decoded.bytes)).toEqual(Array.from(bytes));
  });

  it("stores free-form metadata in the binary envelope and reads it back", async () => {
    const storage = createMemoryStorage();
    const metadata = { description: "Q2 invoice", tags: ["finance"] };

    await ingestBinaryDataContract({
      storage,
      scopeParam: "documents.pdf",
      bytes: new Uint8Array([1, 2, 3]),
      mimeType: "application/pdf",
      metadata,
      collectedAt: "2026-05-08T00:00:00.000Z",
      status: "stored",
    });

    const read = await readDataContract({
      storage,
      scopeParam: "documents.pdf",
    });
    if (!read.ok) throw new Error("expected ok");

    // Lives inside `data`, so it survives the SDK envelope schema.
    expect((read.envelope.data as Record<string, unknown>).metadata).toEqual(
      metadata,
    );
    expect(decodeBinaryEnvelope(read.envelope).metadata).toEqual(metadata);
  });

  it("omits the metadata key when none is provided", async () => {
    const storage = createMemoryStorage();
    await ingestBinaryDataContract({
      storage,
      scopeParam: "documents.pdf",
      bytes: new Uint8Array([1]),
      mimeType: "application/pdf",
      collectedAt: "2026-05-08T00:00:00.000Z",
      status: "stored",
    });
    const read = await readDataContract({
      storage,
      scopeParam: "documents.pdf",
    });
    if (!read.ok) throw new Error("expected ok");
    expect("metadata" in (read.envelope.data as Record<string, unknown>)).toBe(
      false,
    );
  });

  it("parses metadata header as JSON when possible, else as a string", () => {
    expect(parseMetadataHeader('{"a":1}')).toEqual({ a: 1 });
    expect(parseMetadataHeader("just a description")).toBe(
      "just a description",
    );
    expect(parseMetadataHeader("")).toBeUndefined();
    expect(parseMetadataHeader(null)).toBeUndefined();
  });

  it("rejects an empty binary body", async () => {
    const storage = createMemoryStorage();
    expect(
      await ingestBinaryDataContract({
        storage,
        scopeParam: "documents.pdf",
        bytes: new Uint8Array(),
        mimeType: "application/pdf",
        collectedAt: "2026-05-08T00:00:00.000Z",
        status: "stored",
      }),
    ).toMatchObject({
      ok: false,
      status: 400,
      body: { error: "INVALID_BODY" },
    });
  });

  it("ingests binary data without a schemaId (schema-less scope)", async () => {
    const storage = createMemoryStorage();
    const ingest = await ingestBinaryDataContract({
      storage,
      scopeParam: "documents.pdf",
      bytes: new Uint8Array([1, 2, 3]),
      mimeType: "application/octet-stream",
      collectedAt: "2026-05-08T00:00:00.000Z",
      status: "stored",
    });
    expect(ingest).toMatchObject({ ok: true });

    expect(
      await listDataVersionsContract({
        storage,
        scopeParam: "documents.pdf",
        limit: 20,
        offset: 0,
      }),
    ).toMatchObject({
      ok: true,
      response: { versions: [{ schemaId: null }] },
    });
  });
});

describe("lineage on ingest", () => {
  const SOURCE_ID = `0x${"ab".repeat(32)}` as const;
  const lineage = {
    sources: [SOURCE_ID],
    writtenAt: "2026-08-31T09:12:44.000Z",
  };

  it("stamps $lineage into a JSON record and echoes the sources", async () => {
    const storage = createMemoryStorage();
    const result = await ingestDataContract({
      storage,
      scopeParam: "spine.health.summary",
      body: { summary: "x", lineage: [SOURCE_ID] },
      collectedAt: "2026-08-31T09:12:44Z",
      status: "stored",
      lineage,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.response.lineage).toEqual({ sources: [SOURCE_ID] });
    const read = await readDataContract({
      storage,
      scopeParam: "spine.health.summary",
    });
    expect(read.ok && read.envelope.data).toEqual({
      summary: "x",
      lineage: [SOURCE_ID],
      $lineage: lineage,
      $firstAdded: expect.objectContaining({ version: 1 }),
    });
  });

  it("stamps $lineage at the top of a binary record, next to $binary", async () => {
    const storage = createMemoryStorage();
    const result = await ingestBinaryDataContract({
      storage,
      scopeParam: "spine.health.report",
      bytes: new TextEncoder().encode("%PDF"),
      mimeType: "application/pdf",
      metadata: { lineage: [SOURCE_ID] },
      collectedAt: "2026-08-31T09:12:44Z",
      status: "stored",
      lineage,
    });
    expect(result.ok).toBe(true);
    const read = await readDataContract({
      storage,
      scopeParam: "spine.health.report",
    });
    expect(read.ok && read.envelope.data.$lineage).toEqual(lineage);
    expect(read.ok && read.envelope.data.metadata).toEqual({
      lineage: [SOURCE_ID],
    });
  });

  it("rejects a body that carries the reserved $lineage key", async () => {
    const result = await ingestDataContract({
      storage: createMemoryStorage(),
      scopeParam: "spine.health.summary",
      body: { summary: "x", $lineage: lineage },
      collectedAt: "2026-08-31T09:12:44Z",
      status: "stored",
    });
    expect(result).toMatchObject({
      ok: false,
      status: 400,
      body: { error: "INVALID_BODY" },
    });
  });

  it("rejects binary metadata carrying a reserved server key", async () => {
    for (const metadata of [
      { $lineage: lineage },
      { $writtenBy: { builder: "0x1" } },
    ]) {
      const result = await ingestBinaryDataContract({
        storage: createMemoryStorage(),
        scopeParam: "spine.health.report",
        bytes: new TextEncoder().encode("%PDF"),
        mimeType: "application/pdf",
        metadata,
        collectedAt: "2026-08-31T09:12:44Z",
        status: "stored",
      });
      expect(result).toMatchObject({
        ok: false,
        status: 400,
        body: { error: "INVALID_BODY" },
      });
    }
  });

  it("leaves a root record byte-identical (no lineage key)", async () => {
    const storage = createMemoryStorage();
    await ingestDataContract({
      storage,
      scopeParam: "notes.entries",
      body: { note: "x" },
      collectedAt: "2026-08-31T09:12:44Z",
      status: "stored",
    });
    const read = await readDataContract({
      storage,
      scopeParam: "notes.entries",
    });
    expect(read.ok && read.envelope.data).toEqual({
      note: "x",
      $firstAdded: expect.objectContaining({ version: 1 }),
    });
  });
});

describe("first-added ledger on ingest", () => {
  const SCOPE = "notes.entries";
  const T1 = "2026-01-01T00:00:00.000Z";
  const T2 = "2026-02-01T00:00:00.000Z";
  const T3 = "2026-03-01T00:00:00.000Z";

  type IngestExtra = Pick<
    Parameters<typeof ingestDataContract>[0],
    "attribution" | "lineage"
  >;

  function ingest(
    storage: DataStoragePort,
    body: Record<string, unknown>,
    collectedAt: string,
    extra: IngestExtra = {},
  ) {
    return ingestDataContract({
      storage,
      scopeParam: SCOPE,
      body,
      collectedAt,
      status: "stored",
      ...extra,
    });
  }

  async function latestData(storage: DataStoragePort) {
    const read = await readDataContract({ storage, scopeParam: SCOPE });
    if (!read.ok) throw new Error("expected read to succeed");
    return read.envelope.data;
  }

  function ledgerOf(data: Record<string, unknown>) {
    const ledger = readFirstAddedLedger(data);
    if (!ledger) throw new Error("expected a first-added ledger");
    return ledger;
  }

  it("dates every record of the first ingest with that write's collectedAt", async () => {
    const storage = createMemoryStorage();
    await ingest(storage, { items: [{ id: "a" }, { id: "b" }] }, T1);

    const ledger = ledgerOf(await latestData(storage));
    expect(ledger.trackedSince).toBe(T1);
    expect(ledger.records).toEqual({
      "items:i:a": T1,
      "items:i:b": T1,
    });
  });

  it("carries records forward unchanged when a later ingest adds nothing", async () => {
    const storage = createMemoryStorage();
    const body = { items: [{ id: "a" }, { id: "b" }] };
    await ingest(storage, body, T1);
    await ingest(storage, body, T2);

    const ledger = ledgerOf(await latestData(storage));
    expect(ledger.trackedSince).toBe(T1);
    expect(ledger.records).toEqual({
      "items:i:a": T1,
      "items:i:b": T1,
    });
  });

  it("dates only the record a later ingest adds", async () => {
    const storage = createMemoryStorage();
    await ingest(storage, { items: [{ id: "a" }, { id: "b" }] }, T1);
    await ingest(
      storage,
      { items: [{ id: "a" }, { id: "b" }, { id: "c" }] },
      T2,
    );

    expect(ledgerOf(await latestData(storage)).records).toEqual({
      "items:i:a": T1,
      "items:i:b": T1,
      "items:i:c": T2,
    });
  });

  it("keeps a record's original timestamp when it returns after a gap", async () => {
    const storage = createMemoryStorage();
    await ingest(storage, { items: [{ id: "a" }, { id: "b" }] }, T1);
    await ingest(storage, { items: [{ id: "a" }] }, T2);
    await ingest(storage, { items: [{ id: "a" }, { id: "b" }] }, T3);

    expect(ledgerOf(await latestData(storage)).records).toEqual({
      "items:i:a": T1,
      "items:i:b": T1,
    });
  });

  it("treats a pre-tracking snapshot's records as already existing", async () => {
    const storage = createMemoryStorage();
    const envelope = createDataFileEnvelope(SCOPE, T1, {
      items: [{ id: "a" }],
    });
    await storage.writeEnvelope(envelope);
    await storage.insertEntry({
      fileId: null,
      schemaId: null,
      path: `${SCOPE}/${T1}.json`,
      scope: SCOPE,
      collectedAt: T1,
      sizeBytes: JSON.stringify(envelope).length,
      afterTombstoneVersion: null,
    });

    await ingest(storage, { items: [{ id: "a" }, { id: "b" }] }, T2);
    const ledger = ledgerOf(await latestData(storage));
    expect(ledger.trackedSince).toBe(T2);
    expect(ledger.records).toEqual({
      "items:i:a": null,
      "items:i:b": T2,
    });
  });

  it("rejects a body that carries the reserved $firstAdded key", async () => {
    const storage = createMemoryStorage();
    const result = await ingest(
      storage,
      { items: [{ id: "a" }], $firstAdded: { version: 1 } },
      T1,
    );
    expect(result).toEqual({
      ok: false,
      status: 400,
      body: {
        error: "INVALID_BODY",
        message: "Request body must not contain the reserved $firstAdded key",
      },
    });
    expect(storage.listVersions(SCOPE, {})).toEqual([]);
  });

  it("still ingests when the previous envelope cannot be read", async () => {
    const storage = createMemoryStorage();
    await ingest(storage, { items: [{ id: "a" }] }, T1);
    vi.spyOn(storage, "readEnvelope").mockRejectedValueOnce(new Error("boom"));

    const result = await ingest(storage, { items: [{ id: "a" }] }, T2);
    expect(result.ok).toBe(true);

    const data = await latestData(storage);
    expect("$firstAdded" in data).toBe(false);
  });

  it("stamps the ledger alongside $writtenBy and $lineage", async () => {
    const storage = createMemoryStorage();
    const source = `0x${"ab".repeat(32)}` as const;
    const lineage = {
      sources: [source],
      writtenAt: "2026-01-01T00:00:00.000Z",
    };
    const attribution = {
      builder: `0x${"11".repeat(20)}` as `0x${string}`,
      grantId: "grant-1",
      signature: "0xdeadbeef",
      bodyHash: "0xabc",
      writtenAt: "2026-01-01T00:00:00.000Z",
    };

    await ingest(storage, { items: [{ id: "a" }], lineage: [source] }, T1, {
      attribution,
      lineage,
    });

    const data = await latestData(storage);
    expect(data.$writtenBy).toEqual(attribution);
    expect(data.$lineage).toEqual(lineage);
    expect(ledgerOf(data).records).toMatchObject({ "items:i:a": T1 });
  });

  it("does not re-date a note whose text was edited between ingests", async () => {
    const storage = createMemoryStorage();
    const scope = "icloud_notes.notes";
    const body = (textContent: string) => ({
      notes: [{ recordName: "n1", title: "Title", textContent }],
    });
    await ingestDataContract({
      storage,
      scopeParam: scope,
      body: body("first"),
      collectedAt: T1,
      status: "stored",
    });
    await ingestDataContract({
      storage,
      scopeParam: scope,
      body: body("edited"),
      collectedAt: T2,
      status: "stored",
    });

    const read = await readDataContract({ storage, scopeParam: scope });
    if (!read.ok) throw new Error("expected read to succeed");
    const ledger = readFirstAddedLedger(read.envelope.data);
    expect(ledger?.records).toEqual({ "notes:i:n1": T1 });
  });
});

describe("summarize additions contract", () => {
  const SCOPE = "notes.entries";
  const FIRST = "2026-10-01T12:00:00.000Z";
  const SECOND = "2026-10-08T12:00:00.000Z";

  async function ingestTwoVersions(storage: DataStoragePort) {
    await ingestDataContract({
      storage,
      scopeParam: SCOPE,
      body: { items: [{ id: "a" }, { id: "b" }] },
      collectedAt: FIRST,
      status: "stored",
    });
    await ingestDataContract({
      storage,
      scopeParam: SCOPE,
      body: { items: [{ id: "a" }, { id: "b" }, { id: "c" }] },
      collectedAt: SECOND,
      status: "stored",
    });
  }

  it("summarizes real ingested snapshots from their stamped ledgers", async () => {
    const storage = createMemoryStorage();
    await ingestTwoVersions(storage);

    const result = await summarizeDataAdditionsContract({
      storage,
      timezone: "UTC",
      days: 7,
      now: new Date("2026-10-08T12:00:05.000Z"),
    });

    if ("ok" in result) throw new Error("expected a summary");
    expect(result.total).toBe(3);
    expect(result.trackedSince).toBe(FIRST);
    expect(result.scopes).toEqual([
      { scope: SCOPE, total: 3, trackedSince: FIRST },
    ]);
    // `c` was first added by the second write, whose UTC day is 2026-10-08.
    expect(result.days.at(-1)).toEqual({ date: "2026-10-08", added: 1 });
    // `a` and `b` date to 2026-10-01, outside the 7-day day list.
    expect(result.days[0]).toEqual({ date: "2026-10-02", added: 0 });
  });

  it("rejects an out-of-range days or an unknown timezone", async () => {
    for (const days of [0, 32]) {
      const result = await summarizeDataAdditionsContract({
        storage: createMemoryStorage(),
        timezone: "UTC",
        days,
        now: new Date(SECOND),
      });
      expect(result).toMatchObject({
        ok: false,
        status: 400,
        body: { error: "INVALID_QUERY" },
      });
    }

    const badTimezone = await summarizeDataAdditionsContract({
      storage: createMemoryStorage(),
      timezone: "Not/AZone",
      days: 7,
      now: new Date(SECOND),
    });
    expect(badTimezone).toEqual({
      ok: false,
      status: 400,
      body: { error: "INVALID_QUERY", message: "Unknown timezone" },
    });
  });

  it("excludes scopes the visibility filter hides", async () => {
    const storage = createMemoryStorage();
    await ingestTwoVersions(storage);

    const result = await summarizeDataAdditionsContract({
      storage,
      isVisible: () => false,
      timezone: "UTC",
      days: 7,
      now: new Date("2026-10-08T12:00:05.000Z"),
    });

    if ("ok" in result) throw new Error("expected a summary");
    expect(result.total).toBe(0);
    expect(result.scopes).toEqual([]);
  });
});
