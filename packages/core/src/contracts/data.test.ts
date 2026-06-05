import { describe, expect, it } from "vitest";
import type { DataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import type { DataStoragePort } from "../ports/index.js";
import type { IndexEntry } from "../storage/index/index.js";
import {
  deleteDataScopeContract,
  ingestDataContract,
  ingestBinaryDataContract,
  listDataScopesContract,
  listDataVersionsContract,
  readDataContract,
} from "./data.js";
import {
  decodeBinaryEnvelope,
  isBinaryEnvelope,
  parseMetadataHeader,
} from "./binary.js";

function createMemoryStorage(): DataStoragePort {
  const entries: IndexEntry[] = [];
  const envelopes = new Map<string, DataFileEnvelope>();
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
      schemaUrl: "https://schemas.example/instagram.profile.json",
      schemaId: "schema-1",
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

    expect(
      listDataScopesContract({
        storage,
        limit: 20,
        offset: 0,
      }),
    ).toMatchObject({
      ok: true,
      response: {
        scopes: [
          {
            scope: "instagram.profile",
            latestCollectedAt: "2026-05-08T00:00:00.000Z",
            versionCount: 1,
          },
        ],
        total: 1,
      },
    });

    expect(
      listDataVersionsContract({
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
            schemaId: "schema-1",
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
        $schema: "https://schemas.example/instagram.profile.json",
        schemaId: "schema-1",
        data: { username: "test_user" },
      },
    });

    await expect(
      deleteDataScopeContract({ storage, scopeParam: "instagram.profile" }),
    ).resolves.toEqual({ ok: true, deletedCount: 1 });
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
      schemaId: "schema-bin",
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
    expect(read.envelope.schemaId).toBe("schema-bin");

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
      listDataVersionsContract({
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
