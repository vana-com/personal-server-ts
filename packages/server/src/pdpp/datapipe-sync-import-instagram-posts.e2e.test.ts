/**
 * Companion to `datapipe-sync-import.e2e.test.ts`, for the `instagram.posts`
 * bounded snapshot stream (whole-object, keyed by the reserved constant
 * `pdpp_snapshot`, not a per-record id).
 *
 * The declaration and envelope-data fixtures below are captured verbatim
 * from unity-surfaces (worktree unity-datapipe-pdpp-0917, commit d85cfc50)
 * via its own `PDPP_DECLARATIONS`/`buildPdppIngestEnvelope`/
 * `buildPdppSyncAnnotatedData`, not hand-authored.
 */

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import Database from "better-sqlite3";
import { pino } from "pino";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  deriveScopeKey,
  encryptWithPassword,
  type DataFileEnvelope,
  type DataPointRecord,
} from "@opendatalabs/vana-sdk/browser";
import {
  createPdppImporter,
  downloadOne,
  type PdppImporter,
} from "@opendatalabs/personal-server-ts-core/sync";
import { parseDeclaration } from "@opendatalabs/personal-server-ts-core/pdpp";
import type { PdppRecordStore } from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import type { StorageAdapter } from "@opendatalabs/personal-server-ts-core/storage/adapters";
import type { DataStoragePort } from "@opendatalabs/personal-server-ts-core/ports";
import { createSqliteRecordStore } from "../storage/pdpp-records-sqlite-store.js";
import {
  buildDeclarationRegistry,
  singleInstanceInventory,
} from "./deployment.js";

const SCOPE = "instagram.posts";
const SOURCE_ID = "https://registry.pdpp.dev/connectors/instagram";
const OWNER = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12";
const SUBJECT = OWNER.toLowerCase();
const INSTANCE = `instagram:${SUBJECT}`;
const COLLECTED_AT = "2026-09-17T10:00:00.000Z";
const EXPECTED_VERSION = "1";

const DECLARATION_PATH = join(
  import.meta.dirname,
  "../../../core/src/pdpp/__fixtures__/instagram-posts.source-declaration.json",
);
const DECLARATION_DOCUMENT = readFileSync(DECLARATION_PATH, "utf-8");
const DOCUMENT_DIGEST = createHash("sha256")
  .update(DECLARATION_DOCUMENT, "utf8")
  .digest("hex");

/**
 * The digest the unity-surfaces producer's own `pdpp-sync-metadata.test.ts`
 * pins for this exact document (commit d85cfc50), independently reproduced
 * here by re-hashing the vendored bytes rather than trusting the copied
 * string.
 */
const PUBLISHED_DIGEST =
  "71535891f772fb65f1d02329c5757ec526df207af44a9f6527d6885550f0333f";

const ENVELOPE_DATA_1 = JSON.parse(
  readFileSync(
    join(
      import.meta.dirname,
      "../../../core/src/pdpp/__fixtures__/instagram-posts.producer-envelope-data.json",
    ),
    "utf-8",
  ),
) as Record<string, unknown>;

const ENVELOPE_DATA_2 = JSON.parse(
  readFileSync(
    join(
      import.meta.dirname,
      "../../../core/src/pdpp/__fixtures__/instagram-posts.producer-envelope-data-2.json",
    ),
    "utf-8",
  ),
) as Record<string, unknown>;

const logger = pino({ level: "silent" });

function makeEnvelope(
  data: Record<string, unknown>,
  collectedAt = COLLECTED_AT,
): DataFileEnvelope {
  return {
    version: "1.0",
    scope: SCOPE,
    collectedAt,
    data,
  } as DataFileEnvelope;
}

async function encryptEnvelope(
  envelope: DataFileEnvelope,
  masterKey: Uint8Array,
): Promise<Uint8Array> {
  const scopeKey = deriveScopeKey(masterKey, envelope.scope);
  const password = Array.from(scopeKey, (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
  return encryptWithPassword(
    new TextEncoder().encode(JSON.stringify(envelope)),
    password,
  );
}

function makeDataPointRecord(collectedAt = COLLECTED_AT): DataPointRecord {
  return {
    id: `0x${"df".repeat(32)}`,
    ownerAddress: OWNER,
    scope: SCOPE,
    dataHash: `0x${"33".repeat(32)}`,
    metadataHash: `0x${"44".repeat(32)}`,
    expectedVersion: EXPECTED_VERSION,
    addedAt: collectedAt,
  } as DataPointRecord;
}

function createLegacyStorage(): DataStoragePort & {
  written: DataFileEnvelope[];
  entries: unknown[];
} {
  const written: DataFileEnvelope[] = [];
  const entries: unknown[] = [];
  return {
    written,
    entries,
    findEntry: () => undefined,
    findByDataPointId: () => undefined,
    writeEnvelope: async (envelope: DataFileEnvelope) => {
      written.push(envelope);
      return {
        path: `/data/${envelope.scope}/${envelope.collectedAt}.json`,
        relativePath: `${envelope.scope}/${envelope.collectedAt}.json`,
        sizeBytes: 256,
      };
    },
    insertEntry: async (entry: unknown) => {
      entries.push(entry);
      return entry;
    },
    updateDataPointId: async () => true,
    listVersions: () => [],
    deleteVersion: async () => true,
    listScopes: () => ({ scopes: [], total: 0 }),
    readEnvelope: async () => makeEnvelope({}),
    deleteByFileId: async () => true,
  } as unknown as DataStoragePort & {
    written: DataFileEnvelope[];
    entries: unknown[];
  };
}

function createStorageAdapter(blob: Uint8Array): StorageAdapter {
  return {
    urlForKey: (key: string) => `https://storage.test/${key}`,
    download: async () => Uint8Array.from(blob),
  } as unknown as StorageAdapter;
}

describe("the instagram.posts declaration under test is the producer's own document", () => {
  it("is byte-identical to the document unity-surfaces's producer digested", () => {
    expect(DOCUMENT_DIGEST).toBe(PUBLISHED_DIGEST);
  });

  it("parses, and the retained snapshot digests to the document's own bytes", () => {
    const parsed = parseDeclaration(DECLARATION_DOCUMENT, SOURCE_ID);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.snapshot.digest).toBe(PUBLISHED_DIGEST);
    expect(parsed.snapshot.streams.map((s) => s.name)).toEqual(
      expect.arrayContaining(["profile", "posts"]),
    );
  });
});

describe("DataPipe encrypted sync -> PDPP import -> scoped read (instagram.posts)", () => {
  let dir: string;
  let dbPath: string;
  let db: Database.Database;
  let store: PdppRecordStore;
  let importer: PdppImporter;
  const masterKey = new Uint8Array(32).fill(11);

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "pdpp-sync-posts-e2e-"));
    dbPath = join(dir, "records.db");
    db = new Database(dbPath);
    store = createSqliteRecordStore(db);
    importer = buildImporter(store);
  });

  afterEach(() => {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });

  function buildImporter(target: PdppRecordStore): PdppImporter {
    const declPath = join(dir, "instagram.json");
    writeFileSync(declPath, DECLARATION_DOCUMENT, "utf-8");

    const registry = buildDeclarationRegistry({
      declarations: [{ sourceId: SOURCE_ID, document: DECLARATION_DOCUMENT }],
      supportedConnectors: ["instagram"],
      logger,
    });
    expect(registry.retained).toHaveLength(1);

    const snapshot = registry.retained[0];
    const document = registry.retainedDocuments.get(SOURCE_ID);
    expect(document).toBe(DECLARATION_DOCUMENT);

    return createPdppImporter({
      store: target,
      declarations: [
        {
          sourceId: snapshot.source_id,
          version: snapshot.version,
          documentDigest: createHash("sha256")
            .update(document as string, "utf8")
            .digest("hex"),
          streams: snapshot.streams.map((s) => ({
            name: s.name,
            primaryKey: s.primary_key,
            semantics: "mutable_state" as const,
          })),
        },
      ],
      instanceFor: (sourceId) =>
        singleInstanceInventory(SUBJECT, sourceId).eligibleFor("")[0],
      logger,
    });
  }

  async function syncOne(
    envelope: DataFileEnvelope,
    target: PdppImporter = importer,
    collectedAtForRecord = COLLECTED_AT,
  ): Promise<ReturnType<typeof createLegacyStorage>> {
    const blob = await encryptEnvelope(envelope, masterKey);
    const storage = createLegacyStorage();
    await downloadOne(
      {
        storage,
        storageAdapter: createStorageAdapter(blob),
        gateway: {} as never,
        cursor: {} as never,
        masterKey,
        serverOwner: OWNER,
        logger,
        pdppImporter: target,
      } as never,
      makeDataPointRecord(collectedAtForRecord),
    );
    return storage;
  }

  it("decrypts, imports, and serves the bounded posts snapshot under a scoped read, preserving the array field", async () => {
    const legacy = await syncOne(makeEnvelope(ENVELOPE_DATA_1));

    expect(legacy.written).toHaveLength(1);
    expect(legacy.entries).toHaveLength(1);

    const page = store.listRecords("posts", {
      instanceIds: [INSTANCE],
      limit: 10,
      order: "asc",
    });

    expect(page.data).toHaveLength(1);
    expect(page.data[0].recordKey).toBe("current");
    const stored = page.data[0].data as { posts: unknown[] };
    // The array field must survive the encrypt/decrypt/import/store round
    // trip in full, not truncated or flattened.
    expect(stored.posts).toEqual(ENVELOPE_DATA_1.posts);
    expect(stored.posts).toHaveLength(2);
    expect(stored).not.toHaveProperty("$pdpp");
  });

  it("does not leak the snapshot to a read scoped to another instance", async () => {
    await syncOne(makeEnvelope(ENVELOPE_DATA_1));

    const page = store.listRecords("posts", {
      instanceIds: [`instagram:0x${"9".repeat(40)}`],
      limit: 10,
      order: "asc",
    });
    expect(page.data).toEqual([]);
  });

  it("replaces the current snapshot in full on a second sync (bounded semantics, not append)", async () => {
    await syncOne(makeEnvelope(ENVELOPE_DATA_1));
    await syncOne(
      makeEnvelope(ENVELOPE_DATA_2, "2026-09-18T09:05:00.000Z"),
      importer,
      "2026-09-18T09:05:00.000Z",
    );

    const record = store.getRecord(INSTANCE, "posts", "current");
    expect(record).toBeDefined();
    const stored = record?.data as { posts: unknown[] };
    // Only the second run's posts remain — the first run's data is gone,
    // not merged or appended.
    expect(stored.posts).toEqual(ENVELOPE_DATA_2.posts);
    expect(stored.posts).toHaveLength(1);
    expect(record?.version).toBe(2);
  });
});
