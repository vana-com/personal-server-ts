/**
 * End-to-end: a real encrypted DataPipe envelope reaches a scoped PDPP read.
 *
 * This exercises the actual production path rather than a reconstruction of
 * it. Specifically, nothing here is mocked that the claim depends on:
 *
 *   - the envelope is encrypted with the SDK's real `encryptWithPassword`
 *     under a real `deriveScopeKey`-derived scope key, and decrypted by the
 *     real download worker (no stubbed crypto);
 *   - the declaration is a real spec-core §5 document, parsed by the real
 *     `parseDeclaration` and retained through the real
 *     `buildDeclarationRegistry`, including its connector trust gate;
 *   - the record store is the real better-sqlite3 backend, on a real file, so
 *     the persistence claim is about durable state and not a Map;
 *   - the read is the real `listRecords`/`getRecord` surface the resource
 *     server serves, restricted to the same instance handles a grant would
 *     carry.
 *
 * The one thing deliberately faked is the network: a storage adapter that
 * serves bytes from memory and a data-point feed that lists one record. Those
 * are transport, not behavior under test, and using real ones would test the
 * Gateway rather than this importer.
 *
 * What this does NOT prove, stated here so the test is not read as more than
 * it is: it does not prove interoperability with the Unity producer's current
 * declarations. Those use a different document schema (`connector_key`, no
 * `source_id`/`source_kind`) and digest a canonicalized re-serialization
 * rather than the retained bytes. Both are asserted as explicit rejections
 * below so the break cannot regress silently, but a passing suite here means
 * the PS half is correct, not that the producer is compatible.
 */

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
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

const SCOPE = "instagram.profile";
const SOURCE_ID = "https://registry.pdpp.dev/connectors/instagram";
const OWNER = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12";
const SUBJECT = OWNER.toLowerCase();
const INSTANCE = `instagram:${SUBJECT}`;
const COLLECTED_AT = "2026-09-17T10:00:00.000Z";
const EXPECTED_VERSION = "1";

/** A real spec-core §5 SourceDeclaration, as a deployment retains it on disk. */
const DECLARATION_DOCUMENT = JSON.stringify(
  {
    source_id: SOURCE_ID,
    source_kind: "connector",
    version: "0.1.0-local",
    streams: [
      {
        name: "profile",
        fields: ["id", "username", "full_name", "follower_count"],
        required_fields: ["id", "username"],
        primary_key: ["id"],
      },
    ],
  },
  null,
  2,
);

const DOCUMENT_DIGEST = createHash("sha256")
  .update(DECLARATION_DOCUMENT, "utf8")
  .digest("hex");

const logger = pino({ level: "silent" });

/**
 * Build the `$pdpp` metadata block exactly as the producer contract specifies
 * it, including the `sha256:` prefixed digest.
 */
function pdppMetadata(overrides: Record<string, unknown> = {}) {
  return {
    version: 1,
    sourceId: SOURCE_ID,
    declaration: {
      source: "instagram",
      version: "0.1.0-local",
      upstreamCommit: null,
      digest: `sha256:${DOCUMENT_DIGEST}`,
    },
    stream: {
      name: "profile",
      scope: SCOPE,
      semantics: "mutable_state",
      primaryKey: ["id"],
    },
    record: { key: { id: "235680975" }, op: "upsert" },
    run: { id: "dp_0199aa", source: "instagram" },
    ...overrides,
  };
}

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

/**
 * Encrypt an envelope the way the upload worker does: derive the scope key
 * from the master key, hex-encode it as the OpenPGP password, encrypt the
 * serialized envelope. The download worker must be able to reverse exactly
 * this without being told how.
 */
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

function makeDataPointRecord(): DataPointRecord {
  return {
    id: `0x${"de".repeat(32)}`,
    ownerAddress: OWNER,
    scope: SCOPE,
    dataHash: `0x${"11".repeat(32)}`,
    metadataHash: `0x${"22".repeat(32)}`,
    expectedVersion: EXPECTED_VERSION,
    addedAt: COLLECTED_AT,
  } as DataPointRecord;
}

/**
 * A minimal legacy storage port that records what the download worker wrote.
 *
 * The importer must not disturb this path, so the test asserts against it
 * directly rather than trusting that it still runs.
 */
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
    // A fresh copy each call: the worker zeroes the buffer it is handed.
    download: async () => Uint8Array.from(blob),
  } as unknown as StorageAdapter;
}

describe("DataPipe encrypted sync -> PDPP import -> scoped read", () => {
  let dir: string;
  let dbPath: string;
  let db: Database.Database;
  let store: PdppRecordStore;
  let importer: PdppImporter;
  const masterKey = new Uint8Array(32).fill(7);

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "pdpp-sync-e2e-"));
    dbPath = join(dir, "records.db");
    db = new Database(dbPath);
    store = createSqliteRecordStore(db);
    importer = buildImporter(store);
  });

  afterEach(() => {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });

  /**
   * Wire the importer the way `createPdppSyncImporter` does at boot, through
   * the REAL declaration registry so the trust gate and parser both run.
   */
  function buildImporter(target: PdppRecordStore): PdppImporter {
    const declPath = join(dir, "instagram.json");
    writeFileSync(declPath, DECLARATION_DOCUMENT, "utf-8");

    const registry = buildDeclarationRegistry({
      declarations: [{ sourceId: SOURCE_ID, document: DECLARATION_DOCUMENT }],
      // Derived from the scopes this PS holds, as the real bootstrap does.
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

  /** Run the real download worker over a real encrypted blob. */
  async function syncOne(
    envelope: DataFileEnvelope,
    target: PdppImporter = importer,
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
      makeDataPointRecord(),
    );
    return storage;
  }

  it("decrypts, imports, and serves the record under a scoped read", async () => {
    const legacy = await syncOne(
      makeEnvelope({
        id: "235680975",
        username: "callumflack",
        full_name: "Callum Flack",
        follower_count: 4210,
        $pdpp: pdppMetadata(),
      }),
    );

    // Legacy indexing still happened — the importer is additive.
    expect(legacy.written).toHaveLength(1);
    expect(legacy.entries).toHaveLength(1);
    // And the legacy envelope keeps the payload it always had.
    expect(legacy.written[0].scope).toBe(SCOPE);

    // The scoped read the resource server serves, restricted to the instance
    // handles a grant for this source would carry.
    const page = store.listRecords("profile", {
      instanceIds: [INSTANCE],
      limit: 10,
      order: "asc",
    });

    expect(page.data).toHaveLength(1);
    expect(page.data[0].recordKey).toBe("235680975");
    expect(page.data[0].emittedAt).toBe(COLLECTED_AT);
    // $pdpp is import metadata and must not be served back as record data.
    expect(page.data[0].data).toEqual({
      id: "235680975",
      username: "callumflack",
      full_name: "Callum Flack",
      follower_count: 4210,
    });
    expect(page.data[0].data).not.toHaveProperty("$pdpp");
  });

  it("does not leak the record to a read scoped to another instance", async () => {
    await syncOne(
      makeEnvelope({
        id: "235680975",
        username: "callumflack",
        full_name: "Callum Flack",
        $pdpp: pdppMetadata(),
      }),
    );

    const page = store.listRecords("profile", {
      instanceIds: [`instagram:0x${"9".repeat(40)}`],
      limit: 10,
      order: "asc",
    });
    expect(page.data).toEqual([]);
  });

  it("survives a restart: the record is still readable from a reopened store", async () => {
    await syncOne(
      makeEnvelope({
        id: "235680975",
        username: "callumflack",
        full_name: "Callum Flack",
        $pdpp: pdppMetadata(),
      }),
    );

    // Close everything and reopen the same file, as a process restart would.
    store.close();
    const reopened = createSqliteRecordStore(new Database(dbPath));
    try {
      const record = reopened.getRecord(INSTANCE, "profile", "235680975");
      expect(record).toBeDefined();
      expect(record?.data.username).toBe("callumflack");
      expect(record?.version).toBe(1);

      // And a re-sync after restart is still idempotent — the version must
      // not climb just because the process bounced.
      await syncOne(
        makeEnvelope({
          id: "235680975",
          username: "callumflack",
          full_name: "Callum Flack",
          $pdpp: pdppMetadata(),
        }),
        buildImporter(reopened),
      );
      expect(
        reopened.getRecord(INSTANCE, "profile", "235680975")?.version,
      ).toBe(1);
    } finally {
      reopened.close();
    }
    // Reassign so afterEach's close() is harmless.
    store = reopened;
  });

  it("imports an update as a new version and reports it once", async () => {
    await syncOne(
      makeEnvelope({
        id: "235680975",
        username: "callumflack",
        full_name: "Callum Flack",
        follower_count: 4210,
        $pdpp: pdppMetadata(),
      }),
    );

    const anchor = store.changesSince("profile", {
      instanceIds: [INSTANCE],
      limit: 50,
    }).nextChangesSince;

    await syncOne(
      makeEnvelope(
        {
          id: "235680975",
          username: "callumflack",
          full_name: "Callum Flack",
          follower_count: 4300,
          $pdpp: pdppMetadata(),
        },
        "2026-09-18T10:00:00.000Z",
      ),
    );

    const record = store.getRecord(INSTANCE, "profile", "235680975");
    expect(record?.version).toBe(2);
    expect(record?.data.follower_count).toBe(4300);

    const changes = store.changesSince("profile", {
      instanceIds: [INSTANCE],
      changesSince: anchor,
      limit: 50,
    });
    expect(changes.data).toHaveLength(1);
  });

  describe("malformed and hostile metadata", () => {
    it("keeps legacy indexing when $pdpp is malformed, and imports nothing", async () => {
      const legacy = await syncOne(
        makeEnvelope({
          id: "235680975",
          username: "callumflack",
          $pdpp: { version: 1, sourceId: SOURCE_ID, declaration: "broken" },
        }),
      );

      // The blob arrived intact, so the legacy path must still have run.
      expect(legacy.written).toHaveLength(1);
      expect(legacy.entries).toHaveLength(1);
      // But nothing was imported.
      expect(store.listStreams([INSTANCE])).toEqual([]);
    });

    it("rejects an envelope whose digest is over a canonicalized document", async () => {
      // The exact interop break found against the Unity producer: digesting
      // a key-sorted, minified re-serialization instead of the retained
      // bytes. Semantically the same document; still not a proof that the
      // producer read what the owner consented against.
      const canonical = JSON.stringify(JSON.parse(DECLARATION_DOCUMENT));
      const canonicalDigest = createHash("sha256")
        .update(canonical, "utf8")
        .digest("hex");
      expect(canonicalDigest).not.toBe(DOCUMENT_DIGEST);

      await syncOne(
        makeEnvelope({
          id: "235680975",
          username: "callumflack",
          $pdpp: pdppMetadata({
            declaration: {
              source: "instagram",
              version: "0.1.0-local",
              upstreamCommit: null,
              digest: `sha256:${canonicalDigest}`,
            },
          }),
        }),
      );

      expect(store.listStreams([INSTANCE])).toEqual([]);
    });

    it("refuses a declaration document PS cannot parse", () => {
      // The other half of the interop break: the producer's canonical
      // document uses `connector_key` and declares no `source_id` or
      // `source_kind`, so no PS deployment can retain it at all.
      const producerShaped = JSON.stringify({
        connector_key: "instagram",
        version: "0.1.0-local",
        streams: [
          {
            name: "profile",
            fields: ["id", "username"],
            required_fields: ["id"],
            primary_key: ["id"],
          },
        ],
      });

      const parsed = parseDeclaration(producerShaped, SOURCE_ID);
      expect(parsed.ok).toBe(false);
      if (!parsed.ok) {
        expect(parsed.failure.code).toBe("invalid_document");
        expect(parsed.failure.message).toContain("source_id");
      }

      // And the registry consequently retains nothing, which is what makes
      // the importer never see these envelopes.
      const registry = buildDeclarationRegistry({
        declarations: [{ sourceId: SOURCE_ID, document: producerShaped }],
        supportedConnectors: ["instagram"],
        logger,
      });
      expect(registry.retained).toEqual([]);
    });

    it("does not import a record whose key disagrees with its payload", async () => {
      await syncOne(
        makeEnvelope({
          id: "235680975",
          username: "callumflack",
          $pdpp: pdppMetadata({
            record: { key: { id: "999999999" }, op: "upsert" },
          }),
        }),
      );

      expect(store.getRecord(INSTANCE, "profile", "999999999")).toBeUndefined();
      expect(store.getRecord(INSTANCE, "profile", "235680975")).toBeUndefined();
    });
  });
});
