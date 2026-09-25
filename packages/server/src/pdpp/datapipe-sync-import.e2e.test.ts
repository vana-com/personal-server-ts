/**
 * End-to-end: a real encrypted DataPipe envelope reaches the PDPP importer,
 * and the PS store refuses it because it carries no acquisition method.
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
 *   - the record store is the real better-sqlite3 backend, on a real file.
 *     It refuses every method-less write (P8a), so the retry and cache
 *     mechanics run against the core memory store instead;
 *   - the read is the real `listRecords`/`getRecord` surface the resource
 *     server serves, restricted to the same instance handles a grant would
 *     carry.
 *
 * The one thing deliberately faked is the network: a storage adapter that
 * serves bytes from memory and a data-point feed that lists one record. Those
 * are transport, not behavior under test, and using real ones would test the
 * Gateway rather than this importer.
 *
 * The declaration is the REAL delivered `SourceDeclaration` the Unity
 * producer digests, read from disk rather than inlined. That distinction is
 * the point: a fixture authored here would only prove PS agrees with itself,
 * whereas reading the producer's own bytes is what makes the digest check an
 * interoperability result. The `$pdpp` metadata is likewise shaped as the
 * producer writes it.
 *
 * Division of labour with the parser lane, agreed rather than assumed: that
 * lane owns asserting the projection itself (`fields` from
 * `schema.properties`, the required floor from `schema.required`) against
 * these same files. This test asserts what only it can — that the projection
 * yields a stream a real `$pdpp` envelope actually imports against, and that
 * the digest matches the document's own bytes end to end through the import
 * path.
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
  type PdppImportOutcome,
} from "@opendatalabs/personal-server-ts-core/sync";
import { parseDeclaration } from "@opendatalabs/personal-server-ts-core/pdpp";
import {
  createMemoryRecordStore,
  type PdppRecordStore,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
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

/**
 * The REAL delivered SourceDeclaration, read from disk — never inlined.
 *
 * Inlining it would re-create the private-fixture problem: a document written
 * here proves only that PS agrees with this test. These are the producer's
 * own bytes, so the digest below is the value the producer actually stamps
 * into `$pdpp`, and a passing digest check is an interoperability result
 * rather than a self-consistency one.
 *
 * Read from the in-repo vendored copy rather than the delivery directory so
 * the test is self-contained. The two are byte-identical, and the assertion
 * immediately below pins that: if the vendored copy ever drifts from the
 * digest the producer published, this fails rather than quietly testing a
 * document no producer writes.
 */
const DECLARATION_PATH = join(
  import.meta.dirname,
  "../../../core/src/pdpp/__fixtures__/instagram.source-declaration.json",
);
const DECLARATION_DOCUMENT = readFileSync(DECLARATION_PATH, "utf-8");

const DOCUMENT_DIGEST = createHash("sha256")
  .update(DECLARATION_DOCUMENT, "utf8")
  .digest("hex");

/**
 * The digest the producer published for this exact document (PR1098
 * `bccc682e`), independently reproduced by two lanes. Pinned as a literal so
 * a change to the document is a deliberate, visible act.
 */
const PUBLISHED_DIGEST =
  "e4a9d0cb262f6b43956d7ff9cf17dd8851f3be1e3c3fe059bc18f022a29fbce5";

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

/**
 * A legacy storage port that PERSISTS its index across sync runs.
 *
 * `createLegacyStorage` above is fresh per call, which models a first-ever
 * download and cannot express the case that matters here: a data point that
 * is already in the local index when a later sync re-lists it. The retry path
 * is exactly the path that only exists on the second run, so testing it needs
 * an index that survives between runs.
 *
 * `downloads` counts adapter fetches so a retry can be shown to reuse the
 * cached local envelope rather than re-fetching the blob.
 */
function createPersistentLegacyStorage(): DataStoragePort & {
  envelopes: Map<string, DataFileEnvelope>;
  entries: Array<{
    dataPointId: string | null;
    scope: string;
    collectedAt: string;
    path: string;
    schemaId: string | null;
    fileId: string | null;
  }>;
} {
  const envelopes = new Map<string, DataFileEnvelope>();
  const entries: Array<{
    dataPointId: string | null;
    scope: string;
    collectedAt: string;
    path: string;
    schemaId: string | null;
    fileId: string | null;
  }> = [];
  const keyOf = (scope: string, at: string) => `${scope}@${at}`;

  return {
    envelopes,
    entries,
    findByDataPointId: (id: string) =>
      entries.find((e) => e.dataPointId === id),
    findEntry: ({ scope, at }: { scope: string; at: string }) =>
      entries.find((e) => e.scope === scope && e.collectedAt === at),
    writeEnvelope: async (envelope: DataFileEnvelope) => {
      envelopes.set(keyOf(envelope.scope, envelope.collectedAt), envelope);
      return {
        path: `/data/${envelope.scope}/${envelope.collectedAt}.json`,
        relativePath: `${envelope.scope}/${envelope.collectedAt}.json`,
        sizeBytes: 256,
      };
    },
    insertEntry: async (entry: Record<string, unknown>) => {
      entries.push(entry as unknown as (typeof entries)[number]);
      return entry;
    },
    readEnvelope: async (scope: string, collectedAt: string) => {
      const found = envelopes.get(keyOf(scope, collectedAt));
      if (!found) throw new Error("no local envelope");
      return found;
    },
    updateDataPointId: async () => true,
    listVersions: () => [],
    deleteVersion: async () => true,
    listScopes: () => ({ scopes: [], total: 0 }),
    deleteByFileId: async () => true,
  } as unknown as DataStoragePort & {
    envelopes: Map<string, DataFileEnvelope>;
    entries: typeof entries;
  };
}

function createStorageAdapter(blob: Uint8Array): StorageAdapter {
  return {
    urlForKey: (key: string) => `https://storage.test/${key}`,
    // A fresh copy each call: the worker zeroes the buffer it is handed.
    download: async () => Uint8Array.from(blob),
  } as unknown as StorageAdapter;
}

describe("the declaration under test is the producer's own document", () => {
  it("is byte-identical to the document the producer digested", () => {
    // If this fails, the vendored fixture drifted (a reformat is enough) and
    // every producer digest referencing it is silently invalid. Failing here
    // is much cheaper than debugging a `digest_mismatch` at import.
    expect(DOCUMENT_DIGEST).toBe(PUBLISHED_DIGEST);
  });

  it("is a normative Section 5 SourceDeclaration, not PS's internal shape", () => {
    const raw = JSON.parse(DECLARATION_DOCUMENT) as Record<string, unknown>;
    expect(raw.protocol_version).toBe("0.1.0");
    expect(raw.source).toEqual({ kind: "connector", id: SOURCE_ID });
    expect(raw.declaration_version).toBe("0.1.0-local");
    // The normative document carries a JSON Schema, not a flat field list.
    const stream = (raw.streams as Array<Record<string, unknown>>)[0];
    expect(stream.schema).toBeDefined();
    expect(stream).not.toHaveProperty("fields");
  });

  it("parses, and the retained snapshot digests to the document's own bytes", () => {
    const parsed = parseDeclaration(DECLARATION_DOCUMENT, SOURCE_ID);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    // End-to-end byte-exactness: what PS retains hashes to what the producer
    // stamped, with no canonicalization anywhere in between.
    expect(parsed.snapshot.digest).toBe(PUBLISHED_DIGEST);
    expect(parsed.snapshot.version).toBe("0.1.0-local");
  });
});

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

  it("decrypts, keeps legacy indexing, and refuses the record at the method fence", async () => {
    let outcome: PdppImportOutcome | undefined;
    const observed: PdppImporter = {
      importEnvelope: (e) => (outcome = importer.importEnvelope(e)),
      needsRetry: (scope, at) => importer.needsRetry(scope, at),
    };
    const legacy = await syncOne(
      makeEnvelope({
        id: "235680975",
        username: "callumflack",
        full_name: "Callum Flack",
        $pdpp: pdppMetadata(),
      }),
      observed,
    );

    // Legacy indexing still happened: the importer is additive.
    expect(legacy.written).toHaveLength(1);
    expect(legacy.entries).toHaveLength(1);

    // The envelope carries no acquisition method or binding generation, so
    // the PS store cannot apply P8a/P8c to it and writes nothing (L1).
    expect(outcome).toEqual({
      status: "rejected",
      rejection: { code: "method_authority", message: "method_required" },
    });
    expect(store.listStreams([INSTANCE])).toEqual([]);
    expect(
      db.prepare("SELECT COUNT(*) AS n FROM pdpp_instance_binding").get() as {
        n: number;
      },
    ).toEqual({ n: 0 });
  });

  it("does not retry a method-fence refusal on later syncs", async () => {
    let calls = 0;
    const counting: PdppImporter = {
      importEnvelope: (e) => {
        calls += 1;
        return importer.importEnvelope(e);
      },
      needsRetry: (scope, at) => importer.needsRetry(scope, at),
    };
    const envelope = makeEnvelope({
      id: "235680975",
      username: "callumflack",
      $pdpp: pdppMetadata(),
    });
    const storage = createPersistentLegacyStorage();
    const adapter = createStorageAdapter(
      await encryptEnvelope(envelope, masterKey),
    );
    const deps = {
      storage,
      storageAdapter: adapter,
      gateway: {} as never,
      cursor: {} as never,
      masterKey,
      serverOwner: OWNER,
      logger,
      pdppImporter: counting,
    } as never;

    await downloadOne(deps, makeDataPointRecord());
    await downloadOne(deps, makeDataPointRecord());
    await downloadOne(deps, makeDataPointRecord());

    expect(calls).toBe(1);
    expect(store.listStreams([INSTANCE])).toEqual([]);
  });

  /**
   * The retry path. Legacy indexing and PDPP import are two writes with no
   * shared transaction, so the window between them is real: the envelope can
   * be indexed while the import fails, or while no importer exists yet.
   *
   * The danger is that the legacy index is itself the dedup key. Once an
   * entry exists, a later sync recognises the data point as already-handled
   * and returns before decrypting — so without an explicit retry the record
   * is stranded in local storage forever, invisible to every PDPP read, and
   * no amount of re-syncing recovers it.
   */
  describe("retry after the import did not happen", () => {
    // The download worker's retry and cache mechanics are store-agnostic.
    // The PS SQLite store refuses every method-less import (see above), so
    // these run against the core memory store, which accepts them.
    let store: PdppRecordStore;
    let importer: PdppImporter;
    beforeEach(() => {
      store = createMemoryRecordStore();
      importer = buildImporter(store);
    });

    /** Drive one sync run against a persistent index. */
    async function syncWith(
      storage: DataStoragePort,
      envelope: DataFileEnvelope,
      target: PdppImporter | undefined,
      adapter: StorageAdapter,
    ): Promise<void> {
      await downloadOne(
        {
          storage,
          storageAdapter: adapter,
          gateway: {} as never,
          cursor: {} as never,
          masterKey,
          serverOwner: OWNER,
          logger,
          pdppImporter: target,
        } as never,
        makeDataPointRecord(),
      );
    }

    it("imports on a later sync after the first import failed", async () => {
      const storage = createPersistentLegacyStorage();
      const envelope = makeEnvelope({
        id: "235680975",
        username: "callumflack",
        full_name: "Callum Flack",
        $pdpp: pdppMetadata(),
      });
      const adapter = createStorageAdapter(
        await encryptEnvelope(envelope, masterKey),
      );

      // Run 1: the importer is transiently broken — the store is unreachable,
      // not the metadata invalid. Legacy indexing still succeeds.
      let failing = true;
      const flaky: PdppImporter = {
        importEnvelope: (e) => {
          if (failing) throw new Error("record store temporarily unavailable");
          return importer.importEnvelope(e);
        },
        needsRetry: (scope, at) => importer.needsRetry(scope, at),
      };
      await syncWith(storage, envelope, flaky, adapter);

      expect(storage.entries).toHaveLength(1);
      expect(store.getRecord(INSTANCE, "profile", "235680975")).toBeUndefined();

      // Run 2: the transient condition cleared. The data point is already in
      // the local index, so this is precisely the dedup path.
      failing = false;
      await syncWith(storage, envelope, flaky, adapter);

      const record = store.getRecord(INSTANCE, "profile", "235680975");
      expect(record).toBeDefined();
      expect(record?.data.username).toBe("callumflack");
      // Exactly once: the retry must not manufacture a second revision.
      expect(record?.version).toBe(1);
    });

    it("imports once the importer is enabled after an earlier sync", async () => {
      const storage = createPersistentLegacyStorage();
      const envelope = makeEnvelope({
        id: "235680975",
        username: "callumflack",
        full_name: "Callum Flack",
        $pdpp: pdppMetadata(),
      });
      const adapter = createStorageAdapter(
        await encryptEnvelope(envelope, masterKey),
      );

      // Run 1: PDPP is not mounted at all (disabled, or booted after sync).
      await syncWith(storage, envelope, undefined, adapter);
      expect(storage.entries).toHaveLength(1);
      expect(store.listStreams([INSTANCE])).toEqual([]);

      // Run 2: PDPP now mounted. The envelope indexed before it existed must
      // still reach the record store.
      await syncWith(storage, envelope, importer, adapter);

      const record = store.getRecord(INSTANCE, "profile", "235680975");
      expect(record).toBeDefined();
      expect(record?.version).toBe(1);
    });

    it("reuses the cached local envelope instead of re-downloading", async () => {
      const storage = createPersistentLegacyStorage();
      const envelope = makeEnvelope({
        id: "235680975",
        username: "callumflack",
        full_name: "Callum Flack",
        $pdpp: pdppMetadata(),
      });
      let downloads = 0;
      const counting = {
        urlForKey: (key: string) => `https://storage.test/${key}`,
        download: async () => {
          downloads += 1;
          return Uint8Array.from(await encryptEnvelope(envelope, masterKey));
        },
      } as unknown as StorageAdapter;

      await syncWith(storage, envelope, undefined, counting);
      expect(downloads).toBe(1);

      // The retry has the plaintext envelope on disk already; re-fetching and
      // re-decrypting the blob would be wasted network and CPU every cycle.
      await syncWith(storage, envelope, importer, counting);
      expect(downloads).toBe(1);
      expect(store.getRecord(INSTANCE, "profile", "235680975")).toBeDefined();
    });

    it("does not re-import an entry that was already imported", async () => {
      const storage = createPersistentLegacyStorage();
      const envelope = makeEnvelope({
        id: "235680975",
        username: "callumflack",
        full_name: "Callum Flack",
        $pdpp: pdppMetadata(),
      });
      const adapter = createStorageAdapter(
        await encryptEnvelope(envelope, masterKey),
      );

      const anchor = store.changesSince("profile", {
        instanceIds: [INSTANCE],
        limit: 50,
      }).nextChangesSince;

      await syncWith(storage, envelope, importer, adapter);
      // Three further cycles over an already-imported, already-indexed point.
      await syncWith(storage, envelope, importer, adapter);
      await syncWith(storage, envelope, importer, adapter);
      await syncWith(storage, envelope, importer, adapter);

      expect(store.getRecord(INSTANCE, "profile", "235680975")?.version).toBe(
        1,
      );
      const changes = store.changesSince("profile", {
        instanceIds: [INSTANCE],
        changesSince: anchor,
        limit: 50,
      });
      expect(changes.data).toHaveLength(1);
    });

    it("does not retry an envelope whose metadata is invalid", async () => {
      const storage = createPersistentLegacyStorage();
      // Invalid metadata is a permanent verdict, not a transient one. Re-
      // reading and re-verifying it on every cycle forever would be work that
      // can never succeed.
      const envelope = makeEnvelope({
        id: "235680975",
        username: "callumflack",
        $pdpp: pdppMetadata({
          declaration: {
            source: "instagram",
            version: "0.1.0-local",
            upstreamCommit: null,
            digest: `sha256:${"b".repeat(64)}`,
          },
        }),
      });
      const adapter = createStorageAdapter(
        await encryptEnvelope(envelope, masterKey),
      );

      let calls = 0;
      const counting: PdppImporter = {
        importEnvelope: (e) => {
          calls += 1;
          return importer.importEnvelope(e);
        },
        needsRetry: (scope, at) => importer.needsRetry(scope, at),
      };

      await syncWith(storage, envelope, counting, adapter);
      expect(calls).toBe(1);
      await syncWith(storage, envelope, counting, adapter);

      // Rejected once and not retried; nothing imported either way.
      expect(calls).toBe(1);
      expect(store.listStreams([INSTANCE])).toEqual([]);
    });

    it("does not retry a non-PDPP envelope", async () => {
      const storage = createPersistentLegacyStorage();
      const envelope = makeEnvelope({ id: "1", username: "legacy" });
      const adapter = createStorageAdapter(
        await encryptEnvelope(envelope, masterKey),
      );

      let calls = 0;
      const counting: PdppImporter = {
        importEnvelope: (e) => {
          calls += 1;
          return importer.importEnvelope(e);
        },
        needsRetry: (scope, at) => importer.needsRetry(scope, at),
      };

      await syncWith(storage, envelope, counting, adapter);
      expect(calls).toBe(1);
      // A legacy envelope carries no $pdpp and never will. Re-reading it
      // every cycle would be permanent waste for every pre-PDPP data point.
      await syncWith(storage, envelope, counting, adapter);
      expect(calls).toBe(1);
    });
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
      // A regression guard for an interop break the producer has since
      // fixed: it previously digested a key-sorted, minified
      // re-serialization instead of the retained bytes. Semantically the
      // same document, and still not proof the producer read what the owner
      // consented against — so it must keep failing.
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

    it("retains nothing when a document declares a source it does not own", () => {
      // The trust gate still has to hold now that the parser is permissive
      // about document shape: a well-formed declaration is not automatically
      // an authority over whatever source it names.
      const registry = buildDeclarationRegistry({
        declarations: [
          {
            sourceId: "https://registry.pdpp.dev/connectors/spotify",
            document: DECLARATION_DOCUMENT,
          },
        ],
        supportedConnectors: ["instagram", "spotify"],
        logger,
      });
      expect(registry.retained).toEqual([]);
      expect(registry.retainedDocuments.size).toBe(0);
    });

    it("retains nothing for a connector this server does not serve", () => {
      const registry = buildDeclarationRegistry({
        declarations: [{ sourceId: SOURCE_ID, document: DECLARATION_DOCUMENT }],
        // This PS holds no Instagram data, so it must not become an
        // authority over Instagram grants.
        supportedConnectors: ["github"],
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
