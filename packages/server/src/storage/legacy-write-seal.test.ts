/**
 * The legacy-write seal in Node storage. Every test drives storage directly,
 * with no route and no route fence in the way, and uses a switchable account.
 * Disk and index are inspected afterwards: a refused write leaves nothing.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdir, mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { dirname, join, relative } from "node:path";
import { tmpdir } from "node:os";
import type Database from "better-sqlite3";
import {
  createDataFileEnvelope,
  decryptWithPassword,
  deriveScopeKey,
  type DataPointRecord,
} from "@opendatalabs/vana-sdk/browser";
import { createAccountStorageMode } from "@opendatalabs/personal-server-ts-core/api";
import { buildDataFilePath } from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import {
  createLegacyWriteSeal,
  LegacyWriteRefusedError,
} from "@opendatalabs/personal-server-ts-core/storage/legacy-write-seal";
import {
  downloadOne,
  type DownloadWorkerDeps,
} from "@opendatalabs/personal-server-ts-core/sync";
import { initializeDatabase } from "./index-schema.js";
import { createIndexManager, type IndexManager } from "./index-manager.js";
import {
  createNodeDataStorage,
  recoverStagedDataFiles,
} from "./node-data-storage.js";

vi.mock("@opendatalabs/vana-sdk/browser", async (importOriginal) => ({
  ...(await importOriginal()),
  deriveScopeKey: vi.fn(),
  decryptWithPassword: vi.fn(),
}));

const owner = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12";
const scope = "instagram.profile";
const collectedAt = "2026-11-09T00:00:00Z";
const intent = (value: string) => ({
  authority: "local",
  owner: "owner",
  operation: value.repeat(64),
  bodySha256: value.repeat(64),
});

/** Every file below the data directory, relative to it. */
async function filesUnder(dir: string): Promise<string[]> {
  const entries = await readdir(dir, { recursive: true, withFileTypes: true });
  return entries
    .filter((entry) => entry.isFile())
    .map((entry) => relative(dir, join(entry.parentPath, entry.name)));
}

describe("Node storage seals every legacy commit", () => {
  let root: string;
  let dataDir: string;
  let db: Database.Database;
  let index: IndexManager;
  const account = {
    state: "unswitched" as "unswitched" | "switched" | "unknown",
  };

  function build() {
    const mode = createAccountStorageMode({
      owner,
      source: () => {
        if (account.state === "unknown") throw new Error("no evidence");
        return account.state === "switched";
      },
    });
    return createLegacyWriteSeal({ mode, owner });
  }

  beforeEach(async () => {
    account.state = "unswitched";
    root = await mkdtemp(join(tmpdir(), "legacy-write-seal-"));
    dataDir = join(root, "data");
    db = initializeDatabase(join(root, "index.db"));
    index = createIndexManager(db, {
      legacyWriteSeal: build(),
      revisionJournalDir: join(root, "cas-revisions"),
    });
    vi.mocked(deriveScopeKey).mockReturnValue(new Uint8Array(32).fill(0xbb));
  });

  afterEach(async () => {
    index.close();
    await rm(root, { recursive: true, force: true });
  });

  const storage = () =>
    createNodeDataStorage({
      indexManager: index,
      hierarchyOptions: { dataDir },
    });
  const envelope = (value = "v") =>
    createDataFileEnvelope(scope, collectedAt, { value });

  // SEAL_BYPASSED: no route, no fence: the storage itself must refuse.
  describe("a direct commit on a switched owner (SEAL_BYPASSED)", () => {
    beforeEach(() => {
      account.state = "switched";
    });
    afterEach(async () => {
      expect(index.countByScope(scope)).toBe(0);
      expect(await filesUnder(dataDir).catch(() => [])).toEqual([]);
      expect(
        db.prepare("SELECT COUNT(*) AS n FROM owner_import_operations").get(),
      ).toEqual({ n: 0 });
    });

    const refused = async (action: () => unknown) => {
      try {
        await action();
        expect.unreachable("the commit was not refused");
      } catch (error) {
        expect(error).toBeInstanceOf(LegacyWriteRefusedError);
        expect((error as LegacyWriteRefusedError).verdict).toBe("switched");
        expect((error as LegacyWriteRefusedError).response.status).toBe(426);
      }
    };

    it("writeEnvelopeAndIndex", async () => {
      await refused(() =>
        storage().writeEnvelopeAndIndex!(envelope(), {
          fileId: null,
          scope,
          collectedAt,
        }),
      );
    });
    it("commitEnvelope", async () => {
      await refused(() =>
        storage().commitEnvelope!(envelope(), {
          fileId: null,
          scope,
          collectedAt,
        }),
      );
    });
    it("writeEnvelope", async () => {
      await refused(() => storage().writeEnvelope(envelope()));
    });
    it("insertEntry and the index insert", async () => {
      await refused(() =>
        storage().insertEntry({
          fileId: null,
          scope,
          collectedAt,
          path: "instagram/profile/x.json",
          sizeBytes: 1,
        }),
      );
      await refused(() =>
        index.insert({
          fileId: null,
          scope,
          collectedAt,
          path: "instagram/profile/y.json",
          sizeBytes: 1,
        }),
      );
    });
    it("an owner import (commitVersion)", async () => {
      await refused(() =>
        storage().commitVersion!({
          kind: "append",
          envelope: envelope(),
          metadata: {},
          import: intent("a"),
        }),
      );
    });
    it("a replica commit (commitVersion)", async () => {
      await refused(() =>
        storage().commitVersion!({
          kind: "replica",
          envelope: envelope(),
          metadata: { schemaId: null, dataPointId: "0xabc", version: 1 },
        }),
      );
    });
  });

  it("commits the same writes while the account is unswitched", async () => {
    const stored = await storage().commitVersion!({
      kind: "append",
      envelope: envelope(),
      metadata: {},
      import: intent("a"),
    });
    expect(stored.kind).toBe("stored");
    expect(index.countByScope(scope)).toBe(1);
  });

  it("refuses with a retryable 503 and no write while the mode is unknown", async () => {
    account.state = "unknown";
    try {
      await storage().writeEnvelopeAndIndex!(envelope(), {
        fileId: null,
        scope,
        collectedAt,
      });
      expect.unreachable();
    } catch (error) {
      expect((error as LegacyWriteRefusedError).verdict).toBe("unknown");
      expect((error as LegacyWriteRefusedError).response.status).toBe(503);
    }
    expect(index.countByScope(scope)).toBe(0);
    expect(await filesUnder(dataDir).catch(() => [])).toEqual([]);
  });

  describe("a prepared import that the switch overtakes (RECOVER_AFTER_SWITCH)", () => {
    /** A crash left this operation prepared; its file is not published. */
    function seedPrepared() {
      const prepared = createDataFileEnvelope("notes.documents", collectedAt, {
        value: "prepared",
      });
      const path = buildDataFilePath(dataDir, prepared.scope, collectedAt);
      db.prepare(
        `INSERT INTO owner_import_operations (authority, owner, scope, operation, body_sha256, state, collected_at, path, envelope_bytes, metadata_json)
        VALUES ('local', 'owner', @scope, @operation, @sha, 'prepared', @collectedAt, @path, @bytes, '{}')`,
      ).run({
        scope: prepared.scope,
        operation: "p".repeat(64),
        sha: "p".repeat(64),
        collectedAt,
        path: relative(dataDir, path),
        bytes: Buffer.from(JSON.stringify(prepared)),
      });
      return { prepared, path };
    }
    const operations = () =>
      db.prepare("SELECT state FROM owner_import_operations").all();

    it("publishes it on an unswitched account (the control)", async () => {
      const { prepared } = seedPrepared();
      // A scope delete elsewhere runs recover() first.
      await storage().deleteScope("other.scope");
      expect(index.countByScope(prepared.scope)).toBe(1);
      expect(operations()).toEqual([{ state: "accepted" }]);
    });

    it("drops it, publishing nothing, when a delete reaches recover() after the switch", async () => {
      const { prepared } = seedPrepared();
      account.state = "switched";
      await storage().deleteScope("other.scope");
      expect(index.countByScope(prepared.scope)).toBe(0);
      expect(await filesUnder(dataDir).catch(() => [])).toEqual([]);
      expect(operations()).toEqual([]);
    });

    it("leaves it prepared while the mode is unknown, so a later boot decides", async () => {
      const { prepared } = seedPrepared();
      account.state = "unknown";
      await storage().deleteScope("other.scope");
      expect(index.countByScope(prepared.scope)).toBe(0);
      expect(await filesUnder(dataDir).catch(() => [])).toEqual([]);
      expect(operations()).toEqual([{ state: "prepared" }]);
    });
  });

  describe("boot recovery of staged files", () => {
    /** A crash after the index row and the stage, before the final rename. */
    async function seedStaged() {
      const staged = envelope("staged");
      const finalPath = buildDataFilePath(dataDir, scope, collectedAt);
      await mkdir(dirname(finalPath), { recursive: true });
      const stagePath = `${finalPath}.pending.1`;
      await writeFile(stagePath, JSON.stringify(staged));
      db.prepare(
        `INSERT INTO data_files (file_id, schema_id, path, scope, collected_at, size_bytes, version)
         VALUES (NULL, NULL, @path, @scope, @collectedAt, 10, 1)`,
      ).run({
        path: relative(dataDir, finalPath),
        scope,
        collectedAt,
      });
      return { finalPath, stagePath };
    }
    const recover = () =>
      recoverStagedDataFiles({
        indexManager: index,
        hierarchyOptions: { dataDir },
      });

    it("publishes the stage on an unswitched account (the control)", async () => {
      await seedStaged();
      await recover();
      expect(await filesUnder(dataDir)).toEqual([
        relative(dataDir, buildDataFilePath(dataDir, scope, collectedAt)),
      ]);
    });

    it("removes the stage and its row on a switched account", async () => {
      await seedStaged();
      account.state = "switched";
      await recover();
      expect(await filesUnder(dataDir)).toEqual([]);
      expect(index.countByScope(scope)).toBe(0);
    });

    it("leaves the stage and its row while the mode is unknown", async () => {
      const { stagePath } = await seedStaged();
      account.state = "unknown";
      await recover();
      expect(await filesUnder(dataDir)).toEqual([relative(dataDir, stagePath)]);
      expect(index.countByScope(scope)).toBe(1);
    });
  });

  // DOWNLOAD_UNFENCED: the sync worker reaches storage with no route at all.
  describe("a download whose switch lands before it commits (DOWNLOAD_UNFENCED)", () => {
    const record = {
      id: "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
      ownerAddress: owner,
      scope,
      dataHash: `0x${"11".repeat(32)}`,
      metadataHash: `0x${"22".repeat(32)}`,
      expectedVersion: "7",
      addedAt: collectedAt,
    } as DataPointRecord;
    const depsFor = (store = storage()) =>
      ({
        storage: store,
        storageAdapter: {
          urlForKey: () => "https://storage.invalid/blob",
          download: async () => new Uint8Array([0xde, 0xad]),
        },
        gateway: {},
        cursor: { read: async () => null, write: async () => undefined },
        masterKey: new Uint8Array(65).fill(0xaa),
        serverOwner: owner,
        logger: {
          info: () => undefined,
          warn: () => undefined,
          error: () => undefined,
          debug: () => undefined,
        },
      }) as unknown as DownloadWorkerDeps;

    it("stores the replica while unswitched (the control)", async () => {
      vi.mocked(decryptWithPassword).mockResolvedValue(
        new TextEncoder().encode(JSON.stringify(envelope("replica"))),
      );
      await downloadOne(depsFor(), record);
      expect(index.countByScope(scope)).toBe(1);
    });

    it("refuses the commit and leaves nothing when the account switched while it decrypted", async () => {
      vi.mocked(decryptWithPassword).mockImplementation(async () => {
        account.state = "switched";
        return new TextEncoder().encode(JSON.stringify(envelope("replica")));
      });
      await expect(downloadOne(depsFor(), record)).rejects.toBeInstanceOf(
        LegacyWriteRefusedError,
      );
      expect(index.countByScope(scope)).toBe(0);
      expect(await filesUnder(dataDir).catch(() => [])).toEqual([]);
    });
  });
});
