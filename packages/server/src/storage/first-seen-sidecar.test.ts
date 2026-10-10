import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { chmod, mkdtemp, readdir, readFile, rm, stat } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type Database from "better-sqlite3";
import { createDataFileEnvelope } from "@opendatalabs/vana-sdk/node";
import type { DataStoragePort } from "@opendatalabs/personal-server-ts-core/ports";
import {
  deleteDataScopeContract,
  ingestBinaryDataContract,
  ingestDataContract,
  listDataScopesContract,
  listDataVersionsContract,
  readDataContract,
} from "@opendatalabs/personal-server-ts-core/contracts";
import {
  ensureScopeLedger,
  readScopeFirstSeenLedger,
  withScopeLock,
} from "@opendatalabs/personal-server-ts-core/additions";
import { withLegacyProjection } from "@opendatalabs/personal-server-ts-core/storage/legacy-projection";
import { buildDataBlocksAsync } from "@opendatalabs/personal-server-ts-core/storage/blocks/build";
import { buildDataFilePath } from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import { initializeDatabase } from "./index-schema.js";
import { createIndexManager } from "./index-manager.js";
import { createNodeDataStorage } from "./node-data-storage.js";
import { openRedactedEnvelopeStream } from "../jobs/raw-envelope-stream.js";

const SCOPE = "notes.entries";
const T1 = "2026-10-01T12:00:00Z";
const T2 = "2026-10-08T12:00:00Z";
const T3 = "2026-10-09T08:00:00Z";

const items = (...ids: string[]) => ({ items: ids.map((id) => ({ id })) });

describe("first-seen sidecar on the Node storage", () => {
  let db: Database.Database;
  let dataDir: string;
  let storage: DataStoragePort;

  beforeEach(async () => {
    db = initializeDatabase(":memory:");
    dataDir = await mkdtemp(join(tmpdir(), "first-seen-sidecar-test-"));
    storage = createNodeDataStorage({
      indexManager: createIndexManager(db),
      hierarchyOptions: { dataDir },
    });
  });

  afterEach(async () => {
    db.close();
    await rm(dataDir, { recursive: true, force: true });
  });

  function ingest(
    body: Record<string, unknown>,
    collectedAt: string,
    scope = SCOPE,
    port: DataStoragePort = storage,
  ) {
    return ingestDataContract({
      storage: port,
      scopeParam: scope,
      body,
      collectedAt,
      status: "stored",
    });
  }

  const sidecarPath = (scope = SCOPE) =>
    join(dataDir, "first-seen", `${scope}.json`);

  async function ledger(scope = SCOPE) {
    return readScopeFirstSeenLedger(await storage.readFirstSeenLedger!(scope));
  }

  it("keeps one file per scope outside the per-version data files", async () => {
    await ingest(items("a"), T1);
    await ingest(items("a", "b"), T2);

    const onDisk = JSON.parse(await readFile(sidecarPath(), "utf-8"));
    expect(onDisk.version).toBe(3);
    expect(onDisk.records["items:i:b"]).toEqual([T2, T2]);
    // The scope's own directory holds only the two version files.
    expect(await readdir(join(dataDir, "notes", "entries"))).toEqual([
      "2026-10-01T12-00-00Z.json",
      "2026-10-08T12-00-00Z.json",
    ]);
  });

  it("stores the data envelope byte-identically to a write without a sidecar", async () => {
    const body = { items: [{ id: "a" }], note: "hello" };
    await ingest(body, T1);
    const bytes = await readFile(
      buildDataFilePath(dataDir, SCOPE, T1),
      "utf-8",
    );
    expect(bytes).toBe(
      JSON.stringify(createDataFileEnvelope(SCOPE, T1, body), null, 2),
    );
  });

  it("is never an index row: not a version, not a scope, never unsynced", async () => {
    await ingest(items("a"), T1);

    expect(storage.listVersions(SCOPE, { limit: 100 })).toHaveLength(1);
    expect(storage.countVersions(SCOPE)).toBe(1);
    expect(storage.findUnsynced()).toHaveLength(1);
    expect(storage.findUnsynced()[0]!.path).toBe(
      "notes/entries/2026-10-01T12-00-00Z.json",
    );
    expect(
      storage.listScopes({ limit: 100 }).scopes.map((s) => s.scope),
    ).toEqual([SCOPE]);
    const versions = await listDataVersionsContract({
      storage,
      scopeParam: SCOPE,
    });
    expect(JSON.stringify(versions)).not.toContain("first-seen");
    expect(
      JSON.stringify(await listDataScopesContract({ storage })),
    ).not.toContain("first-seen");
  });

  it("is not reachable through a data read, a block read or the raw stream", async () => {
    await ingest(
      { items: Array.from({ length: 40 }, (_, i) => ({ id: `rec-${i}` })) },
      T1,
    );
    const marker = "items:i:rec-";
    expect(JSON.stringify(await ledger())).toContain(marker);

    // Served read (grantee-visible shape).
    const served = withLegacyProjection(storage);
    const read = await readDataContract({ storage: served, scopeParam: SCOPE });
    expect(JSON.stringify(read)).not.toContain(marker);
    expect(JSON.stringify(read)).not.toContain("baseline");

    // Byte-paged block reads with a tiny budget, the MCP block-read path.
    let cursor: string | undefined;
    let text = "";
    let pages = 0;
    do {
      const page = await served.readScopeBlocks!(SCOPE, T1, {
        cursor,
        maxBytes: 64,
      });
      text += JSON.stringify(page.blocks);
      cursor = page.nextCursor;
      pages += 1;
    } while (cursor && pages < 500);
    expect(pages).toBeGreaterThan(1);
    expect(text).not.toContain(marker);
    expect(text).not.toContain("baseline");
    const manifest = await served.readBlockManifest!(SCOPE, T1);
    expect(JSON.stringify(manifest)).not.toContain(marker);

    // The owner/job raw envelope stream.
    const stream = await openRedactedEnvelopeStream(() =>
      served.readEnvelopeStream!(SCOPE, T1),
    );
    const streamed = await new Response(stream).text();
    expect(streamed).not.toContain(marker);
    expect(streamed).not.toContain("baseline");
    expect(JSON.parse(streamed).data.items).toHaveLength(40);
  });

  it("survives a binary write between two JSON writes", async () => {
    await ingest(items("a", "b"), T1);
    await ingestBinaryDataContract({
      storage,
      scopeParam: SCOPE,
      bytes: new TextEncoder().encode("%PDF-1.7 fake"),
      mimeType: "application/pdf",
      collectedAt: T2,
      status: "stored",
    });
    await ingest(items("a", "b", "c"), T3);

    const result = await ledger();
    expect(result?.baseline).toBe(T1);
    expect(result?.records["items:i:c"]).toEqual([T3, T3]);
    expect(result?.records["items:i:a"]![0]).toBe(T1);
  });

  it("backfills a scope that has versions but no sidecar", async () => {
    for (const [at, ids] of [
      [T1, ["a"]],
      [T2, ["a", "b"]],
    ] as const) {
      const envelope = createDataFileEnvelope(SCOPE, at, items(...ids));
      const write = await storage.writeEnvelope(envelope);
      await storage.insertEntry({
        fileId: null,
        schemaId: null,
        path: write.relativePath,
        scope: SCOPE,
        collectedAt: at,
        sizeBytes: write.sizeBytes,
        afterTombstoneVersion: null,
      });
    }
    await expect(stat(sidecarPath())).rejects.toThrow();

    const rebuilt = await ensureScopeLedger(storage, SCOPE);
    expect(rebuilt?.baseline).toBe(T1);
    expect(rebuilt?.records["items:i:b"]).toEqual([T2, T2]);
    expect(rebuilt?.records["items:i:a"]).toEqual([T1, T2]);
    // Persisted for the next request.
    expect(await ledger()).toEqual(rebuilt);
  });

  it("is removed with the scope and a reimport starts a fresh baseline", async () => {
    await ingest(items("a"), T1);
    await ingest(items("a", "b"), T2);
    await stat(sidecarPath());

    await deleteDataScopeContract({ storage, scopeParam: SCOPE });
    await expect(stat(sidecarPath())).rejects.toThrow();
    expect(await ledger()).toBeNull();

    await ingest(items("a", "b", "c"), T3);
    expect((await ledger())?.baseline).toBe(T3);
  });

  it("deleting an absent sidecar is a no-op, and a scope can never escape the folder", async () => {
    await expect(
      storage.deleteFirstSeenLedger!(SCOPE),
    ).resolves.toBeUndefined();
    await expect(
      storage.writeFirstSeenLedger!("../../etc/passwd", {}),
    ).rejects.toThrow();
    await expect(storage.readFirstSeenLedger!("a/../b.c")).rejects.toThrow();
  });

  describe("never outlives the scope's last version", () => {
    it("is removed when deleteVersion removes the last version", async () => {
      await ingest(items("secret-id"), T1);
      await stat(sidecarPath());
      await storage.deleteVersion(SCOPE, T1);
      await expect(stat(sidecarPath())).rejects.toThrow();
    });

    it("is removed when deleteByFileId removes the last version", async () => {
      await ingest(items("secret-id"), T1);
      const entry = storage.findEntry({ scope: SCOPE })!;
      await storage.updateFileId(entry.path, "file-1");
      await storage.deleteByFileId("file-1");
      await expect(stat(sidecarPath())).rejects.toThrow();
    });

    it("is removed when dropUnsyncedEntry removes the last row", async () => {
      await ingest(items("secret-id"), T1);
      const entry = storage.findEntry({ scope: SCOPE })!;
      expect(await storage.dropUnsyncedEntry!(entry.path)).toBe(true);
      await expect(stat(sidecarPath())).rejects.toThrow();
    });

    it("stays while other versions remain, and a deleted newest version is rebuilt away", async () => {
      await ingest(items("a"), T1);
      await ingest(items("a", "secret-id"), T2);
      await storage.deleteVersion(SCOPE, T2);
      await stat(sidecarPath());
      const rebuilt = await ensureScopeLedger(storage, SCOPE);
      expect(rebuilt?.latest.collectedAt).toBe(T1);
      expect(Object.keys(rebuilt!.records)).toEqual(["items:i:a"]);
      expect(await readFile(sidecarPath(), "utf-8")).not.toContain("secret-id");
    });

    it("a delete racing a rebuild leaves nothing on disk", async () => {
      await ingest(items("secret-id"), T1);
      await rm(sidecarPath());
      const original = storage.readEnvelope.bind(storage);
      let deletion: Promise<number> | undefined;
      const racing: DataStoragePort = new Proxy(storage, {
        get(target, property) {
          if (property === "readEnvelope") {
            return async (scope: string, collectedAt: string) => {
              const envelope = await original(scope, collectedAt);
              deletion ??= storage.deleteScope(scope);
              return envelope;
            };
          }
          const value = Reflect.get(target, property, target);
          return typeof value === "function" ? value.bind(target) : value;
        },
      });
      await ensureScopeLedger(racing, SCOPE);
      await deletion;
      await expect(stat(sidecarPath())).rejects.toThrow();
      expect(storage.countVersions(SCOPE)).toBe(0);
    });
  });

  describe("deletes take the scope's sidecar lock (B8)", () => {
    async function blockedBy(run: () => Promise<unknown>) {
      let release!: () => void;
      const held = withScopeLock(
        SCOPE,
        () => new Promise<void>((resolve) => (release = resolve)),
      );
      let finished = false;
      const pending = run().then(() => {
        finished = true;
      });
      await new Promise((resolve) => setTimeout(resolve, 20));
      const waited = !finished;
      release();
      await held;
      await pending;
      return waited;
    }

    it("deleteScope waits for the lock", async () => {
      await ingest(items("a"), T1);
      expect(await blockedBy(() => storage.deleteScope(SCOPE))).toBe(true);
    });

    it("deleteVersion waits for the lock", async () => {
      await ingest(items("a"), T1);
      expect(await blockedBy(() => storage.deleteVersion(SCOPE, T1))).toBe(
        true,
      );
    });

    it("deleteByFileId waits for the lock", async () => {
      await ingest(items("a"), T1);
      const entry = storage.findEntry({ scope: SCOPE })!;
      await storage.updateFileId(entry.path, "file-lock");
      expect(await blockedBy(() => storage.deleteByFileId("file-lock"))).toBe(
        true,
      );
    });
  });

  it("deleteScope removes the sidecar even when the data delete fails (B9)", async () => {
    await ingest(items("secret-id"), T1);
    await stat(sidecarPath());
    // Make the scope's parent read-only so removing the data directory fails.
    await chmod(join(dataDir, "notes"), 0o555);
    try {
      await expect(storage.deleteScope(SCOPE)).rejects.toThrow();
    } finally {
      await chmod(join(dataDir, "notes"), 0o755);
    }
    await expect(stat(sidecarPath())).rejects.toThrow();
  });

  it("a sidecar that cannot be removed never blocks the data delete (F5)", async () => {
    await ingest(items("secret-id"), T1);
    await chmod(join(dataDir, "first-seen"), 0o555);
    try {
      await expect(storage.deleteScope(SCOPE)).resolves.toBe(1);
    } finally {
      await chmod(join(dataDir, "first-seen"), 0o755);
    }
    expect(storage.countVersions(SCOPE)).toBe(0);
    await expect(stat(join(dataDir, "notes", "entries"))).rejects.toThrow();
    // The leftover is harmless and collected: the next read drops it.
    await stat(sidecarPath());
    expect(await ensureScopeLedger(storage, SCOPE)).toBeNull();
    await expect(stat(sidecarPath())).rejects.toThrow();
  });

  it("buildDataBlocks of a stored envelope never sees the sidecar", async () => {
    await ingest(items("a"), T1);
    const stored = await storage.readEnvelope(SCOPE, T1);
    const built = await buildDataBlocksAsync({
      scope: SCOPE,
      collectedAt: T1,
      content: stored,
    });
    expect(JSON.stringify(built)).not.toContain("baseline");
  });
});
