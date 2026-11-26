import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  readFileSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, relative } from "node:path";
import { buildDataFilePath } from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import { afterEach, describe, expect, it, vi } from "vitest";
import Database from "better-sqlite3";
import { initializeDatabase } from "./index-schema.js";
import { createIndexManager } from "./index-manager.js";
import { createLegacyRetireRows } from "./legacy-retire-rows.js";
import { openLegacyWriteSealForTests } from "@opendatalabs/personal-server-ts-core/test-utils";
import { createLegacyRetirePipeline } from "../../../core/src/localdb/legacy-retire-pipeline.js";
import { createOpenPersistentPsLiteStorage } from "../../../lite/src/test-support/open-storage.js";
import { createMemoryPsLitePersistence } from "../../../lite/src/test-support/memory.js";
import type {
  IndexEntry,
  NewIndexEntry,
} from "@opendatalabs/personal-server-ts-core/storage/index";
import type { LegacyHead } from "../../../core/src/localdb/legacy-delete.js";
import type {
  LegacyRetirePipelinePorts,
  RetirementRows,
} from "../../../core/src/localdb/legacy-retire-pipeline.js";
import type { SqlDriver } from "@opendatalabs/personal-server-ts-core/localdb";

const closing: (() => void)[] = [];
afterEach(() => {
  for (const close of closing.splice(0)) close();
});
const base: NewIndexEntry = {
  scope: "github.events",
  path: "github/events/2026-01-01T00:00:00.000Z.json",
  collectedAt: "2026-01-01T00:00:00.000Z",
  fileId: null,
  sizeBytes: 1,
  version: 1,
};
async function backend(kind: string, beforeRemoval?: () => Promise<void>) {
  const originalSeal = openLegacyWriteSealForTests();
  const seal = {
    ...originalSeal,
    remove: async <T>(work: () => Promise<T>) => {
      await beforeRemoval?.();
      return originalSeal.remove(work);
    },
  };
  if (kind === "lite") {
    const persistence = createMemoryPsLitePersistence();
    const storage = await createOpenPersistentPsLiteStorage(
      { kind: "custom" },
      persistence,
      undefined,
      seal,
    );
    // Lite paths are its scope/collectedAt key; obtain it from a real write.
    const { createDataFileEnvelope } =
      await import("@opendatalabs/vana-sdk/browser");
    return {
      rows: storage.retirementRows,
      transactions: vi.spyOn(persistence, "write"),
      scopeReads: undefined,
      reopen: async () =>
        (
          await createOpenPersistentPsLiteStorage(
            { kind: "custom" },
            persistence,
            undefined,
            seal,
          )
        ).retirementRows,
      read: (row: IndexEntry) =>
        storage.readEnvelope(row.scope, row.collectedAt),
      insert: async (entry: NewIndexEntry) => {
        const written = await storage.writeEnvelope(
          createDataFileEnvelope(entry.scope, entry.collectedAt, {
            records: [],
          }),
        );
        return storage.insertEntry({ ...entry, path: written.relativePath });
      },
    };
  }
  const dataDir = mkdtempSync(join(tmpdir(), "legacy-retire-rows-"));
  let db = initializeDatabase(join(dataDir, "index.db"));
  let index = createIndexManager(db);
  closing.push(() => {
    db.close();
    rmSync(dataDir, { recursive: true, force: true });
  });
  const scopeReads = vi.spyOn(index, "findByScope");
  return {
    transactions: vi.spyOn(db, "transaction"),
    scopeReads,
    rows: createLegacyRetireRows(db, index, { dataDir }, seal),
    reopen: async () => {
      db.close();
      db = initializeDatabase(join(dataDir, "index.db"));
      index = createIndexManager(db);
      return createLegacyRetireRows(db, index, { dataDir }, seal);
    },
    read: async (row: IndexEntry) =>
      JSON.parse(
        readFileSync(
          buildDataFilePath(dataDir, row.scope, row.collectedAt),
          "utf8",
        ),
      ),
    insert: (entry: NewIndexEntry) =>
      seal.commit((hold) =>
        Promise.resolve().then(() => {
          const path = buildDataFilePath(
            dataDir,
            entry.scope,
            entry.collectedAt,
          );
          mkdirSync(dirname(path), { recursive: true });
          writeFileSync(
            path,
            JSON.stringify({
              scope: entry.scope,
              collectedAt: entry.collectedAt,
              data: { records: [] },
            }),
          );
          const indexedPath = relative(dataDir, path);
          index.deleteByPath(indexedPath);
          return index.insert(hold, { ...entry, path: indexedPath });
        }),
      ),
  };
}
function fixture(rows: RetirementRows) {
  const sql = new Database(":memory:");
  closing.push(() => sql.close());
  sql.exec(
    "CREATE TABLE legacy_retirements (owner, connector PRIMARY KEY, retire_id, state, scopes, created_at); CREATE TABLE legacy_retire_manifests (retire_id PRIMARY KEY, manifest); CREATE TABLE legacy_retire_receipts (retire_id, scope, version, PRIMARY KEY(retire_id, scope, version));",
  );
  let ready = true;
  const effects: string[] = [];
  const db: SqlDriver = {
    info: { host: "node", persistent: false, sqliteVersion: "3" },
    async query(text, params = []) {
      return sql.prepare(text).all(...params) as never;
    },
    async batch(statements) {
      effects.push("batch");
      return {
        changes: sql.transaction(() =>
          statements.map(
            (s) => sql.prepare(s.sql).run(...(s.params ?? [])).changes,
          ),
        )(),
      };
    },
    async close() {},
  };
  let head: LegacyHead = { state: "absent" };
  const ports: LegacyRetirePipelinePorts = {
    mode: () => "switched",
    scopesOf: () => [base.scope],
    streamsOf: () => ["events"],
    head: async () => head,
    rows,
    finality: {
      tombstoneState: async () => ({
        finalized: "3",
        settling: false,
        rolledBack: null,
      }),
    },
    versions: {
      list: async () => ({
        complete: true,
        versions: [
          { expectedVersion: "1", isTombstone: false, dataHash: "hash" },
          { expectedVersion: "2", isTombstone: false, dataHash: "hash" },
          { expectedVersion: "3", isTombstone: true, dataHash: "hash" },
        ],
      }),
    },
    tombstone: async () => {
      head = { state: "deleted", version: "3" };
      return "accepted";
    },
    eraseBlob: async () => true,
  };
  const restart = () =>
    createLegacyRetirePipeline(
      {
        db,
        ownerAddress: "0x11",
        newOp: () => "retire-1",
        now: () => 1,
        logger: { warn() {} } as never,
      },
      ports,
    );
  const pipeline = restart();
  const authority = () => {
    if (!ready) throw Error("revoked");
  };
  return {
    db,
    sql,
    ports,
    pipeline,
    restart,
    authority,
    effects,
    revoke: () => {
      ready = false;
    },
    head: (value: LegacyHead) => {
      head = value;
    },
  };
}
for (const kind of ["node", "lite"])
  describe(`retirement rows on ${kind}`, () => {
    for (const missing of ["acknowledgement", "tombstone", "rollback"] as const)
      it(`missing ${missing} evidence issues no erase`, async () => {
        const b = await backend(kind);
        await b.insert(base);
        const erase = vi.fn(b.rows.erase);
        const f = fixture({ ...b.rows, erase });
        f.head({
          state: "live",
          fence: {
            expectedVersion: "2",
            dataHash: "hash",
            metadataHash: "meta",
          },
        });
        const id = await f.pipeline.capture("github", f.authority);
        if (missing === "acknowledgement") {
          const stored = f.sql
            .prepare("SELECT manifest FROM legacy_retire_manifests")
            .get() as { manifest: string };
          const manifest = JSON.parse(stored.manifest);
          delete manifest.scopes[0].acknowledgement;
          f.sql
            .prepare("UPDATE legacy_retire_manifests SET manifest = ?")
            .run(JSON.stringify(manifest));
        } else if (missing === "tombstone") {
          const tombstone = f.ports.tombstone;
          f.ports.tombstone = async (...args) => {
            await tombstone(...args);
            return undefined as never;
          };
        } else {
          f.head({ state: "deleted", version: "3" });
          f.ports.finality.tombstoneState = async () => ({
            finalized: "3",
            settling: false,
            rolledBack: undefined as never,
          });
        }
        const result = await f.pipeline.advance(
          id,
          f.authority,
          new AbortController().signal,
        );
        expect(result.state).not.toBe("done");
        expect(erase).not.toHaveBeenCalled();
      });

    it("capture reads only the bound scopes' rows", async () => {
      const b = await backend(kind);
      const bound = await b.insert(base);
      const unrelated = await b.insert({ ...base, scope: "unrelated.history" });
      // Lite keeps the inserted object in its flat snapshot. Reading scope
      // to filter is fine; cloning unrelated row contents is not.
      const readContents = vi.fn(() => unrelated.createdAt);
      if (kind === "lite") {
        const createdAt = unrelated.createdAt;
        readContents.mockImplementation(() => createdAt);
        Object.defineProperty(unrelated, "createdAt", {
          enumerable: true,
          get: readContents,
        });
      }
      const save = vi.fn(async (rows: readonly IndexEntry[]) => rows);
      expect(await b.rows.capture(save, () => {}, [base.scope])).toEqual([
        bound,
      ]);
      expect(save).toHaveBeenCalledOnce();
      expect(readContents).not.toHaveBeenCalled();
      if (b.scopeReads) {
        expect(b.scopeReads).toHaveBeenCalled();
        expect(
          b.scopeReads.mock.calls.every(
            ([options]) => options.scope === base.scope,
          ),
        ).toBe(true);
      }
    });
    it("capture with no bound scopes opens no write transaction", async () => {
      const b = await backend(kind);
      await b.insert(base);
      b.transactions.mockClear();
      const authority = vi.fn();
      const save = vi.fn(async (rows: readonly IndexEntry[]) => rows);
      expect(await b.rows.capture(save, authority, [])).toEqual([]);
      expect(save).toHaveBeenCalledExactlyOnceWith([]);
      expect(b.transactions).not.toHaveBeenCalled();
      // With no rows, Lite must also skip its queued snapshot callback.
      expect(authority).not.toHaveBeenCalled();
    });
    it("keeps a stamped re-add out of the immutable manifest across resume", async () => {
      const b = await backend(kind);
      await b.insert({ ...base, afterTombstoneVersion: 3 });
      const f = fixture(b.rows);
      f.head({ state: "deleted", version: "3" });
      const id = await f.pipeline.capture("github", f.authority);
      expect(
        await f.pipeline.advance(id, f.authority, new AbortController().signal),
      ).toEqual({ state: "done" });
      expect(
        await b.rows.capture(async (rows) => rows.length, f.authority, [
          base.scope,
        ]),
      ).toBe(1);
      expect(await f.pipeline.capture("github", f.authority)).toBe(id);
    });
    it("does not call an absent pin done when erasure was skipped", async () => {
      const b = await backend(kind);
      await b.insert(base);
      const f = fixture({ ...b.rows, erase: async () => {} });
      const id = await f.pipeline.capture("github", f.authority);
      expect(
        await f.pipeline.advance(id, f.authority, new AbortController().signal),
      ).toEqual({ state: "pending" });
      f.ports.rows = b.rows;
      expect(
        await f.pipeline.advance(id, f.authority, new AbortController().signal),
      ).toEqual({ state: "done" });
    });
    it("preserves a replacement identity and settles the captured row", async () => {
      const b = await backend(kind);
      const old = await b.insert(base);
      const f = fixture(b.rows);
      const id = await f.pipeline.capture("github", f.authority);
      const replacement = await b.insert({ ...base, version: 2 });
      expect(replacement.id).not.toBe(old.id);
      expect(
        await f.pipeline.advance(id, f.authority, new AbortController().signal),
      ).toEqual({ state: "done" });
      expect(
        await b.rows.capture(
          async (rows) => rows.map((r) => r.id),
          f.authority,
          [base.scope],
        ),
      ).toEqual([replacement.id]);
      expect(await b.read(replacement)).toMatchObject({ scope: base.scope });
    });
    it("retries after a partial local erase without recapturing", async () => {
      const b = await backend(kind);
      const first = await b.insert(base);
      const second = await b.insert({
        ...base,
        path: base.path.replace("01T", "02T"),
        collectedAt: base.collectedAt.replace("01T", "02T"),
      });
      let calls = 0;
      const f = fixture({
        ...b.rows,
        erase: async (row, check) => {
          if (++calls === 2) throw Error("crash");
          await b.rows.erase(row, check);
        },
      });
      const id = await f.pipeline.capture("github", f.authority);
      await expect(
        f.pipeline.advance(id, f.authority, new AbortController().signal),
      ).rejects.toThrow("crash");
      const remaining = await b.rows.capture(
        async (rows) => rows.map((row) => row.id),
        f.authority,
        [base.scope],
      );
      expect(remaining).toHaveLength(1);
      expect([first.id, second.id]).toContain(remaining[0]);
      f.ports.rows = await b.reopen();
      const restarted = f.restart();
      expect(await restarted.capture("github", f.authority)).toBe(id);
      expect(
        await restarted.advance(id, f.authority, new AbortController().signal),
      ).toEqual({ state: "done" });
    });
    it("revokes between local rows without erasing the next row", async () => {
      const b = await backend(kind);
      await b.insert(base);
      await b.insert({
        ...base,
        path: base.path.replace("01T", "02T"),
        collectedAt: base.collectedAt.replace("01T", "02T"),
      });
      const f = fixture({
        ...b.rows,
        erase: async (row, check) => {
          await b.rows.erase(row, check);
          f.revoke();
        },
      });
      const id = await f.pipeline.capture("github", f.authority);
      await expect(
        f.pipeline.advance(id, f.authority, new AbortController().signal),
      ).rejects.toThrow("revoked");
      expect(
        await b.rows.capture(
          async (rows) => rows.length,
          () => {},
          [base.scope],
        ),
      ).toBe(1);
    });
    it("revokes while waiting for the removal lock and changes nothing later", async () => {
      let entered!: () => void;
      let release!: () => void;
      const waiting = new Promise<void>((resolve) => {
        entered = resolve;
      });
      const hold = new Promise<void>((resolve) => {
        release = resolve;
      });
      const b = await backend(kind, async () => {
        entered();
        await hold;
      });
      const row = await b.insert(base);
      const f = fixture(b.rows);
      const id = await f.pipeline.capture("github", f.authority);
      const running = f.pipeline.advance(
        id,
        f.authority,
        new AbortController().signal,
      );
      await waiting;
      f.revoke();
      release();
      await expect(running).rejects.toThrow("revoked");
      expect(await b.rows.absent([row], () => {})).toBe(false);
    });
    it("persists only eligible retirement row identities", async () => {
      const b = await backend(kind);
      const row = await b.insert({
        ...base,
        dataPointId: "registered",
        version: 2,
      });
      await b.insert({
        ...base,
        collectedAt: "2026-02-01T00:00:00.000Z",
        dataPointId: "newer",
        version: 9,
      });
      const f = fixture(b.rows);
      f.head({ state: "deleted", version: "3" });
      await f.pipeline.capture("github", f.authority);
      const [stored] = await f.db.query<{ manifest: string }>(
        "SELECT manifest FROM legacy_retire_manifests",
      );
      expect(JSON.parse(stored!.manifest).scopes[0].rows).toEqual([
        {
          id: row.id,
          path: row.path,
          scope: row.scope,
          collectedAt: row.collectedAt,
        },
      ]);
    });
    it("blocks a moved head without erasing any captured identity", async () => {
      const b = await backend(kind);
      const row = await b.insert(base);
      const f = fixture(b.rows);
      f.head({ state: "deleted", version: "3" });
      const id = await f.pipeline.capture("github", f.authority);
      f.head({ state: "deleted", version: "4" });
      expect(
        await f.pipeline.advance(id, f.authority, new AbortController().signal),
      ).toEqual({ state: "blocked", reason: "legacy_head_changed" });
      expect(await b.rows.absent([row], f.authority)).toBe(false);
      expect(f.effects).toHaveLength(1);
    });
    it("revokes after the tombstone with no subsequent local or journal effect", async () => {
      const b = await backend(kind);
      await b.insert(base);
      const erase = vi.fn(b.rows.erase);
      const f = fixture({ ...b.rows, erase });
      f.head({
        state: "live",
        fence: { expectedVersion: "2", dataHash: "hash", metadataHash: "meta" },
      });
      const tombstone = f.ports.tombstone;
      f.ports.tombstone = async (...args) => {
        const outcome = await tombstone(...args);
        f.revoke();
        return outcome;
      };
      const id = await f.pipeline.capture("github", f.authority);
      await expect(
        f.pipeline.advance(id, f.authority, new AbortController().signal),
      ).rejects.toThrow("revoked");
      expect(erase).not.toHaveBeenCalled();
      expect(f.effects).toHaveLength(2);
    });
    it("preserves a row replaced between the snapshot and the manifest commit", async () => {
      const b = await backend(kind);
      const old = await b.insert(base);
      const erase = vi.fn(b.rows.erase);
      const f = fixture({ ...b.rows, erase });
      let entered!: () => void;
      let release!: () => void;
      const pending = new Promise<void>((resolve) => {
        entered = resolve;
      });
      const commit = new Promise<void>((resolve) => {
        release = resolve;
      });
      const batch = f.db.batch.bind(f.db);
      f.db.batch = async (statements) => {
        entered();
        await commit;
        return batch(statements);
      };
      const capturing = f.pipeline.capture("github", f.authority);
      await pending;
      expect(
        await f.pipeline.advance(
          "retire-1",
          f.authority,
          new AbortController().signal,
        ),
      ).toEqual({ state: "blocked", reason: "legacy_manifest_missing" });
      expect(erase).not.toHaveBeenCalled();
      expect(f.effects).toHaveLength(0);
      const replacing = b.insert({ ...base, version: 2 });
      try {
        await Promise.race([
          replacing,
          new Promise((_, reject) =>
            setTimeout(
              () => reject(Error("replacement held by manifest commit")),
              500,
            ),
          ),
        ]);
      } finally {
        release();
      }
      const id = await capturing;
      const replacement = await replacing;
      const stored = f.sql
        .prepare("SELECT manifest FROM legacy_retire_manifests")
        .get() as { manifest: string };
      expect(
        JSON.parse(stored.manifest).scopes[0].rows.map(
          (row: IndexEntry) => row.id,
        ),
      ).toEqual([old.id]);
      expect(
        await f.pipeline.advance(id, f.authority, new AbortController().signal),
      ).toEqual({ state: "done" });
      expect(await b.read(replacement)).toMatchObject({ scope: base.scope });
    });
    it("uses the same numeric tombstone match for remote, local and completion checks", async () => {
      const b = await backend(kind);
      await b.insert(base);
      const f = fixture(b.rows);
      f.head({ state: "deleted", version: "3" });
      const id = await f.pipeline.capture("github", f.authority);
      f.head({ state: "deleted", version: "03" });
      expect(
        await f.pipeline.advance(id, f.authority, new AbortController().signal),
      ).toEqual({ state: "done" });
    });

    it("a failed manifest commit leaves no durable intent and retry captures afresh", async () => {
      const b = await backend(kind);
      await b.insert(base);
      const f = fixture(b.rows);
      f.sql.exec(
        "CREATE TRIGGER fail_manifest BEFORE INSERT ON legacy_retire_manifests BEGIN SELECT RAISE(ABORT, 'crash before commit'); END",
      );
      await expect(f.pipeline.capture("github", f.authority)).rejects.toThrow(
        "crash before commit",
      );
      expect(f.sql.prepare("SELECT * FROM legacy_retirements").all()).toEqual(
        [],
      );
      expect(
        f.sql.prepare("SELECT * FROM legacy_retire_manifests").all(),
      ).toEqual([]);
      expect(f.effects).toHaveLength(1);
      const replacement = await b.insert({ ...base, version: 2 });
      f.sql.exec("DROP TRIGGER fail_manifest");
      const id = await f.pipeline.capture("github", f.authority);
      const stored = f.sql
        .prepare("SELECT manifest FROM legacy_retire_manifests")
        .get() as { manifest: string };
      expect(
        JSON.parse(stored.manifest).scopes[0].rows.map(
          (row: IndexEntry) => row.id,
        ),
      ).toEqual([replacement.id]);
      expect(
        await f.pipeline.advance(id, f.authority, new AbortController().signal),
      ).toEqual({ state: "done" });
    });
    it("never recaptures heads, bindings or rows on a repeated request", async () => {
      const b = await backend(kind);
      await b.insert(base);
      const f = fixture(b.rows);
      const id = await f.pipeline.capture("github", f.authority);
      const before = f.sql
        .prepare("SELECT manifest FROM legacy_retire_manifests")
        .get();
      await b.insert({
        ...base,
        path: base.path.replace("01T", "02T"),
        collectedAt: base.collectedAt.replace("01T", "02T"),
      });
      f.head({ state: "deleted", version: "9" });
      f.ports.scopesOf = () => ["another.scope"];
      expect(await f.pipeline.capture("github", f.authority)).toBe(id);
      expect(
        f.sql.prepare("SELECT manifest FROM legacy_retire_manifests").get(),
      ).toEqual(before);
      expect(f.effects).toHaveLength(1);
    });
    it("blocks an old intent with no manifest and never backfills it", async () => {
      const b = await backend(kind);
      const f = fixture(b.rows);
      const id = await f.pipeline.capture("github", f.authority);
      f.sql.exec("DELETE FROM legacy_retire_manifests");
      expect(await f.pipeline.capture("github", f.authority)).toBe(id);
      expect(
        await f.pipeline.advance(id, f.authority, new AbortController().signal),
      ).toEqual({ state: "blocked", reason: "legacy_manifest_missing" });
      expect(f.effects).toHaveLength(1);
    });
    it("revokes between blob receipt batches and never posts the next one", async () => {
      const b = await backend(kind);
      const f = fixture(b.rows);
      f.head({ state: "deleted", version: "3" });
      const id = await f.pipeline.capture("github", f.authority);
      let requests = 0;
      f.ports.eraseBlob = async () => {
        requests++;
        return true;
      };
      const batch = f.db.batch.bind(f.db);
      f.db.batch = async (statements) => {
        const result = await batch(statements);
        f.revoke();
        return result;
      };
      await expect(
        f.pipeline.advance(id, f.authority, new AbortController().signal),
      ).rejects.toThrow("revoked");
      expect(requests).toBe(1);
      expect(f.effects).toHaveLength(2); // capture and the first receipt only
    });
  });
