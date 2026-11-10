import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { open, opendir, lstat, realpath, unlink } from "node:fs/promises";
import { resolve, join, relative, dirname, sep } from "node:path";
import { canonicalJson } from "@opendatalabs/personal-server-ts-stream-sync";
import { withScopeLock } from "@opendatalabs/personal-server-ts-core/additions";
import { retireReplication } from "../storage/pdpp-replication-door.js";
import { openRecordStore } from "../pdpp/records-bootstrap.js";
import { createIndexManager } from "../storage/index-manager.js";
import {
  createCanonicalImportSource,
  type CanonicalImportPageReader,
} from "./canonical-import-source.js";
import type { LegacyWriteSeal } from "@opendatalabs/personal-server-ts-core/storage/legacy-write-seal";
import type { DeclarationSnapshot } from "@opendatalabs/personal-server-ts-core/pdpp";
import type { Database } from "better-sqlite3";
import type {
  ImportInventoryEntry,
  LegacyCopy,
  ImportTarget,
  LegacyEraseLedger,
  ImportProjectionPort,
} from "@opendatalabs/personal-server-ts-core/localdb";

/** F.4: scoped to the verified switched owner and the same local database/network. */
export interface LegacyAccessOptions {
  readonly importProjection: ImportProjectionPort;
  /** Borrowed native handle for root/index.db, NOT LocalSyncDeps.db. */
  readonly db: Database;
  readonly eraseLedger: LegacyEraseLedger;
  /** Existing authenticated connection resolver; null excludes the source from import. */
  readonly resolveTarget: (
    sourceId: string,
    instance: string,
    stream: string,
  ) => Promise<ImportTarget | null>;
  /** Legacy index.db has no owner/network db_meta. Caller must bind the open
   * handle and canonical root to authenticated owner/network before any read
   * or retireReplication effect. Missing/false evidence refuses access.
   * Do not create identity metadata or trust copied config as authority. */
  readonly verifyBinding: (binding: {
    db: Database;
    owner: string;
    network: string;
    root: string;
  }) => Promise<boolean>;
  readonly owner: string;
  readonly network: string;
  /** Re-read trusted mode; unknown/off refuse before opening any store. */
  readonly isSwitched: (owner: string) => Promise<boolean>;
  readonly root: string;
  readonly declarations: readonly DeclarationSnapshot[];
  /** Existing storage removal authority; no new parallel lock/seal. */
  readonly legacyWriteSeal: LegacyWriteSeal;
  /** All legacy writers must be quiescent for the lifetime of this access.
   * Caller owns stopping them; false refuses before reads or door retirement. */
  readonly isQuiescent: () => Promise<boolean>;
}

/** F.4: all access to a switched owner's legacy index.db, including erase, passes here. */
export interface LegacyAccess {
  readonly owner: string;
  readonly network: string;
  /** Includes descriptors with exclusions for unmapped data; never silently omit a store. */
  sources(): AsyncIterable<ImportInventoryEntry>;
  copies(): AsyncIterable<LegacyCopy>;
  erase(copy: LegacyCopy): Promise<boolean>;
  erasedWithIntent(copy: LegacyCopy): Promise<boolean>;
  finishErase(copy: LegacyCopy): Promise<void>;
  close(): Promise<void>;
}

/**
 * F.4: verify db owner/root first; retireReplication(db) BEFORE reads or erases,
 * then openRecordStore(db,false). No replica wrappers, even when env enables
 * replication. Door stays closed. Must not close caller-owned db in close().
 * All raw SQL and file access for switched legacy stores is private here.
 * Inventory root/data using hierarchy's finalized-envelope layout and index
 * entries (including orphan/unmapped files); pending stages/blocks/sidecars
 * are counted with the remaining old files. Reject symlinks and paths outside root.
 * Read/hash exact bytes with SHA-256. Erase uses withScopeLock(scope, work)
 * and legacyWriteSeal.remove, matching node-data-storage; these are not
 * reentrant: do not call a storage delete method while holding the same lock.
 * Writer quiescence must precede the snapshot and include sync/download sinks.
 * Missing trustworthy binding or quiescence refuses; root path is not identity.
 */
export async function openLegacyAccess(
  options: LegacyAccessOptions,
): Promise<LegacyAccess> {
  const { db, owner, network, eraseLedger } = options;
  if (!(await options.isSwitched(owner)) || !(await options.isQuiescent()))
    throw new Error("legacy_access_unavailable");
  const root = await realpath(options.root);
  if (
    root !== resolve(options.root) ||
    (await realpath(db.name)) !== join(root, "index.db") ||
    !(await options.verifyBinding({ db, owner, network, root })) ||
    !(await eraseLedger.belongsTo(owner, network))
  )
    throw new Error("legacy_identity_mismatch");
  const indexIdentity = await lstat(join(root, "index.db"));
  const dataRoot = join(root, "data");
  if ((await realpath(dataRoot)) !== dataRoot)
    throw new Error("legacy_path_refused");
  retireReplication(db);
  const store = openRecordStore(db, false);
  const index = createIndexManager(db);
  let closed = false;
  async function authorized() {
    if (
      closed ||
      !(await options.isSwitched(owner)) ||
      !(await options.isQuiescent()) ||
      !(await options.verifyBinding({ db, owner, network, root })) ||
      !(await eraseLedger.belongsTo(owner, network))
    )
      throw new Error("legacy_access_unavailable");
    const identity = await lstat(join(root, "index.db"));
    if (
      identity.isSymbolicLink() ||
      identity.dev !== indexIdentity.dev ||
      identity.ino !== indexIdentity.ino ||
      (await realpath(root)) !== root ||
      (await realpath(dataRoot)) !== dataRoot
    )
      throw new Error("legacy_identity_mismatch");
  }
  // Revision identifies content, not a device's coincidentally equal clock.
  // The clock/data_version are live fences only and never durable identity.
  const dataVersion = db.pragma("data_version", { simple: true }) as number;
  const clock = store.transitionWriteClock();
  const hash = createHash("sha256").update("legacy-canonical-snapshot/1");
  const frame = (value: unknown) => {
    const bytes = Buffer.from(canonicalJson(value));
    const size = Buffer.alloc(4);
    size.writeUInt32BE(bytes.length);
    hash.update(size).update(bytes);
  };
  let bindingAfter: string | null = null;
  for (;;) {
    const row = db
      .prepare(
        "SELECT * FROM pdpp_instance_binding WHERE (? IS NULL OR instance > ?) ORDER BY instance LIMIT 1",
      )
      .get(bindingAfter, bindingAfter) as Record<string, unknown> | undefined;
    if (!row) break;
    frame(row);
    bindingAfter = row.instance as string;
  }
  let prior: [string, string, string] | null = null;
  for (;;) {
    const row = db
      .prepare(
        `SELECT instance,stream,record_key,length(CAST(data AS BLOB)) AS bytes FROM pdpp_records
      WHERE deleted = 0 AND (? IS NULL OR (instance,stream,record_key) > (?,?,?)) ORDER BY instance,stream,record_key LIMIT 1`,
      )
      .get(
        prior?.[0] ?? null,
        prior?.[0] ?? null,
        prior?.[1] ?? null,
        prior?.[2] ?? null,
      ) as
      | { instance: string; stream: string; record_key: string; bytes: number }
      | undefined;
    if (!row) break;
    frame([row.instance, row.stream, row.record_key, row.bytes]);
    for (let offset = 0; offset < row.bytes; offset += 65536) {
      const chunk = db
        .prepare(
          "SELECT substr(CAST(data AS BLOB),?,65536) AS bytes FROM pdpp_records WHERE instance = ? AND stream = ? AND record_key = ?",
        )
        .get(offset + 1, row.instance, row.stream, row.record_key) as {
        bytes: Buffer;
      };
      hash.update(chunk.bytes);
    }
    prior = [row.instance, row.stream, row.record_key];
  }
  const revision = hash.digest("hex");
  const reader: CanonicalImportPageReader = {
    declarations: options.declarations,
    async assertRevision(expected) {
      await authorized();
      if (
        expected !== revision ||
        store.transitionWriteClock() !== clock ||
        db.pragma("data_version", { simple: true }) !== dataVersion
      )
        throw new Error("source_changed");
    },
    async *inventory(expected) {
      await reader.assertRevision(expected);
      let instance: string | null = null;
      let stream = "";
      for (;;) {
        await reader.assertRevision(expected);
        const row = db
          .prepare(
            `SELECT p.instance, p.stream, b.source_id AS sourceId, count(*) AS rows
          FROM pdpp_records p LEFT JOIN pdpp_instance_binding b ON b.instance = p.instance
          WHERE p.deleted = 0 AND (? IS NULL OR p.instance > ? OR (p.instance = ? AND p.stream > ?))
          GROUP BY p.instance,p.stream ORDER BY p.instance,p.stream LIMIT 1`,
          )
          .get(instance, instance, instance, stream) as
          | {
              instance: string;
              stream: string;
              sourceId: string | null;
              rows: number;
            }
          | undefined;
        if (!row) break;
        instance = row.instance;
        stream = row.stream;
        yield row;
      }
      // A verified stream with a known connection can be fetched-empty. Keep
      // that distinct from a missing peer, without hiding undeclared storage.
      for (const declaration of options.declarations)
        for (const connection of store.listConnections(declaration.source_id))
          for (const stream of declaration.streams) {
            const row = db
              .prepare(
                "SELECT count(*) AS n FROM pdpp_records WHERE instance = ? AND stream = ? AND deleted = 0",
              )
              .get(connection.instance, stream.name) as { n: number };
            if (!row.n)
              yield {
                instance: connection.instance,
                stream: stream.name,
                sourceId: declaration.source_id,
                rows: 0,
              };
          }
      await reader.assertRevision(expected);
    },
    async connections(sourceId) {
      await authorized();
      return store.listConnections(sourceId).map((c) => ({
        instance: c.instance,
        deleted: c.deletedAt !== null,
        lastActive: Math.max(
          0,
          ...store
            .listStreams([c.instance])
            .map((s) => (s.lastUpdated ? Date.parse(s.lastUpdated) : 0)),
        ),
      }));
    },
    async page(instance, stream, after, limit, maxBytes, expected) {
      await reader.assertRevision(expected);
      const rows: Record<string, unknown>[] = [];
      let cursor = after;
      let bytes = 0;
      const metadata = db.prepare(
        "SELECT record_key, length(CAST(data AS BLOB)) AS bytes, length(CAST(record_key AS BLOB)) AS keyBytes FROM pdpp_records WHERE instance = ? AND stream = ? AND deleted = 0 AND (? IS NULL OR record_key > ?) ORDER BY record_key LIMIT 1",
      );
      while (rows.length < limit) {
        const next = metadata.get(instance, stream, cursor, cursor) as
          { record_key: string; bytes: number; keyBytes: number } | undefined;
        if (!next) return { rows, next: null };
        if (rows.length && bytes + next.bytes + next.keyBytes > maxBytes)
          return { rows, next: cursor };
        const row = db
          .prepare(
            "SELECT data FROM pdpp_records WHERE instance = ? AND stream = ? AND record_key = ? AND deleted = 0",
          )
          .get(instance, stream, next.record_key) as { data: string };
        let value: Record<string, unknown>;
        try {
          const parsed: unknown = JSON.parse(row.data);
          if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
            throw new Error();
          value = parsed as Record<string, unknown>;
        } catch {
          throw new Error("invalid_record");
        }
        rows.push(value);
        bytes += next.bytes + next.keyBytes;
        cursor = next.record_key;
      }
      const more = metadata.get(instance, stream, cursor, cursor);
      await reader.assertRevision(expected);
      return { rows, next: more ? cursor : null };
    },
  };
  const sources = () =>
    createCanonicalImportSource({
      owner,
      network,
      revision,
      bindings: options.importProjection.bindings,
      reader,
      resolveTarget: options.resolveTarget,
    });
  async function safePath(path: string, missing = false) {
    const absolute = resolve(path);
    if (!absolute.startsWith(dataRoot + sep))
      throw new Error("legacy_path_refused");
    const parent = await realpath(dirname(absolute));
    if (
      parent !== dirname(absolute) ||
      (!parent.startsWith(dataRoot + sep) && parent !== dataRoot)
    )
      throw new Error("legacy_path_refused");
    try {
      const info = await lstat(absolute);
      if (info.isSymbolicLink() || !info.isFile())
        throw new Error("legacy_path_refused");
    } catch (error) {
      if (!(missing && (error as NodeJS.ErrnoException).code === "ENOENT"))
        throw error;
    }
    return absolute;
  }
  async function read(path: string) {
    await authorized();
    await safePath(path);
    const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const info = await file.stat();
      if (!info.isFile()) throw new Error("legacy_path_refused");
      const hash = createHash("sha256");
      for await (const chunk of file.createReadStream({ autoClose: false }))
        hash.update(chunk);
      const contentHash = hash.digest("hex");
      return { contentHash };
    } finally {
      await file.close();
    }
  }
  async function describe(path: string): Promise<LegacyCopy> {
    const { contentHash } = await read(path);
    const entry = index.findByPath(relative(dataRoot, path));
    const dataSet = entry?.scope ?? "";
    const binding = options.importProjection.bindings.get(dataSet);
    const dependencies: LegacyCopy["sources"][number][] = [];
    let excluded = false;
    if (entry && binding) {
      const selected: Exclude<ImportInventoryEntry, { kind: "excluded" }>[] =
        [];
      for await (const candidate of sources()) {
        if (
          !("kind" in candidate) &&
          candidate.target.connector === binding.connector &&
          binding.streams.includes(candidate.target.stream)
        ) {
          if (
            selected.some((s) => s.target.stream === candidate.target.stream)
          ) {
            excluded = true;
            continue;
          }
          selected.push(candidate);
        }
      }
      const identities = new Set(selected.map((s) => s.source));
      for await (const candidate of sources())
        if ("kind" in candidate && identities.has(candidate.source))
          excluded = true;
      for (const stream of binding.streams) {
        const matches = selected.filter((s) => s.target.stream === stream);
        if (matches.length !== 1) {
          excluded = true;
          break;
        }
        const selectedSource = matches[0]!;
        dependencies.push({
          source: selectedSource.source,
          connectionId: selectedSource.target.connectionId,
          stream,
        });
      }
    }
    return {
      id: createHash("sha256")
        .update(canonicalJson([path, entry?.id ?? null]))
        .digest("hex"),
      path,
      contentHash,
      revision,
      dataSet,
      sources: excluded ? [] : dependencies,
    };
  }
  async function* files(dir: string): AsyncIterable<string> {
    for await (const entry of await opendir(dir)) {
      const path = join(dir, entry.name);
      if (entry.isSymbolicLink()) throw new Error("legacy_path_refused");
      if (entry.isDirectory()) yield* files(path);
      else if (entry.isFile()) yield path;
    }
  }
  const sameCopy = (a: LegacyCopy, b: LegacyCopy) =>
    a.id === b.id && a.path === b.path && a.contentHash === b.contentHash;
  async function erasedWithIntent(copy: LegacyCopy) {
    await authorized();
    await safePath(copy.path, true);
    return withScopeLock(copy.dataSet, async () => {
      await authorized();
      if (!(await eraseLedger.has(copy))) return false;
      const entry = index.findByPath(relative(dataRoot, copy.path));
      if (
        entry &&
        createHash("sha256")
          .update(canonicalJson([copy.path, entry.id]))
          .digest("hex") !== copy.id
      )
        return false;
      try {
        await lstat(copy.path);
        return false;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
        return true;
      }
    });
  }
  return {
    owner,
    network,
    sources,
    async *copies() {
      await authorized();
      for await (const path of files(dataRoot)) yield await describe(path);
      // Missing indexed files without intent are inventory too. They have no
      // known content hash and cannot authorize reconciliation or removal.
      let after = 0;
      for (;;) {
        const row = db
          .prepare(
            "SELECT id,path,scope FROM data_files WHERE id > ? ORDER BY id LIMIT 1",
          )
          .get(after) as
          { id: number; path: string; scope: string } | undefined;
        if (!row) break;
        after = row.id;
        const path = resolve(dataRoot, row.path);
        if (!path.startsWith(dataRoot + sep))
          throw new Error("legacy_path_refused");
        try {
          await lstat(path);
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
          let known = false;
          for await (const pending of eraseLedger.pending())
            if (pending.path === path) {
              known = true;
              break;
            }
          if (!known)
            yield {
              id: createHash("sha256")
                .update(canonicalJson([path, row.id]))
                .digest("hex"),
              path,
              contentHash: "",
              revision,
              dataSet: row.scope,
              sources: [],
            };
        }
      }
      // Pending identities survive unlink-before-receipt crashes. Replacements
      // are enumerated from disk above and cannot borrow an old intent.
      for await (const copy of eraseLedger.pending()) {
        await safePath(copy.path, true);
        try {
          await lstat(copy.path);
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code === "ENOENT") yield copy;
          else throw error;
        }
      }
    },
    async erase(copy) {
      await authorized();
      await safePath(copy.path, true);
      return withScopeLock(copy.dataSet, () =>
        options.legacyWriteSeal.remove(async () => {
          await authorized();
          let current: LegacyCopy;
          try {
            const { contentHash } = await read(copy.path);
            const entry = index.findByPath(relative(dataRoot, copy.path));
            current = {
              ...copy,
              contentHash,
              id: createHash("sha256")
                .update(canonicalJson([copy.path, entry?.id ?? null]))
                .digest("hex"),
            };
          } catch (error) {
            if ((error as NodeJS.ErrnoException).code === "ENOENT")
              return false;
            throw error;
          }
          if (!sameCopy(copy, current)) return false;
          await eraseLedger.record(copy);
          // Recheck after the journal commit; an old descriptor never grants a
          // second removal. No gateway call or legacy tombstone is involved.
          const { contentHash } = await read(copy.path);
          const entry = index.findByPath(relative(dataRoot, copy.path));
          const id = createHash("sha256")
            .update(canonicalJson([copy.path, entry?.id ?? null]))
            .digest("hex");
          if (contentHash !== copy.contentHash || id !== copy.id) return false;
          await unlink(copy.path);
          index.deleteByPath(relative(dataRoot, copy.path));
          return true;
        }),
      );
    },
    erasedWithIntent,
    async finishErase(copy) {
      await authorized();
      await safePath(copy.path, true);
      await withScopeLock(copy.dataSet, () =>
        options.legacyWriteSeal.remove(async () => {
          await authorized();
          if (!(await eraseLedger.has(copy)))
            throw new Error("erase_intent_missing");
          try {
            await lstat(copy.path);
            throw new Error("copy_changed");
          } catch (error) {
            if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
          }
          // The index and intent live in separate databases. Atomically check and
          // remove the exact index row first; retain intent until that commit.
          // A crash between commits is safe to retry with an already-absent row.
          db.transaction(() => {
            const entry = index.findByPath(relative(dataRoot, copy.path));
            if (entry) {
              const id = createHash("sha256")
                .update(canonicalJson([copy.path, entry.id]))
                .digest("hex");
              if (id !== copy.id || entry.scope !== copy.dataSet)
                throw new Error("copy_changed");
              index.deleteByPath(relative(dataRoot, copy.path));
            }
          }).immediate();
          await eraseLedger.finish(copy);
        }),
      );
    },
    async close() {
      closed = true;
    },
  };
}
