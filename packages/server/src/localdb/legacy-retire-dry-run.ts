import { createHash } from "node:crypto";
import { constants } from "node:fs";
import {
  open,
  readdir,
  lstat,
  realpath,
  mkdir,
  mkdtemp,
  rm,
} from "node:fs/promises";
import {
  resolve,
  join,
  dirname,
  relative,
  sep,
  basename,
  isAbsolute,
} from "node:path";
import { homedir } from "node:os";
import { createLegacyEraseLedger } from "@opendatalabs/personal-server-ts-core/localdb";
import type { Database } from "better-sqlite3";
import type { DeclarationSnapshot } from "@opendatalabs/personal-server-ts-core/pdpp";
import type {
  LocalSyncDeps,
  LegacyCopy,
  LegacyRetireAccess,
  LegacyRetireOptions,
  LegacyRetireFileReport,
  LegacyRetireReport,
  ImportProjectionDeps,
} from "@opendatalabs/personal-server-ts-core/localdb";
import type { LegacyAccess, LegacyAccessOptions } from "./legacy-access.js";

/** F.2/F.4: caller supplies trusted offline ports; no config parsing. */
export interface LegacyRetireDryRunOptions {
  readonly copyRoot: string;
  readonly scratchRoot: string;
  /** Trusted provenance of absolute intent paths in a byte copy. Defaults to
   * the copied legacy store root. This path is mapped, never opened. */
  readonly originalStoreRoot?: string;
  readonly owner: string;
  readonly network: string;
  readonly declarations: readonly DeclarationSnapshot[];
  readonly importProjection: LegacyAccessOptions["importProjection"];
  readonly isSwitched: LegacyAccessOptions["isSwitched"];
  readonly verifyBinding: LegacyAccessOptions["verifyBinding"];
  readonly legacyWriteSeal: LegacyAccessOptions["legacyWriteSeal"];
  readonly isQuiescent: LegacyAccessOptions["isQuiescent"];
  readonly resolveTarget: LegacyAccessOptions["resolveTarget"];
  /** Relative to copyRoot; two distinct files. Never guess that legacy index.db
   * has localdb db_meta/receipts. Reject traversal, symlinks, WAL/SHM inputs. */
  readonly localDatabasePath: string;
  readonly legacyDatabasePath: string;
  /** Open only the scratch copies. Native legacy handle is separate from the
   * SqlDriver in deps; close owns both, including partial-open rollback. */
  readonly openScratch: (paths: {
    localDatabasePath: string;
    legacyDatabasePath: string;
  }) => Promise<{
    deps: LocalSyncDeps;
    legacyDb: Database;
    close(): Promise<void>;
  }>;
  readonly openAccess: (options: LegacyAccessOptions) => Promise<LegacyAccess>;
  /** Caller composes fresh read-back with immutable peer sources and copyRecords.
   * This capability cannot erase. All SQL reads use scratch deps. */
  readonly readBack: (
    deps: ImportProjectionDeps,
    access: Pick<
      LegacyAccess,
      "owner" | "network" | "sources" | "copies" | "copyRecords"
    >,
  ) => LegacyRetireAccess["readBack"];
  readonly retire: (
    deps: LocalSyncDeps,
    access: LegacyRetireAccess,
    options: LegacyRetireOptions,
  ) => Promise<LegacyRetireReport>;
  readonly reportFile: (report: LegacyRetireFileReport) => void;
}

/**
 * Byte-copy only, never live user data. Hash input tree before/after; all
 * mutation, including retireReplication, is on scratch. Invoke retire with
 * dryRun:true and an erase port that refuses. Never import, publish, refresh
 * registry or persist proof status. Close all acquired handles on every exit.
 */
export async function runLegacyRetireDryRun(
  options: LegacyRetireDryRunOptions,
): Promise<LegacyRetireReport> {
  const allowed = resolve(homedir(), ".tmp") + sep;
  const input = resolve(options.copyRoot);
  const scratchRoot = resolve(options.scratchRoot);
  if (
    !input.startsWith(allowed) ||
    !scratchRoot.startsWith(allowed) ||
    input === scratchRoot ||
    scratchRoot.startsWith(input + sep)
  )
    throw new Error("dry_run_copy_required");
  if ((await realpath(input)) !== input)
    throw new Error("dry_run_symlink_refused");
  // Resolve an existing ancestor before mkdir can follow a symlink.
  let ancestor = scratchRoot;
  for (;;) {
    try {
      if ((await realpath(ancestor)) !== ancestor)
        throw new Error("dry_run_symlink_refused");
      break;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      ancestor = dirname(ancestor);
    }
  }
  if (
    !(await options.isSwitched(options.owner)) ||
    !(await options.isQuiescent())
  )
    throw new Error("dry_run_not_quiescent");
  const local = relativeFile(input, options.localDatabasePath);
  const legacy = relativeFile(input, options.legacyDatabasePath);
  if (local === legacy || basename(legacy) !== "index.db")
    throw new Error("dry_run_ambiguous_layout");
  if (!(await lstat(local)).isFile() || !(await lstat(legacy)).isFile())
    throw new Error("dry_run_ambiguous_layout");
  const before = await treeFingerprint(input);
  await mkdir(scratchRoot, { recursive: true });
  const scratch = await mkdtemp(join(scratchRoot, "legacy-dry-run-"));
  let opened:
    Awaited<ReturnType<LegacyRetireDryRunOptions["openScratch"]>> | undefined;
  let access: LegacyAccess | undefined;
  try {
    for await (const file of walk(input)) {
      const target = join(scratch, relative(input, file.path));
      if (file.directory) {
        await mkdir(target, { recursive: true });
        continue;
      }
      await mkdir(dirname(target), { recursive: true });
      const source = await open(
        file.path,
        constants.O_RDONLY | constants.O_NOFOLLOW,
      );
      let dest: Awaited<ReturnType<typeof open>> | undefined;
      try {
        dest = await open(target, "wx", 0o600);
        for await (const chunk of source.createReadStream({
          autoClose: false,
        })) {
          let offset = 0;
          while (offset < chunk.length) {
            const written = await dest.write(
              chunk,
              offset,
              chunk.length - offset,
              null,
            );
            if (!written.bytesWritten) throw new Error("dry_run_copy_failed");
            offset += written.bytesWritten;
          }
        }
      } finally {
        try {
          await source.close();
        } finally {
          await dest?.close();
        }
      }
    }
    if ((await treeFingerprint(input)) !== before)
      throw new Error("dry_run_input_changed");
    opened = await options.openScratch({
      localDatabasePath: join(scratch, relative(input, local)),
      legacyDatabasePath: join(scratch, relative(input, legacy)),
    });
    const [meta] = await opened.deps.db.query<{
      owner: string;
      network: string;
    }>("SELECT owner, network FROM db_meta WHERE id = 1");
    if (
      meta?.owner !== options.owner.toLowerCase() ||
      meta.owner !== opened.deps.ownerAddress.toLowerCase() ||
      meta.network !== options.network
    )
      throw new Error("dry_run_identity_mismatch");
    const unavailable = async (): Promise<never> => {
      throw new Error("dry_run_external_capability_refused");
    };
    const deps: ImportProjectionDeps = {
      ...opened.deps,
      importProjection: options.importProjection,
      registry: {
        read: unavailable,
        post: unavailable,
        listControlRows: unavailable,
        listStreamRows: unavailable,
      },
      blobs: { get: unavailable, put: unavailable },
      keys: {
        namespaceHmac: unavailable,
        encrypt: unavailable,
        encryptPart: unavailable,
        decrypt: unavailable,
      },
      signer: { signAddData: unavailable },
    };
    const scratchStoreRoot = dirname(join(scratch, relative(input, legacy)));
    const originalStoreRoot = resolve(
      options.originalStoreRoot ?? dirname(legacy),
    );
    const journal = createLegacyEraseLedger(deps.db, deps.now);
    const rebaseIntent = (copy: LegacyCopy, from: string, to: string) => {
      const path = resolve(copy.path);
      const suffix = relative(from, path);
      if (
        !isAbsolute(copy.path) ||
        !suffix ||
        suffix === ".." ||
        suffix.startsWith(".." + sep) ||
        isAbsolute(suffix)
      )
        throw new Error("dry_run_intent_path_refused");
      return { ...copy, path: resolve(to, suffix) };
    };
    access = await options.openAccess({
      db: opened.legacyDb,
      root: dirname(join(scratch, relative(input, legacy))),
      owner: options.owner,
      network: options.network,
      declarations: options.declarations,
      importProjection: options.importProjection,
      isSwitched: options.isSwitched,
      isQuiescent: options.isQuiescent,
      verifyBinding: options.verifyBinding,
      legacyWriteSeal: options.legacyWriteSeal,
      // Rebase only the copy's read capability. Never rewrite the input
      // journal, and never grant journal mutation to a dry-run access adapter.
      eraseLedger: {
        belongsTo: (owner, network) => journal.belongsTo(owner, network),
        has: (copy) =>
          journal.has(rebaseIntent(copy, scratchStoreRoot, originalStoreRoot)),
        async *pending() {
          for await (const copy of journal.pending())
            yield rebaseIntent(copy, originalStoreRoot, scratchStoreRoot);
        },
        record: async () => {
          throw new Error("dry_run_erase_refused");
        },
        finish: async () => {
          throw new Error("dry_run_erase_refused");
        },
      },
      resolveTarget: options.resolveTarget,
    });
    const readOnly = {
      owner: access.owner,
      network: access.network,
      sources: access.sources.bind(access),
      copies: access.copies.bind(access),
      copyRecords: access.copyRecords.bind(access),
    };
    const readBack = options.readBack(deps, readOnly);
    return await options.retire(
      deps,
      {
        copies: access.copies.bind(access),
        readBack,
        erase: async () => {
          throw new Error("dry_run_erase_refused");
        },
      },
      { dryRun: true, reportFile: options.reportFile },
    );
  } finally {
    try {
      await access?.close();
    } finally {
      try {
        await opened?.close();
      } finally {
        await rm(scratch, { recursive: true, force: true });
        if ((await treeFingerprint(input)) !== before)
          throw new Error("dry_run_input_changed");
      }
    }
  }
}

function relativeFile(root: string, path: string) {
  const result = resolve(root, path);
  if (!path || path.startsWith(sep) || !result.startsWith(root + sep))
    throw new Error("dry_run_ambiguous_layout");
  return result;
}
async function* walk(
  root: string,
): AsyncIterable<{ path: string; directory: boolean }> {
  const entries = await readdir(root, { withFileTypes: true });
  entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  for (const entry of entries) {
    const path = join(root, entry.name);
    if (entry.isSymbolicLink()) throw new Error("dry_run_symlink_refused");
    if (/-(wal|shm|journal)$/.test(entry.name))
      throw new Error("dry_run_live_database_refused");
    if (entry.isDirectory()) {
      yield { path, directory: true };
      yield* walk(path);
    } else if (entry.isFile()) yield { path, directory: false };
    else throw new Error("dry_run_special_file_refused");
  }
}
async function treeFingerprint(root: string) {
  const hash = createHash("sha256");
  for await (const entry of walk(root)) {
    const name = Buffer.from(relative(root, entry.path));
    const length = Buffer.alloc(4);
    length.writeUInt32BE(name.length);
    hash
      .update(entry.directory ? "directory" : "file")
      .update(length)
      .update(name);
    if (!entry.directory) {
      const file = await open(
        entry.path,
        constants.O_RDONLY | constants.O_NOFOLLOW,
      );
      try {
        const body = createHash("sha256");
        for await (const chunk of file.createReadStream({ autoClose: false }))
          body.update(chunk);
        hash.update(body.digest());
      } finally {
        await file.close();
      }
    }
  }
  return hash.digest("hex");
}
