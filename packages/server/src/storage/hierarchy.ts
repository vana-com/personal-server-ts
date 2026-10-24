import {
  access,
  open,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import {
  createReadStream,
  closeSync,
  existsSync,
  fsyncSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  rmdirSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { Readable } from "node:stream";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import { createHash, randomUUID } from "node:crypto";
import {
  DataFileEnvelopeSchema,
  scopeToPathSegments,
  type DataFileEnvelope,
} from "@opendatalabs/vana-sdk/browser";
import {
  buildDataFilePath,
  buildScopeDir,
  canonicalJson,
  envelopeGeneration,
  filenameToTimestamp,
  type HierarchyManagerOptions,
  type WriteResult,
} from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import {
  DataBlockStorageError,
  readManifestScopeBlocks,
  type DataBlockManifest,
  type DataScopeBlock,
  type ReadScopeBlocksResponse,
} from "@opendatalabs/personal-server-ts-core/storage/blocks";
import { hasPdppOrigin } from "@opendatalabs/personal-server-ts-core/sync";
import { previewJsonEnvelopePrefix } from "@opendatalabs/personal-server-ts-core/storage/preview";
import { ProtocolError } from "@opendatalabs/personal-server-ts-core/errors";

function syncDirectory(path: string): void {
  if (process.platform === "win32") return;
  const fd = openSync(path, "r");
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

/*
 * Retained version files.
 *
 * A retained legacy version (`legacy_publication_retained_versions`) is
 * immutable in every policy state, including mirroring after rollback and
 * with the gate flag off. This module owns every file effect under a data
 * directory, so it enforces that rule itself for every caller, from the
 * actual absolute path of each effect: any options object, any scope mapping
 * and path-only calls reach the same rule. It needs no database handle:
 * sealing writes a durable identity record per retained file set into the
 * data root, and every effect reads those records synchronously, right
 * before it happens and again right after it.
 *
 * Records live under `<dataDir>/.legacy-retained/` and are never replaced or
 * removed:
 * - `<envelope path>.retained`: `{ kind: "envelope", sha256 }`, for the
 *   indexed path and for the path the version's scope and time name;
 * - `blocks/<scope dirs>/<collectedAt>.retained`: `{ kind: "blocks", files }`,
 *   where `files` maps each sidecar file name to its SHA-256, or is `"absent"`
 *   (no sidecar existed when sealed) or `"unknown"`.
 *
 * Rules:
 * - nothing removes, replaces or renames a retained file, a directory that
 *   holds one or a data root; a publisher never consumes a retained file as
 *   its stage; nothing creates a file or directory inside a retained set;
 * - the same bytes over an existing retained file are a no-op;
 * - a missing retained file is created only from bytes with its recorded
 *   SHA-256. Without one (`sha256: null`, an absent or unknown sidecar) it
 *   stays missing. Equal content in other bytes is not the same file.
 * Refusals are `409 legacy_history_retained`, before any lasting effect.
 *
 * Races: sealing re-reads the files after writing their records and fails if
 * they changed. A removal first moves the path aside and checks again; a
 * creation checks again after it links. So a seal and a mutation that
 * overlap, in this or another process, end with the seal failed or the
 * mutation undone, never with sealed bytes removed or replaced. A crash inside
 * that window can leave a moved-aside file (`.retiring.*`) or an extra link,
 * never a deleted retained byte.
 */
const RETAINED_DIR = ".legacy-retained";
const RETAINED_SUFFIX = ".retained";

type RetainedIdentity =
  | { kind: "envelope"; sha256: string | null }
  | { kind: "blocks"; files: Record<string, string> | "absent" | "unknown" }
  | { kind: "unknown" };

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function retainedRefusal(): never {
  throw new ProtocolError(
    409,
    "legacy_history_retained",
    "A retained legacy version is immutable; only its recorded bytes can restore a missing file",
  );
}

function missingPath(error: unknown): boolean {
  const code = (error as NodeJS.ErrnoException).code;
  return code === "ENOENT" || code === "ENOTDIR";
}

/** `path` with the symbolic links of its existing ancestors resolved. A link
 * at `path` itself stays: it is what an effect at `path` changes. */
function realTarget(path: string): string {
  const absolute = resolve(path);
  const rest = [basename(absolute)];
  for (let current = dirname(absolute); ; current = dirname(current)) {
    try {
      return join(realpathSync(current), ...rest);
    } catch (error) {
      if (!missingPath(error)) throw error;
      if (dirname(current) === current) return absolute;
      rest.unshift(basename(current));
    }
  }
}

/** Whether a retention path exists. Only a proven absence (ENOENT, ENOTDIR)
 * is false: an unreadable path throws, so it never reads as unretained. */
function markerExists(path: string): boolean {
  try {
    lstatSync(path);
    return true;
  } catch (error) {
    if (missingPath(error)) return false;
    throw error;
  }
}

function readRetainedIdentity(record: string): RetainedIdentity {
  try {
    const identity = JSON.parse(readFileSync(record, "utf8")) as {
      kind?: unknown;
    };
    if (identity.kind === "envelope" || identity.kind === "blocks")
      return identity as RetainedIdentity;
  } catch {
    // An unreadable record still marks its files retained, identity unknown.
  }
  return { kind: "unknown" };
}

/**
 * The retained file set `path` belongs to, with the path's name inside it
 * (`""` for the set itself), or whether `path` is a directory above retained
 * files of a data root that encloses it. Every data root above `path` is
 * consulted; a path inside the records themselves is refused.
 */
function retainedAt(path: string): {
  version?: { identity: RetainedIdentity; inner: string };
  holds: boolean;
} {
  const target = realTarget(path);
  let holds = false;
  for (let root = dirname(target); ; root = dirname(root)) {
    if (markerExists(join(root, RETAINED_DIR))) {
      const segments = relative(root, target).split(sep);
      if (segments[0] === RETAINED_DIR) retainedRefusal();
      for (let i = 1; i <= segments.length; i++) {
        const record =
          join(root, RETAINED_DIR, ...segments.slice(0, i)) + RETAINED_SUFFIX;
        if (markerExists(record))
          return {
            version: {
              identity: readRetainedIdentity(record),
              inner: segments.slice(i).join(sep),
            },
            holds: false,
          };
      }
      if (markerExists(join(root, RETAINED_DIR, ...segments))) holds = true;
    }
    if (dirname(root) === root) return { holds };
  }
}

/** Whether the tree at `path` contains a data root's records. Links are not
 * followed, as removal does not follow them. */
function containsRetainedRoot(path: string): boolean {
  let entries;
  try {
    entries = readdirSync(path, { withFileTypes: true });
  } catch (error) {
    if (missingPath(error)) return false;
    throw error;
  }
  return entries.some(
    (entry) =>
      entry.name === RETAINED_DIR ||
      (entry.isDirectory() && containsRetainedRoot(join(path, entry.name))),
  );
}

/** Refuse creating a file or directory at `path` when it is, or is inside, a
 * retained file set. Restoring a missing retained file uses `linkNewSync`. */
function assertCreatable(path: string): void {
  if (retainedAt(path).version) retainedRefusal();
}

/** Refuse removing, replacing or moving `path`, now at `physical`, when it is
 * or holds retained files or a data root. */
function assertRemovable(path: string, physical = path): void {
  const at = retainedAt(path);
  if (at.version || at.holds || containsRetainedRoot(physical))
    retainedRefusal();
}

function recordedBytes(
  { identity, inner }: { identity: RetainedIdentity; inner: string },
  candidate: Buffer,
): boolean {
  if (identity.kind === "envelope")
    return (
      inner === "" &&
      !!identity.sha256 &&
      sha256Hex(candidate) === identity.sha256
    );
  return (
    identity.kind === "blocks" &&
    typeof identity.files === "object" &&
    inner !== "" &&
    !inner.includes(sep) &&
    Object.hasOwn(identity.files, inner) &&
    identity.files[inner] === sha256Hex(candidate)
  );
}

/**
 * Admit `bytes` as the file at `path`: `"free"` when no retained version owns
 * the path, `"same"` when the retained file already holds exactly these bytes
 * (a no-op), or `"restore"` when it is missing and these are its recorded
 * bytes. Anything else is refused before any effect. `bytes` is read only for
 * a retained path.
 */
function admitRetainedFile(
  path: string,
  bytes: () => Uint8Array,
): "free" | "same" | "restore" {
  const at = retainedAt(path);
  if (at.holds) retainedRefusal();
  if (!at.version) return "free";
  const candidate = Buffer.from(bytes());
  let existing: Buffer | undefined;
  try {
    existing = readFileSync(path);
  } catch (error) {
    if (!missingPath(error)) throw error;
  }
  if (existing) {
    if (existing.equals(candidate)) return "same";
    retainedRefusal();
  }
  if (recordedBytes(at.version, candidate)) return "restore";
  retainedRefusal();
}

/** Create the directory `dir` and its missing parents, never inside a
 * retained set. Returns the directories created, outermost first. */
function ensureDirSync(dir: string): string[] {
  const missing: string[] = [];
  for (let parent = resolve(dir); !existsSync(parent);) {
    missing.unshift(parent);
    const next = dirname(parent);
    if (next === parent) break;
    parent = next;
  }
  if (missing.length === 0) return missing;
  assertCreatable(dir);
  mkdirSync(dir, { recursive: true });
  if (retainedAt(dir).version) {
    // A seal landed meanwhile: take back only what this call created.
    for (const created of [...missing].reverse()) rmdirSync(created);
    retainedRefusal();
  }
  return missing;
}

/** Undo a creation at `path` that a seal now covers, then refuse. Removes the
 * file only if it is still the one this call created (`created`). */
function refuseCreated(path: string, created: { dev: number; ino: number }) {
  const now = lstatSync(path, { throwIfNoEntry: false });
  if (now && now.dev === created.dev && now.ino === created.ino)
    unlinkSync(path);
  retainedRefusal();
}

/** Exclusively create `path` with `bytes`, fsynced. Never inside a retained
 * set, including one sealed while it was written. */
function createFileSync(path: string, bytes: Uint8Array): void {
  assertCreatable(path);
  const fd = openSync(path, "wx", 0o600);
  try {
    writeFileSync(fd, bytes);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  if (retainedAt(path).version) refuseCreated(path, statSync(path));
}

/**
 * Link `source` at `path` without replacing a file; false when a file is
 * already there. At a retained path only its recorded bytes may be linked.
 * The path is checked again after the link: a seal that landed meanwhile
 * either recorded these bytes or this link is removed and refused.
 */
function linkNewSync(source: string, path: string): boolean {
  if (existsSync(path)) return false;
  admitRetainedFile(path, () => readFileSync(source));
  try {
    linkSync(source, path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") return false;
    throw error;
  }
  const at = retainedAt(path);
  if (
    at.holds ||
    (at.version && !recordedBytes(at.version, readFileSync(path)))
  )
    refuseCreated(path, statSync(source));
  return true;
}

/**
 * A removal target: a whole tree, or a file removed with the semantics of
 * `rmSync` or `unlinkSync` (a directory there fails as those calls fail).
 */
type Removal = string | { file: string; as: "rm" | "unlink" };

const removalPath = (removal: Removal) =>
  typeof removal === "string" ? removal : removal.file;

/**
 * Move existing targets aside so the caller can delete or replace them. Each
 * is checked before any move and again after its own move: a seal that lands
 * in between either finds the path gone and fails, or is found here and every
 * moved path is put back. Returns the moved-aside paths; missing ones are
 * skipped.
 */
function detachSync(removals: readonly Removal[]): string[] {
  for (const removal of removals) {
    assertRemovable(removalPath(removal));
    if (
      typeof removal !== "string" &&
      lstatSync(removal.file, { throwIfNoEntry: false })?.isDirectory()
    ) {
      // Fail exactly as the plain file removal does; it removes nothing here.
      if (removal.as === "rm") rmSync(removal.file, { force: true });
      else unlinkSync(removal.file);
    }
  }
  const moved: [string, string][] = [];
  try {
    for (const removal of removals) {
      const path = removalPath(removal);
      const aside = join(dirname(path), `.retiring.${randomUUID()}`);
      try {
        renameSync(path, aside);
      } catch (error) {
        if (missingPath(error)) continue;
        throw error;
      }
      moved.push([path, aside]);
      assertRemovable(path, aside);
    }
  } catch (error) {
    for (const [path, aside] of moved.reverse())
      restoreDetachedSync(aside, path);
    throw error;
  }
  return moved.map(([, aside]) => aside);
}

/** Put a moved-aside path back without replacing anything there now. */
function restoreDetachedSync(aside: string, path: string): void {
  if (lstatSync(aside).isDirectory()) {
    renameSync(aside, path);
    return;
  }
  linkSync(aside, path);
  unlinkSync(aside);
}

/** Remove targets; missing ones are a no-op. See `detachSync`. */
function removeSync(removals: readonly Removal[]): void {
  for (const aside of detachSync(removals))
    rmSync(aside, { recursive: true, force: true });
}

/**
 * Replace the file at `path` with `source` atomically for readers. A backup
 * link keeps the old bytes until the new file is checked: if a seal landed
 * meanwhile and did not record the new bytes, the old file is put back.
 */
function replaceFileSync(source: string, path: string): void {
  assertRemovable(path);
  assertCreatable(source);
  const backup = join(dirname(path), `.retiring.${randomUUID()}`);
  let backedUp = true;
  try {
    linkSync(path, backup);
  } catch (error) {
    if (!missingPath(error)) throw error;
    backedUp = false;
  }
  renameSync(source, path);
  const at = retainedAt(path);
  if (
    at.holds ||
    (at.version && !recordedBytes(at.version, readFileSync(path)))
  ) {
    if (backedUp) renameSync(backup, path);
    else unlinkSync(path);
    retainedRefusal();
  }
  if (backedUp) unlinkSync(backup);
}

/** A version whose files become retained, as its index row names them. */
export interface RetainedVersionFiles {
  scope: string;
  collectedAt: string;
  /** The row's envelope path, relative to the data directory. */
  path: string;
  /** The generation the row records, if known. */
  generation: string | null;
}

/**
 * Seal versions' files: record them as retained. Call it in the writer
 * transaction that inserts their retained rows, before that transaction
 * commits. It changes no version file, and it never replaces a record: a
 * version keeps its first one. Both the row's own envelope path and the path
 * its scope and time name are sealed. A row path outside the data directory
 * is refused.
 *
 * With `bytes: "observed"`, the record holds the SHA-256 of each file present
 * now. A version is sealed only with its indexed envelope present and, when
 * the row records a generation, holding that generation: missing or changed
 * history is never certified, so this throws before writing any record. The
 * files are read again after the records are written; if they no longer match
 * (a mutation raced the seal), this throws. Either way the caller's
 * transaction must not commit. A mutation that moved a file aside before this
 * read therefore wins and the seal fails; one that starts later is refused
 * (see `detachSync`, `linkNewSync`).
 *
 * With `bytes: "unknown"`, for versions retained before these records
 * existed, no byte identity is recorded, so no lost file can be restored.
 */
export function recordRetainedVersionFiles(
  options: HierarchyManagerOptions,
  versions: readonly RetainedVersionFiles[],
  bytes: "observed" | "unknown",
): void {
  if (versions.length === 0) return;
  // The records' root is itself an effect: never inside a retained set,
  // including through a link at the data directory itself.
  ensureDirSync(options.dataDir);
  const root = realpathSync(options.dataDir);
  assertCreatable(root);
  for (const version of versions) {
    const blockDir = buildBlockDir(root, version.scope, version.collectedAt);
    const sealed: {
      path: string;
      observe: () => RetainedIdentity;
      unknown: RetainedIdentity;
    }[] = [
      ...retainedEnvelopePaths(root, version).map((path) => ({
        path,
        observe: () => observedEnvelopeIdentity(path, version.generation),
        unknown: { kind: "envelope", sha256: null } as RetainedIdentity,
      })),
      {
        path: blockDir,
        observe: () => observedBlockIdentity(blockDir),
        unknown: { kind: "blocks", files: "unknown" },
      },
    ];
    const identities = sealed.map(({ observe, unknown }) =>
      bytes === "observed" ? observe() : unknown,
    );
    const indexed = identities[0];
    if (
      bytes === "observed" &&
      indexed.kind === "envelope" &&
      indexed.sha256 === null
    )
      throw new Error(
        `Cannot seal ${version.path}: its file is missing or is not its indexed generation`,
      );
    sealed.forEach(({ path }, i) =>
      writeRetainedRecord(root, path, identities[i]),
    );
    if (bytes === "unknown") continue;
    for (const { path, observe } of sealed)
      if (
        canonicalJson(readRetainedIdentity(retainedRecordPath(root, path))) !==
        canonicalJson(observe())
      )
        throw new Error(
          `Retained version files changed while sealing; retry: ${relative(root, path)}`,
        );
  }
}

/** Whether a version already has all its retention records. */
export function hasRetainedVersionFiles(
  options: HierarchyManagerOptions,
  version: RetainedVersionFiles,
): boolean {
  let root: string;
  try {
    root = realpathSync(options.dataDir);
  } catch (error) {
    if (missingPath(error)) return false;
    throw error;
  }
  return [
    ...retainedEnvelopePaths(root, version),
    buildBlockDir(root, version.scope, version.collectedAt),
  ].every((target) => markerExists(retainedRecordPath(root, target)));
}

function retainedRecordPath(root: string, target: string): string {
  return join(root, RETAINED_DIR, relative(root, target)) + RETAINED_SUFFIX;
}

/** The indexed path and the canonical path of a version's envelope. */
function retainedEnvelopePaths(
  root: string,
  version: RetainedVersionFiles,
): string[] {
  const indexed = resolve(root, version.path);
  const inside = relative(root, indexed);
  if (
    inside === "" ||
    inside === ".." ||
    inside.startsWith(`..${sep}`) ||
    inside.split(sep)[0] === RETAINED_DIR ||
    !inside.endsWith(".json")
  )
    throw new Error(
      `Indexed version path is not a data file in its data directory: ${version.path}`,
    );
  const canonical = buildDataFilePath(root, version.scope, version.collectedAt);
  return indexed === canonical ? [indexed] : [indexed, canonical];
}

function observedEnvelopeIdentity(
  path: string,
  generation: string | null,
): RetainedIdentity {
  let bytes: Buffer;
  try {
    bytes = readFileSync(path);
  } catch (error) {
    if (!missingPath(error)) throw error;
    return { kind: "envelope", sha256: null };
  }
  if (generation !== null) {
    let stored: string | undefined;
    try {
      stored = envelopeGeneration(JSON.parse(bytes.toString("utf8")));
    } catch {
      // Unparseable bytes have no generation.
    }
    // Bytes that are not the indexed version are not its identity.
    if (stored !== generation) return { kind: "envelope", sha256: null };
  }
  return { kind: "envelope", sha256: sha256Hex(bytes) };
}

function observedBlockIdentity(dir: string): RetainedIdentity {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT")
      return { kind: "blocks", files: "absent" };
    if (missingPath(error)) return { kind: "blocks", files: "unknown" };
    throw error;
  }
  const files: Record<string, string> = {};
  for (const entry of entries) {
    if (!entry.isFile()) return { kind: "blocks", files: "unknown" };
    files[entry.name] = sha256Hex(readFileSync(join(dir, entry.name)));
  }
  return { kind: "blocks", files };
}

function writeRetainedRecord(
  root: string,
  target: string,
  identity: RetainedIdentity,
): void {
  const record = retainedRecordPath(root, target);
  if (markerExists(record)) return;
  const dir = dirname(record);
  const missing: string[] = [];
  for (let parent = dir; !existsSync(parent); parent = dirname(parent)) {
    missing.push(parent);
  }
  mkdirSync(dir, { recursive: true });
  for (const created of missing.reverse()) syncDirectory(dirname(created));
  const temp = `${record}.tmp.${randomUUID()}`;
  try {
    const fd = openSync(temp, "wx", 0o600);
    try {
      writeFileSync(fd, JSON.stringify(identity));
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    try {
      linkSync(temp, record);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }
  } finally {
    rmSync(temp, { force: true });
  }
  syncDirectory(dir);
}

export class PublishedDataFileError extends Error {
  constructor(
    public readonly relativePath: string,
    cause: unknown,
  ) {
    super(cause instanceof Error ? cause.message : String(cause), { cause });
  }
}

/** Synchronous, no-replace publication inside the SQLite writer gate. */
export function publishDataFile(
  options: HierarchyManagerOptions,
  envelope: DataFileEnvelope,
  bytes: Uint8Array,
  operation?: string,
): WriteResult {
  const path = buildDataFilePath(
    options.dataDir,
    envelope.scope,
    envelope.collectedAt,
  );
  const dir = dirname(path);
  const result = {
    path,
    relativePath: relative(options.dataDir, path),
    sizeBytes: bytes.byteLength,
  };
  const temp = `${path}.tmp.${operation ?? randomUUID()}`;
  if (admitRetainedFile(path, () => bytes) === "same") return result;
  const missing = ensureDirSync(dir);
  for (const created of missing) syncDirectory(dirname(created));
  removeSync([{ file: temp, as: "rm" }]);
  let published = false;
  try {
    try {
      createFileSync(temp, bytes);
      if (
        !linkNewSync(temp, path) &&
        admitRetainedFile(path, () => bytes) === "free" &&
        !readFileSync(path).equals(Buffer.from(bytes))
      ) {
        throw new Error(
          `Stored envelope conflicts with publication at ${path}`,
        );
      }
      published = true;
      syncDirectory(dir);
    } finally {
      removeSync([{ file: temp, as: "rm" }]);
      syncDirectory(dir);
    }
  } catch (err) {
    if (published) {
      throw new PublishedDataFileError(relative(options.dataDir, path), err);
    }
    throw err;
  }
  return result;
}

export function deleteDataFileSync(
  options: HierarchyManagerOptions,
  scope: string,
  collectedAt: string,
  operation?: string,
): void {
  const path = buildDataFilePath(options.dataDir, scope, collectedAt);
  const asides = detachSync([
    { file: path, as: "rm" },
    ...(operation
      ? [{ file: `${path}.tmp.${operation}`, as: "rm" as const }]
      : []),
    buildBlockDir(options.dataDir, scope, collectedAt),
  ]);
  for (const aside of asides) rmSync(aside, { recursive: true, force: true });
  if (existsSync(dirname(path))) syncDirectory(dirname(path));
}

export function deleteFirstSeenLedgerSync(
  options: HierarchyManagerOptions,
  scope: string,
): void {
  try {
    removeSync([
      { file: buildFirstSeenLedgerPath(options.dataDir, scope), as: "rm" },
    ]);
  } catch {
    /* Derived sidecar cleanup must not block data deletion. */
  }
}

export function snapshotScopeFiles(
  options: HierarchyManagerOptions,
  scope: string,
  preservePaths: readonly string[] = [],
): { files: string[]; directories: string[] } {
  const files: string[] = [];
  const directories: string[] = [];
  function visit(path: string): void {
    let info;
    try {
      info = lstatSync(path);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return;
      throw err;
    }
    if (!info.isDirectory()) {
      if (
        preservePaths.some(
          (preserved) =>
            path === preserved || path.startsWith(`${preserved}${sep}`),
        )
      ) {
        return;
      }
      files.push(path);
      return;
    }
    for (const name of readdirSync(path)) visit(join(path, name));
    directories.push(path);
  }
  for (const path of [
    buildScopeDir(resolve(options.dataDir), scope),
    buildScopeDir(join(resolve(options.dataDir), "blocks"), scope),
  ]) {
    for (
      let parent = dirname(path);
      parent !== resolve(options.dataDir);
      parent = dirname(parent)
    ) {
      if (existsSync(parent) && lstatSync(parent).isSymbolicLink()) {
        throw new Error(`Scope parent is a symbolic link: ${parent}`);
      }
    }
    visit(path);
  }
  return { files, directories };
}

/**
 * Delete a snapshot from `snapshotScopeFiles`. The snapshot may predate a
 * seal, so every target is checked now, before any effect, and each removal
 * is checked again after its move (see `detachSync`).
 */
export function deleteScopeFilesSync(
  snapshot: ReturnType<typeof snapshotScopeFiles>,
): void {
  for (const path of snapshot.directories) assertRemovable(path);
  for (const aside of detachSync(
    snapshot.files.map((file) => ({ file, as: "rm" as const })),
  ))
    rmSync(aside, { force: true });
  for (const dir of new Set(snapshot.files.map(dirname))) {
    if (existsSync(dir)) syncDirectory(dir);
  }
  for (const path of snapshot.directories) {
    // Only an empty directory is removed: it holds no retained byte.
    assertRemovable(path);
    try {
      rmdirSync(path);
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code !== "ENOENT" && code !== "ENOTEMPTY") throw err;
    }
    if (existsSync(dirname(path))) syncDirectory(dirname(path));
  }
}

/** Publish a durable envelope before callers make it visible in the index. */
export async function writeDataFile(
  options: HierarchyManagerOptions,
  envelope: DataFileEnvelope,
): Promise<WriteResult> {
  const staged = await stageDataFile(options, envelope);
  await publishStagedDataFile(staged.stagePath, staged.finalPath);
  return {
    path: staged.finalPath,
    relativePath: staged.relativePath,
    sizeBytes: staged.sizeBytes,
  };
}

/** Stage and fsync an envelope before an index transaction makes it visible. */
export async function stageDataFile(
  options: HierarchyManagerOptions,
  envelope: DataFileEnvelope,
  deps: { openFile?: typeof open } = {},
): Promise<{
  finalPath: string;
  stagePath: string;
  relativePath: string;
  sizeBytes: number;
  /**
   * Provenance and generation of the bytes staged, taken with the same
   * snapshot of `envelope` as the bytes, before any await: a caller that
   * changes its object later cannot change what is recorded.
   */
  identity: { pdppOrigin: boolean; generation: string };
}> {
  const openFile = deps.openFile ?? open;
  const bytes = Buffer.from(JSON.stringify(envelope, null, 2), "utf-8");
  const identity = {
    pdppOrigin: hasPdppOrigin(envelope),
    generation: envelopeGeneration(envelope),
  };
  const finalPath = buildDataFilePath(
    options.dataDir,
    envelope.scope,
    envelope.collectedAt,
  );
  const finalDir = dirname(finalPath);
  const directorySyncPaths = collectDirectorySyncPaths(finalDir);
  ensureDirSync(finalDir);
  const stagePath = `${finalPath}.pending.${randomUUID()}`;
  assertCreatable(stagePath);
  const handle = await openFile(stagePath, "wx");
  try {
    await handle.writeFile(bytes);
    await handle.sync();
  } finally {
    await handle.close();
  }
  if (retainedAt(stagePath).version)
    refuseCreated(stagePath, statSync(stagePath));
  for (const directoryPath of directorySyncPaths) {
    const directory = await openFile(directoryPath, "r");
    try {
      await directory.sync();
    } finally {
      await directory.close();
    }
  }
  return {
    finalPath,
    stagePath,
    relativePath: relative(options.dataDir, finalPath),
    sizeBytes: bytes.length,
    identity,
  };
}

function collectDirectorySyncPaths(finalDir: string): string[] {
  const paths: string[] = [];
  let current = finalDir;
  while (true) {
    paths.unshift(current);
    const parent = dirname(current);
    if (parent === current) return paths;
    current = parent;
  }
}

/** Two serialized envelopes with the same content, in any key order. */
function sameEnvelope(a: Buffer, b: Buffer): boolean {
  try {
    return (
      canonicalJson(JSON.parse(a.toString("utf8"))) ===
      canonicalJson(JSON.parse(b.toString("utf8")))
    );
  } catch {
    return false;
  }
}

/**
 * Fail when a file already published at `finalPath` holds a different
 * envelope than the staged one. Nothing is published or changed. Callers run
 * it before committing an index row, so a rejected publication leaves no row
 * describing bytes that are not there. A retained file accepts only its exact
 * bytes.
 */
export async function assertPublishable(
  stagePath: string,
  finalPath: string,
): Promise<void> {
  assertPublishableSync(stagePath, finalPath);
}

function assertPublishableSync(stagePath: string, finalPath: string): void {
  if (admitRetainedFile(finalPath, () => readFileSync(stagePath)) !== "free")
    return;
  let published: Buffer;
  try {
    published = readFileSync(finalPath);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return;
    throw err;
  }
  const staged = readFileSync(stagePath);
  if (!published.equals(staged) && !sameEnvelope(published, staged)) {
    throw new Error(
      `Stored envelope conflicts with publication at ${finalPath}`,
    );
  }
}

/**
 * Publish a staged envelope at its version path without replacing one.
 *
 * A version path names immutable bytes. Readers authorize the version they
 * selected, including its PDPP provenance, and only then read the path, so
 * different bytes appearing there would bypass that decision. The same
 * envelope (in any key order) republishes idempotently and keeps the stored
 * bytes; a different envelope fails, as in `publishDataFile`. The stage is
 * consumed, so it must not be a retained file.
 */
export async function publishStagedDataFile(
  stagePath: string,
  finalPath: string,
): Promise<void> {
  publishStagedDataFileSync(stagePath, finalPath);
}

/** No-replace stage publication for callers holding the SQLite writer gate.
 * A collision is refused; this path never replaces a retained version. */
export function publishStagedDataFileSync(
  stagePath: string,
  finalPath: string,
): void {
  assertRemovable(stagePath);
  if (!linkNewSync(stagePath, finalPath))
    assertPublishableSync(stagePath, finalPath);
  syncDirectory(dirname(finalPath));
  removeSync([{ file: stagePath, as: "unlink" }]);
}

/**
 * Publish exactly `bytes`, read earlier from `stagePath`, at `finalPath`, then
 * consume the stage. A stage changed after the read cannot reach the final
 * path. Returns false, leaving the stage, when the final path refuses them.
 */
export function publishStageBytesSync(
  stagePath: string,
  bytes: Uint8Array,
  finalPath: string,
): boolean {
  assertRemovable(stagePath);
  const verified = `${stagePath}.${randomUUID()}`;
  createFileSync(verified, bytes);
  try {
    publishStagedDataFileSync(verified, finalPath);
  } catch {
    // A file that appeared at the final path is not replaced.
    removeSync([{ file: verified, as: "rm" }]);
    return false;
  }
  removeSync([{ file: stagePath, as: "unlink" }]);
  return true;
}

/** Remove a stage or an unindexed publication. A missing file is a no-op;
 * a retained file is refused. */
export async function discardDataFile(path: string): Promise<void> {
  removeSync([{ file: path, as: "unlink" }]);
}

/** Read and parse a data file */
export async function readDataFile(
  options: HierarchyManagerOptions,
  scope: string,
  collectedAt: string,
): Promise<DataFileEnvelope> {
  const filePath = buildDataFilePath(options.dataDir, scope, collectedAt);
  const content = await readFile(filePath, "utf-8");
  return DataFileEnvelopeSchema.passthrough().parse(JSON.parse(content));
}

/** Read a data file without decoding or parsing its potentially large body. */
export async function readDataFileBytes(
  options: HierarchyManagerOptions,
  scope: string,
  collectedAt: string,
): Promise<Uint8Array> {
  return readFile(buildDataFilePath(options.dataDir, scope, collectedAt));
}

/** Open a fresh stream over a stored data file. */
export function readDataFileStream(
  options: HierarchyManagerOptions,
  scope: string,
  collectedAt: string,
): ReadableStream<Uint8Array> {
  return Readable.toWeb(
    createReadStream(buildDataFilePath(options.dataDir, scope, collectedAt)),
  ) as ReadableStream<Uint8Array>;
}

/** Read a bounded UTF-8 text prefix without parsing the full envelope. */
export async function readDataFilePreview(
  options: HierarchyManagerOptions,
  scope: string,
  collectedAt: string,
  maxBytes: number,
): Promise<{ text: string; truncated: boolean }> {
  const filePath = buildDataFilePath(options.dataDir, scope, collectedAt);
  const handle = await open(filePath, "r");
  try {
    const stats = await handle.stat();
    const bytesToRead = Math.max(0, Math.min(maxBytes, stats.size));
    const buffer = Buffer.alloc(bytesToRead);
    const { bytesRead } = await handle.read(buffer, 0, bytesToRead, 0);
    return previewJsonEnvelopePrefix(
      buffer.subarray(0, bytesRead).toString("utf-8"),
      maxBytes,
      { sourceTruncated: stats.size > bytesRead },
    );
  } finally {
    await handle.close();
  }
}

/**
 * Per-scope first-seen ledger: ONE flat file `<dataDir>/first-seen/<scope>.json`.
 *
 * It sits outside the per-version data files (`<dataDir>/<source>/<category>/…`)
 * and outside the block sidecars (`<dataDir>/blocks/…`). A scope's source
 * matches `[a-z0-9][a-z0-9_]*`, so no scope can have `first-seen` (it holds a
 * hyphen) as its directory, and the ledger is never in the SQLite index, so it
 * is not a version and nothing that lists, uploads or serves data reaches it.
 */
function buildFirstSeenLedgerPath(dataDir: string, scope: string): string {
  // Throws for anything that is not a well-formed scope, so the scope can
  // never carry a path separator or `..` into the file name.
  scopeToPathSegments(scope);
  return join(dataDir, "first-seen", `${scope}.json`);
}

/** Returns null when the scope has no ledger file. */
export async function readFirstSeenLedger(
  options: HierarchyManagerOptions,
  scope: string,
): Promise<unknown | null> {
  try {
    return JSON.parse(
      await readFile(buildFirstSeenLedgerPath(options.dataDir, scope), "utf-8"),
    ) as unknown;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw err;
  }
}

/** Atomic write: mkdir -p, write temp file, rename. The ledger is
 * scope-level, not a version file, but its actual path gets the same rules. */
export async function writeFirstSeenLedger(
  options: HierarchyManagerOptions,
  scope: string,
  ledger: unknown,
): Promise<void> {
  const filePath = buildFirstSeenLedgerPath(options.dataDir, scope);
  ensureDirSync(dirname(filePath));
  const tempPath = `${filePath}.tmp.${randomUUID()}`;
  try {
    createFileSync(tempPath, Buffer.from(JSON.stringify(ledger), "utf-8"));
    replaceFileSync(tempPath, filePath);
  } catch (err) {
    removeSync([{ file: tempPath, as: "rm" }]);
    throw err;
  }
}

/** Idempotent: a missing file is a no-op. */
export async function deleteFirstSeenLedger(
  options: HierarchyManagerOptions,
  scope: string,
): Promise<void> {
  removeSync([
    { file: buildFirstSeenLedgerPath(options.dataDir, scope), as: "rm" },
  ]);
}

export async function writeBlockManifest(
  options: HierarchyManagerOptions,
  scope: string,
  collectedAt: string,
  manifest: DataBlockManifest,
  blocks: DataScopeBlock[],
  commit?: (publish: () => void) => void,
): Promise<void> {
  const dir = buildBlockDir(options.dataDir, scope, collectedAt);
  const tempDir = `${dir}.tmp.${randomUUID()}`;

  ensureDirSync(tempDir);
  try {
    for (const block of blocks) {
      await writeFile(
        buildBlockPayloadPath(tempDir, block.id),
        JSON.stringify(block),
        "utf-8",
      );
    }
    await writeFile(
      join(tempDir, "manifest.json"),
      JSON.stringify(manifest, null, 2),
      "utf-8",
    );
    // Blocks and manifest appear together. The gate publishes at its barrier.
    const publish = () => publishBlockDirSync(tempDir, dir);
    if (commit) commit(publish);
    else publish();
  } finally {
    if (existsSync(tempDir)) removeSync([tempDir]);
  }
}

/**
 * Replace the sidecar directory `dir` with `tempDir`. A retained sidecar is
 * never replaced: files it already holds must be byte-identical, and a
 * missing file is created only from its recorded bytes.
 */
function publishBlockDirSync(tempDir: string, dir: string): void {
  const at = retainedAt(dir);
  if (at.version) {
    if (at.version.inner !== "") retainedRefusal();
    const restore = readdirSync(tempDir).filter(
      (name) =>
        admitRetainedFile(join(dir, name), () =>
          readFileSync(join(tempDir, name)),
        ) === "restore",
    );
    if (restore.length === 0) return;
    mkdirSync(dir, { recursive: true });
    for (const name of restore)
      if (!linkNewSync(join(tempDir, name), join(dir, name)))
        admitRetainedFile(join(dir, name), () =>
          readFileSync(join(tempDir, name)),
        );
    syncDirectory(dir);
    syncDirectory(dirname(dir));
    return;
  }
  const [aside] = detachSync([dir]);
  try {
    renameSync(tempDir, dir);
  } catch (error) {
    if (aside) restoreDetachedSync(aside, dir);
    throw error;
  }
  const now = retainedAt(dir);
  if (
    now.holds ||
    (now.version &&
      (now.version.inner !== "" ||
        canonicalJson(now.version.identity) !==
          canonicalJson(observedBlockIdentity(dir))))
  ) {
    // A seal landed meanwhile and did not record this sidecar: undo.
    renameSync(dir, tempDir);
    if (aside) restoreDetachedSync(aside, dir);
    retainedRefusal();
  }
  syncDirectory(dirname(dir));
  if (aside) rmSync(aside, { recursive: true, force: true });
}

export async function readScopeBlocks(
  options: HierarchyManagerOptions,
  scope: string,
  collectedAt: string,
  readOptions: {
    cursor?: string;
    maxBytes: number;
    blockIds?: readonly string[];
    representation?: "stored" | "grantee";
  },
): Promise<ReadScopeBlocksResponse> {
  const manifest = await readBlockManifest(options, scope, collectedAt);
  return readManifestScopeBlocks(
    manifest,
    (id) => readBlockPayloadIfPresent(options, scope, collectedAt, id),
    readOptions,
  );
}

/**
 * Manifest as a table of contents. Unlike the internal reader this returns null
 * for a scope that was stored before block sidecars existed, so callers can
 * degrade instead of failing.
 */
export async function readScopeBlockManifest(
  options: HierarchyManagerOptions,
  scope: string,
  collectedAt: string,
): Promise<DataBlockManifest | null> {
  try {
    return await readBlockManifest(options, scope, collectedAt);
  } catch (err) {
    if (
      err instanceof DataBlockStorageError &&
      err.code === "block_manifest_not_found"
    ) {
      return null;
    }
    throw err;
  }
}

export async function hasScopeBlocks(
  options: HierarchyManagerOptions,
  scope: string,
  collectedAt: string,
): Promise<boolean> {
  try {
    await access(buildBlockManifestPath(options.dataDir, scope, collectedAt));
    return true;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      return false;
    }
    throw err;
  }
}

/** List version filenames for a scope, newest first. Empty array if scope dir doesn't exist. */
export async function listVersions(
  options: HierarchyManagerOptions,
  scope: string,
): Promise<string[]> {
  const scopeDir = buildScopeDir(options.dataDir, scope);

  let entries: string[];
  try {
    entries = await readdir(scopeDir);
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      return [];
    }
    throw err;
  }

  const jsonFiles = entries
    .filter((f) => f.endsWith(".json"))
    .sort()
    .reverse();

  return jsonFiles.map((f) => filenameToTimestamp(f.replace(".json", "")));
}

/** Delete a single data file and its sidecar. Idempotent: a missing file is a
 * no-op (matches deleteByFileId's no-op contract and avoids stalling the sync
 * cursor when the blob is already gone). */
export async function deleteDataFile(
  options: HierarchyManagerOptions,
  scope: string,
  collectedAt: string,
): Promise<void> {
  for (const aside of detachSync([
    {
      file: buildDataFilePath(options.dataDir, scope, collectedAt),
      as: "unlink",
    },
    buildBlockDir(options.dataDir, scope, collectedAt),
  ]))
    await rm(aside, { recursive: true, force: true });
}

/**
 * Delete all files for a scope by removing the scope directory recursively.
 * No-op if directory doesn't exist.
 */
export async function deleteAllForScope(
  options: HierarchyManagerOptions,
  scope: string,
): Promise<void> {
  for (const aside of detachSync([
    buildScopeDir(options.dataDir, scope),
    buildScopeDir(join(options.dataDir, "blocks"), scope),
  ]))
    await rm(aside, { recursive: true, force: true });
}

async function readBlockManifest(
  options: HierarchyManagerOptions,
  scope: string,
  collectedAt: string,
): Promise<DataBlockManifest> {
  try {
    return JSON.parse(
      await readFile(
        buildBlockManifestPath(options.dataDir, scope, collectedAt),
        "utf-8",
      ),
    ) as DataBlockManifest;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      throw new DataBlockStorageError(
        "block_manifest_not_found",
        `Block manifest not found for ${scope} at ${collectedAt}`,
      );
    }
    throw err;
  }
}

async function readBlockPayload(
  options: HierarchyManagerOptions,
  scope: string,
  collectedAt: string,
  blockId: string,
): Promise<DataScopeBlock> {
  try {
    return JSON.parse(
      await readFile(
        buildBlockPayloadPath(
          buildBlockDir(options.dataDir, scope, collectedAt),
          blockId,
        ),
        "utf-8",
      ),
    ) as DataScopeBlock;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      throw new DataBlockStorageError(
        "block_payload_not_found",
        `Block payload not found for ${scope} at ${collectedAt}: ${blockId}`,
      );
    }
    throw err;
  }
}

/** Payload read for block-addressed selection: a missing id is a warning, not a throw. */
async function readBlockPayloadIfPresent(
  options: HierarchyManagerOptions,
  scope: string,
  collectedAt: string,
  blockId: string,
): Promise<DataScopeBlock | null> {
  try {
    return await readBlockPayload(options, scope, collectedAt, blockId);
  } catch (err) {
    if (
      err instanceof DataBlockStorageError &&
      err.code === "block_payload_not_found"
    ) {
      return null;
    }
    throw err;
  }
}

function buildBlockDir(
  dataDir: string,
  scope: string,
  collectedAt: string,
): string {
  return join(buildScopeDir(join(dataDir, "blocks"), scope), collectedAt);
}

function buildBlockManifestPath(
  dataDir: string,
  scope: string,
  collectedAt: string,
): string {
  return join(buildBlockDir(dataDir, scope, collectedAt), "manifest.json");
}

function buildBlockPayloadPath(dir: string, blockId: string): string {
  return join(dir, `${encodeURIComponent(blockId)}.json`);
}
