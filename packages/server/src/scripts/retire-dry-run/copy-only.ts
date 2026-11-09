/**
 * COPY_ONLY: the dry run opens a byte copy of a data folder, never a live one.
 *
 * A person makes the copy (database file and its `-wal` file, never `-shm`;
 * plus the legacy files) under `$HOME/.tmp/`. This check runs before the tool
 * opens anything, and refuses a folder that is not under `$HOME/.tmp/`, that is
 * (or resolves into) `$HOME/.vana`, or that holds a `-shm` file (its owner is
 * probably running, so the copy may be torn). It also refuses a symlink inside
 * the folder, so no later read leaves it.
 *
 * `--out` must be a new file, or an existing plain file with one link, in a
 * folder under `$HOME/.tmp/` and outside the data folder. A symlink, a hard
 * link or a folder there is refused: the report is written by replacing the
 * path, and a link would let that reach the copy.
 *
 * Messages are fixed text. They never name a file of the folder: a file name
 * can be a person's data.
 */

import { lstat, readdir, realpath, stat } from "node:fs/promises";
import { basename, dirname, join, relative, resolve, sep } from "node:path";

export type CopyOnlyReason =
  | "missing"
  | "not_a_directory"
  | "not_under_home_tmp"
  | "under_vana_home"
  | "has_shm_file"
  | "has_symlink"
  | "out_not_under_home_tmp"
  | "out_inside_data_dir"
  | "out_not_a_plain_file";

export class CopyOnlyError extends Error {
  constructor(
    readonly reason: CopyOnlyReason,
    message: string,
  ) {
    super(message);
    this.name = "CopyOnlyError";
  }
}

/** True when `path` is `root` or below it. Both must be absolute and resolved. */
export function isInside(root: string, path: string): boolean {
  const rel = relative(root, path);
  return rel === "" || (!rel.startsWith("..") && !rel.startsWith(sep));
}

function strictlyInside(root: string, path: string): boolean {
  return path !== root && isInside(root, path);
}

async function realOrThrow(path: string, what: string): Promise<string> {
  try {
    return await realpath(path);
  } catch {
    throw new CopyOnlyError("missing", `${what} does not exist.`);
  }
}

async function scanTree(root: string): Promise<void> {
  const pending = [root];
  while (pending.length > 0) {
    const dir = pending.pop()!;
    for (const item of await readdir(dir, { withFileTypes: true })) {
      if (item.isSymbolicLink()) {
        throw new CopyOnlyError(
          "has_symlink",
          "Refusing: the data folder holds a symlink. Copy the bytes, not links.",
        );
      }
      if (item.name.endsWith("-shm")) {
        throw new CopyOnlyError(
          "has_shm_file",
          "Refusing: the data folder holds a -shm file. " +
            "That means a live process may have had the database open. " +
            "Copy only the .db and .db-wal files, with the owner stopped.",
        );
      }
      if (item.isDirectory()) pending.push(join(dir, item.name));
    }
  }
}

export interface CopyOnlyInput {
  readonly dataDir: string;
  readonly outPath: string;
  /** `$HOME`; a parameter so a test can use a throwaway home. */
  readonly home: string;
}

export interface CopyOnlyPaths {
  readonly dataDir: string;
  readonly outPath: string;
  /** `$HOME/.tmp`, resolved: where the tool may make its own scratch folder. */
  readonly tmpRoot: string;
}

export async function assertCopyOnly(
  input: CopyOnlyInput,
): Promise<CopyOnlyPaths> {
  const home = await realOrThrow(input.home, "The home folder");
  const tmpRoot = join(home, ".tmp");
  const vanaHome = join(home, ".vana");

  const dataDir = await realOrThrow(resolve(input.dataDir), "The data folder");
  if (!(await stat(dataDir)).isDirectory()) {
    throw new CopyOnlyError(
      "not_a_directory",
      "The data path is not a folder.",
    );
  }
  if (isInside(vanaHome, dataDir)) {
    throw new CopyOnlyError(
      "under_vana_home",
      "Refusing: the data folder is inside ~/.vana (the installed app's live data). Make a copy under ~/.tmp/ first.",
    );
  }
  if (!strictlyInside(tmpRoot, dataDir)) {
    throw new CopyOnlyError(
      "not_under_home_tmp",
      "Refusing: the data folder is not under ~/.tmp/. Make a byte copy there first.",
    );
  }
  await scanTree(dataDir);

  const requested = resolve(input.outPath);
  const outParent = await realOrThrow(
    dirname(requested),
    "The folder of --out",
  );
  const outPath = join(outParent, basename(requested));
  await assertPlainFileOrAbsent(outPath);
  if (isInside(vanaHome, outParent) || !isInside(tmpRoot, outParent)) {
    throw new CopyOnlyError(
      "out_not_under_home_tmp",
      "Refusing: --out must be a file under ~/.tmp/ (outside ~/.vana).",
    );
  }
  if (isInside(dataDir, outPath)) {
    throw new CopyOnlyError(
      "out_inside_data_dir",
      "Refusing: --out is inside the data folder, which must not change.",
    );
  }
  return { dataDir, outPath, tmpRoot };
}

/** A symlink, hard link or folder at `--out` would let the write reach the copy. */
async function assertPlainFileOrAbsent(path: string): Promise<void> {
  let info;
  try {
    info = await lstat(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  if (!info.isFile() || info.nlink > 1) {
    throw new CopyOnlyError(
      "out_not_a_plain_file",
      "Refusing: --out exists and is a symlink, a folder or a linked file. Name a new file.",
    );
  }
}
