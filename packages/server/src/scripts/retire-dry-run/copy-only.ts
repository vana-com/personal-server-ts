/**
 * COPY_ONLY: the dry run opens a byte copy of a data folder, never a live one.
 *
 * A person makes the copy (database file and its `-wal` file, never `-shm`;
 * plus the legacy files) under `$HOME/.tmp/`. This check runs before the tool
 * opens anything, and refuses a folder that is not under `$HOME/.tmp/`, that is
 * (or resolves into) `$HOME/.vana`, or that holds a `-shm` file (its owner is
 * probably running, so the copy may be torn). It also refuses a symlink inside
 * the folder, so no later read leaves it, and an `--out` path inside it.
 */

import { readdir, realpath, stat } from "node:fs/promises";
import { dirname, join, relative, resolve, sep } from "node:path";

export type CopyOnlyReason =
  | "missing"
  | "not_a_directory"
  | "not_under_home_tmp"
  | "under_vana_home"
  | "has_shm_file"
  | "has_symlink"
  | "out_not_under_home_tmp"
  | "out_inside_data_dir";

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
    throw new CopyOnlyError("missing", `${what} does not exist: ${path}`);
  }
}

async function scanTree(root: string): Promise<void> {
  const pending = [root];
  while (pending.length > 0) {
    const dir = pending.pop()!;
    for (const item of await readdir(dir, { withFileTypes: true })) {
      const path = join(dir, item.name);
      if (item.isSymbolicLink()) {
        throw new CopyOnlyError(
          "has_symlink",
          `Refusing: the data folder holds a symlink (${relative(root, path)}). Copy the bytes, not links.`,
        );
      }
      if (item.name.endsWith("-shm")) {
        throw new CopyOnlyError(
          "has_shm_file",
          `Refusing: the data folder holds a -shm file (${relative(root, path)}). ` +
            "That means a live process may have had the database open. " +
            "Copy only the .db and .db-wal files, with the owner stopped.",
        );
      }
      if (item.isDirectory()) pending.push(path);
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
}

export async function assertCopyOnly(
  input: CopyOnlyInput,
): Promise<CopyOnlyPaths> {
  const home = await realOrThrow(input.home, "Home folder");
  const tmpRoot = join(home, ".tmp");
  const vanaHome = join(home, ".vana");

  const dataDir = await realOrThrow(resolve(input.dataDir), "Data folder");
  if (!(await stat(dataDir)).isDirectory()) {
    throw new CopyOnlyError("not_a_directory", `Not a folder: ${dataDir}`);
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

  const outParent = await realOrThrow(
    dirname(resolve(input.outPath)),
    "Folder of --out",
  );
  const outPath = join(outParent, resolve(input.outPath).split(sep).pop()!);
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
  return { dataDir, outPath };
}
