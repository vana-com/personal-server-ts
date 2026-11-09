/**
 * NO_LOCAL_DELETES, as a runtime tripwire: a cheap fingerprint of the data
 * folder (relative path, size, mtime of every file) before and after the run.
 * Any difference aborts the run. The tests prove the stronger claim with
 * content hashes.
 */

import { lstat, readdir } from "node:fs/promises";
import { join, relative } from "node:path";

export async function fingerprintTree(root: string): Promise<string> {
  const lines: string[] = [];
  const pending = [root];
  while (pending.length > 0) {
    const dir = pending.pop()!;
    for (const item of await readdir(dir, { withFileTypes: true })) {
      const path = join(dir, item.name);
      const stats = await lstat(path);
      lines.push(
        `${relative(root, path)}|${item.isDirectory() ? "d" : stats.size}|${Math.trunc(stats.mtimeMs)}`,
      );
      if (item.isDirectory()) pending.push(path);
    }
  }
  return lines.sort().join("\n");
}

/** The newest file modification time in the folder, and how many files it holds. */
export async function copyAge(
  root: string,
): Promise<{ newestFileModified: string; files: number }> {
  let newest = 0;
  let files = 0;
  const pending = [root];
  while (pending.length > 0) {
    const dir = pending.pop()!;
    for (const item of await readdir(dir, { withFileTypes: true })) {
      const path = join(dir, item.name);
      if (item.isDirectory()) {
        pending.push(path);
        continue;
      }
      files += 1;
      newest = Math.max(newest, (await lstat(path)).mtimeMs);
    }
  }
  return {
    newestFileModified: new Date(Math.trunc(newest)).toISOString(),
    files,
  };
}
