/**
 * Child workload for spool-retain.test.ts. Reads a spool-format file through the
 * real `readSpool` and keeps the text of every `keepEvery`-th line, as a bucket
 * reducer keeps its winners. What the kept texts pin is what the peak measures.
 */

import { stat, writeFile, open } from "node:fs/promises";
import { basename, dirname } from "node:path";
import { readSpool } from "@opendatalabs/personal-server-ts-core/stream-sync";
import { createFsStreamSyncFiles } from "./fs-files.js";

const LINE_BYTES = 16 * 1024;

export interface RetainArgs {
  readonly path: string;
  readonly mib: number;
  readonly keepEvery: number;
}

/** Spool-format file of `mib` MiB: `<64-hex pkHash> <canonical line>\n`. */
async function ensureSpool(path: string, mib: number): Promise<void> {
  const expected = ((mib * 1024 * 1024) / LINE_BYTES) * LINE_BYTES;
  try {
    if ((await stat(path)).size === expected) return;
  } catch {
    // generate below
  }
  const lines = (mib * 1024 * 1024) / LINE_BYTES;
  const handle = await open(path, "w");
  try {
    for (let i = 0; i < lines; i += 1) {
      const hash = (i % 4096).toString(16).padStart(64, "0");
      const head = `{"o":${i},"r":"r","v":{"id":"k${String(i % 4096).padStart(8, "0")}","pad":"`;
      const tail = `"}}`;
      const pad = "p".repeat(
        LINE_BYTES - 1 - head.length - tail.length - hash.length - 1,
      );
      await handle.write(`${hash} ${head}${pad}${tail}\n`);
    }
  } finally {
    await handle.close();
  }
}

/** Child side: read through readSpool, keep every keepEvery-th line's text. */
export async function retainWinners(
  args: unknown,
): Promise<{ lines: number; kept: number }> {
  const a = args as RetainArgs;
  await ensureSpool(a.path, a.mib);
  const files = createFsStreamSyncFiles(dirname(a.path));
  const kept: string[] = [];
  let lines = 0;
  for await (const line of readSpool(files, basename(a.path))) {
    if (lines % a.keepEvery === 0) kept.push(line.text);
    lines += 1;
  }
  return { lines, kept: kept.length };
}
