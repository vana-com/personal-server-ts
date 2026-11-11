import { createHash } from "node:crypto";
import {
  closeSync,
  copyFileSync,
  mkdirSync,
  openSync,
  writeSync,
  symlinkSync,
} from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildSync } from "esbuild";
import { initializeDatabase } from "../storage/index-schema.js";
import { openRecordStore } from "../pdpp/records-bootstrap.js";
import type { ImportMemoryFixture } from "./import-memory.child.js";

export type { ImportMemoryFixture };

/** Compile test support before the fresh child's baseline. Keep the artifact
 * out of runtime dist and avoid charging source transpilation to the import.
 * External packages resolve through the checkout's existing dependencies. */
export function buildImportMemoryChild(root: string): string {
  const output = join(root, "import-memory.child.mjs");
  symlinkSync(
    fileURLToPath(new URL("../../../../node_modules", import.meta.url)),
    join(root, "node_modules"),
    "dir",
  );
  buildSync({
    entryPoints: [
      fileURLToPath(new URL("./import-memory.child.ts", import.meta.url)),
    ],
    outfile: output,
    bundle: true,
    platform: "node",
    format: "esm",
    packages: "external",
    target: "node22",
    logLevel: "silent",
  });
  // The driver starts its SQLite worker from a file beside the code that runs
  // it; a bundle has no such file, so place the worker next to the artifact.
  for (const worker of ["better-sqlite3-worker.cjs", "statement-cache.cjs"])
    copyFileSync(
      fileURLToPath(new URL(`./${worker}`, import.meta.url)),
      join(root, worker),
    );
  return output;
}

export const MEMORY_ROWS = 2_250;
export const MEMORY_ROW_BYTES = 16_384;
export const MEMORY_IDENTITY = {
  owner: "0xabc" as const,
  network: "test",
  deviceId: "memory-fixture",
};
export const MEMORY_TARGET = {
  connectionId: "memory-connection",
  connector: "memory-source",
  stream: "items",
  primaryKey: ["id"],
  semantics: "mutable_state" as const,
  incremental: true,
};

/** Generate 36.864 MB on disk, one 16 KiB row at a time. The same rows feed
 * native canonical storage and the upload; fixture generation is not measured. */
export function createImportMemoryFixture(
  root: string,
  rows = MEMORY_ROWS,
): ImportMemoryFixture {
  const nativeRoot = join(root, "native");
  mkdirSync(join(nativeRoot, "data"), { recursive: true });
  const native = initializeDatabase(join(nativeRoot, "index.db"));
  const uploadPath = join(root, "source.ndjson");
  const file = openSync(uploadPath, "wx");
  const hash = createHash("sha256");
  let bytes = 0;
  let payloadBytes = 0;
  const sourceId = "urn:memory-fixture";
  try {
    const store = openRecordStore(native, false);
    store.registerConnection({
      instance: "memory-instance",
      sourceId,
      method: MEMORY_TARGET.connector,
      label: "Memory fixture",
    });
    native.transaction(() => {
      for (let i = 0; i < rows; i++) {
        const id = String(i).padStart(6, "0");
        const empty = JSON.stringify({ id, text: "" }) + "\n";
        const prefix = `payload-${id}-`;
        const text = prefix
          .repeat(Math.ceil(MEMORY_ROW_BYTES / prefix.length))
          .slice(0, MEMORY_ROW_BYTES - Buffer.byteLength(empty));
        const data = { id, text };
        const line = Buffer.from(JSON.stringify(data) + "\n");
        if (line.length !== MEMORY_ROW_BYTES)
          throw new Error("memory_fixture_row_size");
        let offset = 0;
        while (offset < line.length) {
          const written = writeSync(file, line, offset, line.length - offset);
          if (!written) throw new Error("memory_fixture_write_failed");
          offset += written;
        }
        hash.update(line);
        bytes += line.length;
        payloadBytes += Buffer.byteLength(text);
        const result = store.ingestBatch(
          [
            {
              instance: "memory-instance",
              stream: MEMORY_TARGET.stream,
              key: id,
              data,
              emitted_at: "2026-01-01T00:00:00.000Z",
            },
          ],
          () => MEMORY_TARGET.semantics,
          () => MEMORY_TARGET.primaryKey,
          { method: MEMORY_TARGET.connector, generation: 1 },
        );
        if (result.accepted !== 1) throw new Error("memory_fixture_rejected");
      }
    })();
  } finally {
    closeSync(file);
    native.close();
  }
  return {
    root,
    rows,
    uploadPath,
    revision: hash.digest("hex"),
    bytes,
    payloadBytes,
    identity: MEMORY_IDENTITY,
    target: MEMORY_TARGET,
    sourceId,
  };
}
