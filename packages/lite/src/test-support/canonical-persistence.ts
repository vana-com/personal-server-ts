/** Crash oracle only. This adapter is not exported as durable mobile storage. */
import { sha256 } from "viem";
import { canonicalJson } from "@opendatalabs/personal-server-ts-core/replication/envelope";
import {
  LITE_CANONICAL_MAX_VALUE_BYTES,
  type LiteBlobDescriptor,
  type LiteCanonicalPersistence,
  type LiteCanonicalTransaction,
  type LiteStorageEntry,
} from "../canonical-persistence.js";

export interface FakeCanonicalDisk {
  rows: Map<string, string>;
  blobs: Map<string, { descriptor: LiteBlobDescriptor; bytes: Uint8Array }>;
}
export const fakeCanonicalDisk = (): FakeCanonicalDisk => ({
  rows: new Map(),
  blobs: new Map(),
});
export type CanonicalCrashPoint =
  "record" | "blob" | "log" | "import" | "before-commit" | "after-commit";
export function writeCrashPoint(key: string): CanonicalCrashPoint | undefined {
  if (key.startsWith("rows/")) return "record";
  if (key.startsWith("log/")) return "log";
  if (key.startsWith("import/")) return "import";
  return undefined;
}
export function storagePage(entries: LiteStorageEntry[], after?: string) {
  const sorted = entries
    .filter((entry) => after === undefined || entry.key > after)
    .sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
  const page: LiteStorageEntry[] = [];
  let size = 0;
  for (const entry of sorted) {
    const bytes = new TextEncoder().encode(entry.value).length;
    if (bytes > LITE_CANONICAL_MAX_VALUE_BYTES)
      throw new Error("native value exceeds 18 MiB");
    // A page holds its first entry whatever its size.
    if (page.length === 100 || (page.length && size + bytes > 512 * 1024))
      break;
    page.push(entry);
    size += bytes;
  }
  return {
    entries: page,
    ...(page.length < sorted.length ? { after: page.at(-1)!.key } : {}),
  };
}
export async function collectStagedBlob(
  descriptor: LiteBlobDescriptor,
  chunks: AsyncIterable<Uint8Array>,
) {
  const parts: Uint8Array[] = [];
  let size = 0;
  for await (const part of chunks) {
    if (part.length > 128 * 1024)
      throw new Error("native frame exceeds 128 KiB");
    parts.push(part.slice());
    size += part.length;
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) {
    bytes.set(part, offset);
    offset += part.length;
  }
  if (
    size !== descriptor.sizeBytes ||
    `sha256:${sha256(bytes).slice(2)}` !== descriptor.sha256 ||
    descriptor.blobId !== descriptor.sha256
  )
    throw new Error("invalid staged blob");
  return { descriptor: structuredClone(descriptor), bytes };
}
export function createFakeCanonicalPersistence(disk = fakeCanonicalDisk()) {
  const staged = new Map<
    string,
    Awaited<ReturnType<typeof collectStagedBlob>>
  >();
  let failure: CanonicalCrashPoint | undefined;
  let queue = Promise.resolve();
  const hit = (point: CanonicalCrashPoint | undefined) => {
    if (point && failure === point) {
      failure = undefined;
      throw new Error(`interrupted:${point}`);
    }
  };
  const port: LiteCanonicalPersistence = {
    transaction<T>(
      run: (tx: LiteCanonicalTransaction) => Promise<T>,
    ): Promise<T> {
      const work = queue.then(async () => {
        const rows = new Map(disk.rows);
        const blobs = new Map(disk.blobs);
        const tx: LiteCanonicalTransaction = {
          async get(key) {
            return rows.get(key);
          },
          async put(key, value) {
            if (
              new TextEncoder().encode(value).length >
              LITE_CANONICAL_MAX_VALUE_BYTES
            )
              throw new Error("native value exceeds 18 MiB");
            rows.set(key, value);
            hit(writeCrashPoint(key));
          },
          async delete(key) {
            rows.delete(key);
          },
          async scan(prefix, after) {
            return storagePage(
              [...rows]
                .filter(([key]) => key.startsWith(prefix))
                .map(([key, value]) => ({ key, value })),
              after,
            );
          },
          async attachBlob(id, expected) {
            const value = staged.get(id);
            if (
              !value ||
              canonicalJson(value.descriptor) !== canonicalJson(expected)
            )
              throw new Error("unknown staged blob");
            const prior = blobs.get(expected.blobId);
            if (
              prior &&
              canonicalJson(prior.descriptor) !== canonicalJson(expected)
            )
              throw new Error("blob metadata conflict");
            blobs.set(expected.blobId, value);
            hit("blob");
          },
          async blob(id) {
            return blobs.get(id)?.descriptor;
          },
        };
        const result = await run(tx);
        hit("before-commit");
        disk.rows = rows;
        disk.blobs = blobs;
        hit("after-commit");
        return result;
      });
      queue = work.then(
        () => undefined,
        () => undefined,
      );
      return work;
    },
    async stageBlob(descriptor, chunks) {
      const value = await collectStagedBlob(descriptor, chunks);
      const id = globalThis.crypto.randomUUID();
      staged.set(id, value);
      return id;
    },
    async *readBlob(id) {
      const value = disk.blobs.get(id);
      if (!value) throw new Error("missing committed blob");
      for (let i = 0; i < value.bytes.length; i += 128 * 1024)
        yield value.bytes.slice(i, i + 128 * 1024);
    },
  };
  return {
    port,
    crashAt(point: CanonicalCrashPoint) {
      failure = point;
    },
    disk,
  };
}
