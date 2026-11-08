/**
 * Workloads for `memory-oracle.ts`. Each export runs in a fresh child process,
 * so anything it needs must come from disk or from its arguments.
 */

import { sha256 } from "@noble/hashes/sha2";
import { createMemoryStreamSyncReadFiles } from "../stream-sync-read/memory-files.js";
import {
  StreamSyncReadService,
  type StreamSyncReadOptions,
} from "../stream-sync-read/service.js";
import { testOwnerKey } from "../stream-sync-read/testing.js";
import { createDiskStreamSyncReadFiles } from "./disk-files.js";
import { ask, identityReadKeys, masterKey, silent } from "./read-fixture.js";

const hex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

/**
 * Read a view from a directory written by a fixture, as a restarted server
 * would: no blob reads, no import. The child holds only the body it reads.
 */
type RestartArgs = { dir: string; seed: number; scope: string };

/** Open a view from a directory written by a fixture, as a restarted server: no blob reads, no import. */
async function openRestart(args: RestartArgs): Promise<StreamSyncReadService> {
  const owner = await testOwnerKey(masterKey(args.seed));
  return StreamSyncReadService.open({
    files: createDiskStreamSyncReadFiles(args.dir),
    blobs: {
      get: async () => {
        throw new Error("blob read on restart");
      },
    },
    keys: identityReadKeys(owner),
    logger: silent,
    overlay: { entries: async () => [] },
    now: () => new Date("2026-11-02T00:00:00Z"),
  } as StreamSyncReadOptions);
}

/** Resolve the view, call `onStart`, then drain it, calling `onChunk` after each chunk. */
async function drainRestart(
  service: StreamSyncReadService,
  scope: string,
  hooks: { onStart?: () => void; onChunk?: () => void } = {},
): Promise<{ bytes: number; digest: string }> {
  const decision = await service.resolve(ask(scope));
  if (decision.kind !== "view") {
    throw new Error(`expected a view, got ${decision.kind}`);
  }
  hooks.onStart?.();
  const reader = decision.body.getReader();
  const hash = sha256.create();
  let bytes = 0;
  for (;;) {
    const next = await reader.read();
    if (next.done) break;
    hash.update(next.value);
    bytes += next.value.byteLength;
    hooks.onChunk?.();
  }
  return { bytes, digest: hex(hash.digest()) };
}

/**
 * Read a view from a directory written by a fixture, as a restarted server
 * would: no blob reads, no import. The child holds only the body it reads.
 */
export async function readRetention(
  args: RestartArgs,
): Promise<{ bytes: number; digest: string }> {
  return drainRestart(await openRestart(args), args.scope);
}

/**
 * The same restart read, measuring live memory with forced full GC instead of
 * the RSS high-water mark. Deterministic: no timer, and the live set after a
 * full GC is a function of the code, not of allocation timing. Live memory is
 * the V8 heap plus ArrayBuffer backing stores, where the part bytes live.
 * `retained` is the largest live amount seen during the drain above the
 * amount live when the body starts. Absolute values include the module graph;
 * the growth gate compares sizes.
 */
export async function readLiveRetention(
  args: RestartArgs & { sampleEvery: number },
): Promise<{ bytes: number; digest: string; retained: number }> {
  const gc = (globalThis as { gc?: () => void }).gc;
  if (!gc) throw new Error("readLiveRetention requires --expose-gc");
  const live = (): number => {
    gc();
    const m = process.memoryUsage();
    return m.heapUsed + m.arrayBuffers;
  };
  let start = 0;
  let max = 0;
  let chunks = 0;
  const { bytes, digest } = await drainRestart(
    await openRestart(args),
    args.scope,
    {
      onStart: () => {
        start = live();
        max = start;
      },
      onChunk: () => {
        chunks += 1;
        if (chunks % args.sampleEvery === 0) max = Math.max(max, live());
      },
    },
  );
  max = Math.max(max, live());
  return { bytes, digest, retained: max - start };
}

/**
 * The store production selects for the stream-sync read side when no host
 * store is injected (Lite: `createMemoryStreamSyncReadFiles()`, see
 * packages/lite/src/sync.ts). Step 2 replaces this selector with the durable
 * store. The probe below must then keep passing with that store.
 */
export function productionReadFiles(_root: string) {
  return createMemoryStreamSyncReadFiles();
}

/**
 * Write `files` payloads of `fileBytes` each, then reopen the same root and
 * count the payloads read back intact. `store: "disk"` is the green setup (a
 * store that survives a reopen). `store: "production"` is the selector under
 * test. The caller's `peakBytes` is what the store keeps resident.
 */
export async function durableStoreProbe(args: {
  root: string;
  store: "disk" | "production";
  files: number;
  fileBytes: number;
}): Promise<{ reopenedFiles: number }> {
  const open = () =>
    args.store === "disk"
      ? createDiskStreamSyncReadFiles(args.root)
      : productionReadFiles(args.root);
  const store = open();
  for (let i = 0; i < args.files; i++) {
    await store.write(
      `views/a/_/s/parts/p${i}`,
      new Uint8Array(args.fileBytes).fill((i % 250) + 1),
    );
  }
  const reopened = open();
  let reopenedFiles = 0;
  for (let i = 0; i < args.files; i++) {
    const got = await reopened.read(`views/a/_/s/parts/p${i}`);
    if (got && got.byteLength === args.fileBytes) reopenedFiles += 1;
  }
  return { reopenedFiles };
}
