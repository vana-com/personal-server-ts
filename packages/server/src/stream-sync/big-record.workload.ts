/**
 * Memory workloads for one record of a chosen body size. Each export runs in a
 * fresh child of `packages/core/src/test-support/memory-oracle.ts`, so the
 * child's kernel peak (VmHWM) is the peak of that one step.
 *
 * - `writeWorkload` builds one record and publishes it through the real
 *   `StreamSyncWriter`.
 * - `readForwardWorkload` imports the published parts into the read cache and
 *   walks the view with `viewBodies`, hashing each body piece as it passes: the
 *   work a server does when it forwards a body without parsing it.
 * - `readParseWorkload` does the same walk, then joins the pieces and parses
 *   them: the work of a final consumer that needs an object.
 *
 * `surface: "lite"` swaps the file adapters for the Lite ones (IndexedDB chunks
 * through fake-indexeddb, and the read-cache adapter). fake-indexeddb keeps its
 * records in the JS heap; real IndexedDB does not, so Lite numbers are an upper
 * bound for storage.
 */

import { createHash } from "node:crypto";
import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import {
  StreamSyncWriter,
  createStreamSyncKeyPorts,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import {
  createStreamSyncReadKeys,
  type StreamSyncReadFiles,
} from "@opendatalabs/personal-server-ts-core/stream-sync-read";
import { ViewStore } from "../../../core/src/stream-sync-read/view-store.js";
import {
  NO_OVERLAY,
  viewBodies,
} from "../../../core/src/stream-sync-read/lines.js";
import {
  canonicalJson,
  decodeHead,
  partBlobName,
  streamScope,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
import { createIndexedDbStreamSyncFiles } from "@opendatalabs/personal-server-ts-lite";
import { createStreamSyncReadCacheFiles } from "../../../lite/src/stream-sync-read-cache-files.js";
import { createFsStreamSyncFiles } from "./fs-files.js";
import {
  OWNER,
  OWNER_SIGNATURE,
  SERVER_KEY,
  OWNER_KEY,
  SHAPE,
  accountSigner,
  createFakeStreamSyncRegistry,
  finishedOutcome,
  testStreamSyncHome,
} from "./bounded-publish.harness.js";
import { fsReadFiles } from "./big-record.fs-read-files.js";
import { diskBlobs } from "./bounded-publish.workload.js";

export const CONNECTOR = "big-record";
export const STREAM = "items";

export interface BigArgs {
  readonly root: string;
  /** Canonical JSON bytes of the record body. */
  readonly bodyBytes: number;
  readonly surface: "node" | "lite";
}

export interface BigPublished {
  readonly scope: string;
  readonly headHex: string;
  readonly blobDir: string;
  readonly version: number;
}

/** A record whose canonical JSON body is exactly `bodyBytes` bytes. */
export function bigRecord(bodyBytes: number) {
  const shell = canonicalJson({ id: "big", pad: "" }).length;
  return { id: "big", pad: "a".repeat(bodyBytes - shell) };
}

function writerFiles(a: BigArgs) {
  return a.surface === "node"
    ? createFsStreamSyncFiles(join(a.root, "device"))
    : createIndexedDbStreamSyncFiles({
        dbName: "big-record",
        factory: new IDBFactory(),
        keyRange: IDBKeyRange,
      });
}

export async function writeWorkload(args: unknown): Promise<BigPublished> {
  const a = args as BigArgs;
  const registry = createFakeStreamSyncRegistry();
  const blobDir = join(a.root, "blobs");
  await mkdir(blobDir, { recursive: true });
  const writer = new StreamSyncWriter({
    ownerAddress: OWNER,
    registry,
    blobs: diskBlobs(blobDir),
    home: testStreamSyncHome(await writerFiles(a)),
    keys: createStreamSyncKeyPorts(OWNER_SIGNATURE),
    signer: accountSigner(a.surface === "node" ? SERVER_KEY : OWNER_KEY),
    declaredStreams: () => [],
  });
  const runId = "run-1";
  const observedAt = Date.UTC(2026, 10, 1);
  await writer.refreshControls();
  await writer.beginRun({
    runId,
    connector: CONNECTOR,
    userConnect: false,
    observedAt,
    identity: "none",
    checkpointUsed: null,
  });
  await writer.declareStream(runId, STREAM, SHAPE);
  await writer.append(runId, STREAM, bigRecord(a.bodyBytes));
  await writer.finishRun(runId, { checkpointCandidate: { cursor: runId } });
  await writer.publishPending();
  const finished = finishedOutcome(await writer.status(), runId)?.outcome;
  if (finished?.kind !== "checkpointed") {
    throw new Error(`publish did not checkpoint: ${JSON.stringify(finished)}`);
  }
  const scope = streamScope(CONNECTOR, "", STREAM);
  const row = await registry.read(scope);
  if (!row.found) throw new Error("stream not published");
  return {
    scope,
    headHex: row.dataHash.toLowerCase().replace(/^0x/, ""),
    blobDir,
    version: row.version,
  };
}

export interface BigReadArgs extends BigArgs {
  readonly published: BigPublished;
}

/** Import the published parts into the read cache; return the leased view. */
async function importView(a: BigReadArgs) {
  const p = a.published;
  const keys = await createStreamSyncReadKeys(
    Uint8Array.from(Buffer.from(OWNER_SIGNATURE.replace(/^0x/, ""), "hex")),
  );
  const blobs = diskBlobs(p.blobDir);
  const readFiles: StreamSyncReadFiles =
    a.surface === "node"
      ? fsReadFiles(join(a.root, "read"))
      : createStreamSyncReadCacheFiles(
          await createIndexedDbStreamSyncFiles({
            dbName: "big-record-read",
            factory: new IDBFactory(),
            keyRange: IDBKeyRange,
          }),
          keys.keyCheck,
        );
  const views = await ViewStore.open(readFiles);
  const cipher = await blobs.get(`${p.scope}/h-${p.headHex}`);
  if (!cipher) throw new Error("head missing");
  const clear = await keys.decrypt(p.scope, cipher);
  const decoded = decodeHead(clear);
  if (decoded.kind !== "ok") throw new Error(`head: ${decoded.kind}`);
  const head = decoded.head;
  const viewKey = { connector: CONNECTOR, ns: "", stream: STREAM };
  await views.withImport(viewKey, async (tx) => {
    // One part at a time: fetch, decrypt, store. The store checks the hash on read.
    for (const part of head.parts) {
      const partCipher = await blobs.get(
        `${p.scope}/${partBlobName(head.generation, part.hash)}`,
      );
      if (!partCipher) throw new Error("part missing");
      await tx.putPart(part.hash, await keys.decrypt(p.scope, partCipher));
    }
    await tx.commit(p.version, `0x${p.headHex}`, clear, head);
  });
  const lease = views.lease(viewKey);
  if (!lease) throw new Error("no lease");
  return { views, keys, lease, head };
}

export async function readForwardWorkload(
  args: unknown,
): Promise<{ bytes: number; sha256: string; records: number }> {
  const { views, keys, lease, head } = await importView(args as BigReadArgs);
  let bytes = 0;
  let records = 0;
  let sha256 = "";
  try {
    for await (const item of viewBodies(
      views,
      keys,
      lease,
      NO_OVERLAY,
      head.primaryKey,
    )) {
      const hash = createHash("sha256");
      for await (const piece of item.body()) {
        hash.update(piece);
        bytes += piece.length;
      }
      sha256 = hash.digest("hex");
      records += 1;
    }
  } finally {
    lease.release();
  }
  return { bytes, sha256, records };
}

export async function readParseWorkload(
  args: unknown,
): Promise<{ bytes: number; padLength: number }> {
  const { views, keys, lease, head } = await importView(args as BigReadArgs);
  let bytes = 0;
  let padLength = 0;
  try {
    for await (const item of viewBodies(
      views,
      keys,
      lease,
      NO_OVERLAY,
      head.primaryKey,
    )) {
      const decoder = new TextDecoder();
      let text = "";
      for await (const piece of item.body()) {
        bytes += piece.length;
        text += decoder.decode(piece, { stream: true });
      }
      text += decoder.decode();
      padLength = (JSON.parse(text) as { pad: string }).pad.length;
    }
  } finally {
    lease.release();
  }
  return { bytes, padLength };
}
