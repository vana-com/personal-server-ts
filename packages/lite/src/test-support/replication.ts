/**
 * In-memory reference implementations of the Lite replication host ports, for
 * tests. Not durable storage. The transport reference is the Node contract
 * harness (`server/src/storage/pdpp-replica-contract.test-utils.ts`
 * `network()` for the DPv2 port, `createMemoryReplicaObjectTransfers` below
 * for native object I/O, and core's `createTestReplicaRoster` for the roster.
 */
import { sha256 } from "viem";
import type { ProgressReport } from "@opendatalabs/personal-server-ts-core/replication/coordinator";
import type { ReplicaBudget } from "@opendatalabs/personal-server-ts-core/replication/coordinator";
import type { LiteStagingId } from "../canonical-persistence.js";
import {
  LiteReplicaTransferError,
  type LiteReplicaObjectTransfers,
  type LiteReplicaPersistence,
  type LiteReplicaSql,
  type LiteReplicaTransaction,
  type LiteReplicaTransferCall,
  type LiteReplicationEngine,
} from "../replication-ports.js";
import {
  collectStagedBlob,
  fakeCanonicalDisk,
  storagePage,
  type FakeCanonicalDisk,
} from "./canonical-persistence.js";

const FRAME_BYTES = 128 * 1024;
const VALUE_BYTES = 256 * 1024;
/** Unattached staged bytes the reference holds at once, as the native side does. */
export const MEMORY_STAGED_BYTES_CAP = 32 * 1024 * 1024;

export interface MemoryReplicaDisk extends FakeCanonicalDisk {
  bytes: Map<string, Uint8Array>;
}
/** The persistence port plus the stage release a cancelled transfer needs. */
export type MemoryReplicaPersistencePort = LiteReplicaPersistence & {
  /** Drop an unattached stage. A no-op for an unknown or attached id. */
  discardBytes(id: string): void;
};
export const memoryReplicaDisk = (): MemoryReplicaDisk => ({
  ...fakeCanonicalDisk(),
  bytes: new Map(),
});

const sha256Of = (bytes: Uint8Array) => sha256(bytes).slice(2);

/**
 * `LiteReplicaPersistence` over maps. Transactions run one at a time on a
 * copy and replace the disk only when the callback resolves, so a throw
 * rolls back rows, blobs and bytes together. Staged bytes stay invisible
 * until a transaction attaches them. Unattached stages share one byte cap
 * (`maxStagedBytes`): a stage that would pass it fails `storage-full`, so an
 * abandoned stage costs space until `discardBytes` releases it.
 */
export function createMemoryReplicaPersistence(
  disk = memoryReplicaDisk(),
  opts: { maxStagedBytes?: number } = {},
) {
  const maxStagedBytes = opts.maxStagedBytes ?? MEMORY_STAGED_BYTES_CAP;
  const staged = new Map<string, Uint8Array>();
  // Bytes of stages still being consumed: reserved so that two concurrent
  // stages cannot both fit a cap only one fits.
  let inFlight = 0;
  const stagedTotal = () => {
    let total = 0;
    for (const value of staged.values()) total += value.length;
    return total;
  };
  const stagedBlobs = new Map<
    string,
    Awaited<ReturnType<typeof collectStagedBlob>>
  >();
  let queue = Promise.resolve();
  let failBeforeCommit = false;
  const port: MemoryReplicaPersistencePort = {
    transaction<T>(run: (tx: LiteReplicaTransaction) => Promise<T>) {
      const work = queue.then(async () => {
        const rows = new Map(disk.rows);
        const blobs = new Map(disk.blobs);
        const bytes = new Map(disk.bytes);
        const tx: LiteReplicaTransaction = {
          async get(key) {
            return rows.get(key);
          },
          async put(key, value) {
            if (new TextEncoder().encode(value).length > VALUE_BYTES)
              throw new Error("native value exceeds 256 KiB");
            rows.set(key, value);
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
            const value = stagedBlobs.get(id);
            if (!value || value.descriptor.sha256 !== expected.sha256)
              throw new Error("unknown staged blob");
            blobs.set(expected.blobId, value);
          },
          async blob(id) {
            return blobs.get(id)?.descriptor;
          },
          async attachBytes(stagingId, expected) {
            const value = staged.get(stagingId) ?? bytes.get(stagingId);
            if (!value) throw new Error("unknown staged bytes");
            if (
              value.length !== expected.length ||
              sha256Of(value) !== expected.sha256
            )
              throw new Error("staged bytes do not match");
            bytes.set(stagingId, value);
          },
          async releaseBytes(id) {
            bytes.delete(id);
          },
          sql: noSql,
        };
        const result = await run(tx);
        if (failBeforeCommit) {
          failBeforeCommit = false;
          throw new Error("interrupted:before-commit");
        }
        disk.rows = rows;
        disk.blobs = blobs;
        disk.bytes = bytes;
        for (const id of bytes.keys()) staged.delete(id);
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
      const id = globalThis.crypto.randomUUID() as LiteStagingId;
      stagedBlobs.set(id, value);
      return id;
    },
    async *readBlob(id) {
      const value = disk.blobs.get(id);
      if (!value) throw new Error("missing committed blob");
      yield* frames(value.bytes);
    },
    async stageBytes(chunks) {
      const parts: Uint8Array[] = [];
      let size = 0;
      try {
        for await (const part of chunks) {
          if (part.length > FRAME_BYTES)
            throw new Error("native frame exceeds 128 KiB");
          if (stagedTotal() + inFlight + part.length > maxStagedBytes)
            throw new LiteReplicaTransferError("storage-full");
          parts.push(part.slice());
          size += part.length;
          inFlight += part.length;
        }
      } catch (error) {
        inFlight -= size;
        throw error;
      }
      const value = new Uint8Array(size);
      let offset = 0;
      for (const part of parts) {
        value.set(part, offset);
        offset += part.length;
      }
      const id = globalThis.crypto.randomUUID();
      inFlight -= size;
      staged.set(id, value);
      return id;
    },
    async *readBytes(id) {
      const value = disk.bytes.get(id);
      if (!value) throw new Error("missing attached bytes");
      yield* frames(value);
    },
    discardBytes(id) {
      staged.delete(id);
    },
  };
  return {
    port,
    disk,
    /** Unattached staged bytes, for tests. */
    stagedBytes: stagedTotal,
    /** The next transaction throws after its callback, before it commits. */
    failNextCommit() {
      failBeforeCommit = true;
    },
  };
}

/**
 * The map double has no relational store. The phase engine needs one; run it
 * on the SQLite double (`server/src/storage/lite-replica-sqlite.test-utils.ts`).
 */
const noSql: LiteReplicaSql = {
  get: () => Promise.reject(new Error("memory replica double has no SQL")),
  all: () => Promise.reject(new Error("memory replica double has no SQL")),
  run: () => Promise.reject(new Error("memory replica double has no SQL")),
  exec: () => Promise.reject(new Error("memory replica double has no SQL")),
};

function* frames(bytes: Uint8Array) {
  if (bytes.length === 0) yield new Uint8Array(0);
  for (let i = 0; i < bytes.length; i += FRAME_BYTES)
    yield bytes.slice(i, i + FRAME_BYTES);
}

/**
 * Native object I/O over a map of URL to bytes, staging downloads into
 * `persistence` and uploading its attached bytes. At most `maxTransfers` run
 * at once; one more fails `busy`, as the native gate refuses rather than
 * queueing. An aborted call fails `cancelled` and leaves no stage behind:
 * a stage made before the abort is discarded. A transfer still running at its
 * `deadlineMs` fails `timeout`, frees its capacity at once and discards the
 * stage it makes late.
 */
export function createMemoryReplicaObjectTransfers(
  persistence: MemoryReplicaPersistencePort,
  opts: { maxTransfers?: number } = {},
) {
  const objects = new Map<string, Uint8Array>();
  const maxTransfers = opts.maxTransfers ?? 2;
  let active = 0;
  async function transfer<T>(
    call: LiteReplicaTransferCall,
    run: () => Promise<T>,
    discard?: (result: T) => void,
  ) {
    const { signal, deadlineMs } = call;
    if (signal.aborted) throw new LiteReplicaTransferError("cancelled");
    if (active >= maxTransfers) throw new LiteReplicaTransferError("busy");
    active++;
    let held = true;
    const release = () => {
      if (held) active--;
      held = false;
    };
    let timer: ReturnType<typeof setTimeout> | undefined;
    let timedOut = false;
    const work = run();
    const deadline = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => {
        // As the native side does at its deadline: free the capacity now and
        // drop what the late transfer stages.
        timedOut = true;
        release();
        reject(new LiteReplicaTransferError("timeout"));
      }, deadlineMs);
    });
    try {
      const result = await Promise.race([work, deadline]);
      if (signal.aborted) {
        discard?.(result);
        throw new LiteReplicaTransferError("cancelled");
      }
      return result;
    } finally {
      clearTimeout(timer);
      release();
      if (timedOut)
        void work.then(
          (late) => discard?.(late),
          () => {},
        );
    }
  }
  const port: LiteReplicaObjectTransfers = {
    download({ url, maxBytes, expected }, call) {
      return transfer(
        call,
        async () => {
          const value = objects.get(url);
          if (!value) throw new LiteReplicaTransferError("not-found");
          if (value.length > maxBytes)
            throw new LiteReplicaTransferError("too-large");
          const info = { length: value.length, sha256: sha256Of(value) };
          if (expected && expected.length !== info.length)
            throw new LiteReplicaTransferError("length-mismatch");
          if (expected && expected.sha256 !== info.sha256)
            throw new LiteReplicaTransferError("digest-mismatch");
          const stagingId = await persistence.stageBytes(
            (async function* () {
              yield* frames(value);
            })(),
          );
          return { stagingId, ...info };
        },
        (staged) => persistence.discardBytes(staged.stagingId),
      );
    },
    probe({ url }, call) {
      return transfer(call, async () => objects.has(url));
    },
    upload({ url, bytesId }, call) {
      return transfer(call, async () => {
        const parts: Uint8Array[] = [];
        for await (const part of persistence.readBytes(bytesId))
          parts.push(part);
        const value = new Uint8Array(
          parts.reduce((n, part) => n + part.length, 0),
        );
        let offset = 0;
        for (const part of parts) {
          value.set(part, offset);
          offset += part.length;
        }
        objects.set(url, value);
        return { status: 201 };
      });
    },
  };
  return { port, objects };
}

/**
 * A scripted engine: each step returns the next report (the last repeats)
 * and records the budget it was given. A step honours its abort signal.
 */
export function createScriptedReplicationEngine(
  reports: ProgressReport[],
  opts: { stepMs?: number } = {},
) {
  const budgets: ReplicaBudget[] = [];
  const dependencies: string[] = [];
  let aborted = 0;
  const engine: LiteReplicationEngine = {
    async step({ budget, signal }) {
      budgets.push(budget);
      if (opts.stepMs)
        await new Promise<void>((resolve) => {
          const timer = setTimeout(resolve, opts.stepMs);
          signal.addEventListener(
            "abort",
            () => {
              clearTimeout(timer);
              aborted++;
              resolve();
            },
            { once: true },
          );
        });
      return reports[Math.min(budgets.length - 1, reports.length - 1)]!;
    },
    onDependencyChanged(key) {
      dependencies.push(key);
    },
  };
  return {
    engine,
    budgets,
    dependencies,
    get aborted() {
      return aborted;
    },
  };
}
