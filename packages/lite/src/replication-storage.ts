/**
 * Replica object storage over the native transfers (host contract §4.2), as
 * the storage adapter core's DPv2 replica transport (`replication/dpv2.ts`)
 * takes. Bulk bytes move natively and land in replica byte storage; JS sees
 * only what one fragment or manifest read needs. Gateway calls (register,
 * evidence, owner feed) stay in PS JS core over Lite's HTTP client.
 */
import { sha256 } from "viem";
import {
  AdditionsBudgetExceeded,
  type ByteBudget,
} from "@opendatalabs/personal-server-ts-core/additions";
import {
  StoredBlobConflictError,
  type BoundedStorageAdapter,
} from "@opendatalabs/personal-server-ts-core/storage/adapters";
import {
  LiteReplicaTransferError,
  type LiteReplicaObjectTransfers,
  type LiteReplicaPersistence,
} from "./replication-ports.js";

const FRAME_BYTES = 128 * 1024;
/** Deadline of one transfer when the caller's budget sets none. */
export const LITE_REPLICA_TRANSFER_DEADLINE_MS = 60_000;

function* frames(bytes: Uint8Array) {
  if (bytes.length === 0) yield new Uint8Array(0);
  for (let i = 0; i < bytes.length; i += FRAME_BYTES)
    yield bytes.subarray(i, i + FRAME_BYTES);
}

/** A storage failure the DPv2 transport reads as definitive absence. */
const notFound = (url: string) =>
  Object.assign(new Error(`replica object not found: ${url}`), {
    status: 404,
  });

export function createLiteReplicaStorage(input: {
  persistence: LiteReplicaPersistence;
  transfers: LiteReplicaObjectTransfers;
  /** The object URL of a storage key (the inverse of the storage layout). */
  urlForKey(key: string): string;
  /** Upload headers, e.g. storage authorization. */
  headers?: () => Record<string, string>;
  deadlineMs?: number;
}): BoundedStorageAdapter {
  const { persistence, transfers } = input;
  const deadline = (budget?: ByteBudget) =>
    Math.max(
      1,
      Math.min(
        input.deadlineMs ?? LITE_REPLICA_TRANSFER_DEADLINE_MS,
        budget?.remainingMilliseconds ?? Infinity,
      ),
    );
  const attach = (id: string, length: number, digest: string) =>
    persistence.transaction((tx) =>
      tx.attachBytes(id, { length, sha256: digest }),
    );
  const release = (id: string) =>
    persistence.transaction((tx) => tx.releaseBytes(id));
  async function read(id: string) {
    const parts: Uint8Array[] = [];
    let size = 0;
    for await (const part of persistence.readBytes(id)) {
      parts.push(part);
      size += part.length;
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const part of parts) {
      bytes.set(part, offset);
      offset += part.length;
    }
    return bytes;
  }
  const unsupported = (): never => {
    throw new Error("Lite replica storage supports bounded reads only");
  };
  return {
    urlForKey: (key) => input.urlForKey(key),
    /**
     * Write-once: the native upload of different bytes to a stored key
     * fails with HTTP 409, which is `StoredBlobConflictError`.
     */
    async upload(key, data) {
      const url = input.urlForKey(key);
      const id = await persistence.stageBytes(
        (async function* () {
          yield* frames(data);
        })(),
      );
      await attach(id, data.length, sha256(data).slice(2));
      try {
        const controller = new AbortController();
        await transfers.upload(
          { url, method: "PUT", headers: input.headers?.() ?? {}, bytesId: id },
          { signal: controller.signal, deadlineMs: deadline() },
        );
      } catch (error) {
        if (
          error instanceof LiteReplicaTransferError &&
          error.code === "http-status" &&
          /\b409\b/.test(error.message)
        )
          throw new StoredBlobConflictError(key);
        throw error;
      } finally {
        await release(id);
      }
      return url;
    },
    /**
     * At most `budget.remaining` bytes. A spent budget only probes: a present
     * object is over budget, a missing one is not found.
     */
    async downloadBounded(url, budget) {
      const signal = budget.signal ?? new AbortController().signal;
      const call = { signal, deadlineMs: deadline(budget) };
      if (budget.remaining <= 0) {
        if (!(await transfers.probe({ url }, call))) throw notFound(url);
        throw new AdditionsBudgetExceeded("replica object exceeds budget");
      }
      let staged;
      try {
        staged = await transfers.download(
          { url, maxBytes: budget.remaining },
          call,
        );
      } catch (error) {
        if (error instanceof LiteReplicaTransferError) {
          if (error.code === "not-found") throw notFound(url);
          if (error.code === "too-large")
            throw new AdditionsBudgetExceeded("replica object exceeds budget");
        }
        throw error;
      }
      budget.recordSpent(staged.length);
      await attach(staged.stagingId, staged.length, staged.sha256);
      try {
        return await read(staged.stagingId);
      } finally {
        await release(staged.stagingId);
      }
    },
    download: unsupported,
    delete: unsupported,
    exists: unsupported,
  };
}
