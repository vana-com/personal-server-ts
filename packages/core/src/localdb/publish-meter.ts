import type { StreamSyncBlobs } from "../stream-sync/ports.js";
import type { LocalSyncDeps } from "./deps.js";

/**
 * What one stream's publish spends, for the single log line it ends with. All
 * `*Ms` fields add up the durations of the calls they name, so they stay
 * correct if those calls later run in parallel (they then exceed `totalMs`).
 */
export interface PublishMeter {
  /** Snapshot and plan: the slot turn that freezes the rows to send. */
  planMs: number;
  /** The whole transfer: spool reads, framing, hashing, encryption, upload. */
  transferMs: number;
  /** Blob GET and PUT calls only: the part of the transfer spent on the wire. */
  uploadMs: number;
  /** Signing and posting the head to the registry. */
  headRegisterMs: number;
  /** Blob reads: a GET of a body, or an existence probe (a HEAD, no body). */
  blobGets: number;
  blobPuts: number;
  /** Part blobs written (a part already in storage is a GET and no PUT). */
  partsUploaded: number;
  /** Bytes of every blob written: parts, attachments and the head. */
  bytesUploaded: number;
}

export function newPublishMeter(): PublishMeter {
  return {
    planMs: 0,
    transferMs: 0,
    uploadMs: 0,
    headRegisterMs: 0,
    blobGets: 0,
    blobPuts: 0,
    partsUploaded: 0,
    bytesUploaded: 0,
  };
}

/** Run `work` and hand its duration to `add`, also when it throws. */
export async function timed<T>(
  deps: Pick<LocalSyncDeps, "now">,
  add: (ms: number) => void,
  work: () => Promise<T>,
): Promise<T> {
  const startedAt = deps.now();
  try {
    return await work();
  } finally {
    add(deps.now() - startedAt);
  }
}

/**
 * The same blob port, counted and timed. It is a view for the transfer's own
 * calls only: reads elsewhere key a cache on the original port's identity.
 */
export function meteredBlobs(
  deps: Pick<LocalSyncDeps, "now" | "blobs">,
  meter: PublishMeter,
): StreamSyncBlobs {
  const add = (ms: number) => {
    meter.uploadMs += ms;
  };
  return {
    get: (key) => {
      meter.blobGets += 1;
      return timed(deps, add, () => deps.blobs.get(key));
    },
    exists: (key) => {
      meter.blobGets += 1;
      return timed(deps, add, () => deps.blobs.exists(key));
    },
    put: async (key, bytes) => {
      meter.blobPuts += 1;
      await timed(deps, add, () => deps.blobs.put(key, bytes));
      meter.bytesUploaded += bytes.length;
    },
  };
}

/** The fields of the log line, named as a journey reads them. */
export function publishTimings(meter: PublishMeter, totalMs: number) {
  return {
    planMs: meter.planMs,
    encodeEncryptMs: Math.max(0, meter.transferMs - meter.uploadMs),
    partsUploaded: meter.partsUploaded,
    bytesUploaded: meter.bytesUploaded,
    blobGets: meter.blobGets,
    blobPuts: meter.blobPuts,
    uploadMs: meter.uploadMs,
    headRegisterMs: meter.headRegisterMs,
    totalMs,
  };
}
