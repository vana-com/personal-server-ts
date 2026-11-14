import type { StreamSyncBlobs } from "../stream-sync/ports.js";

/**
 * Hold `bytes` of the store's memory budget (see
 * `StorageAccessPolicy.maxBytesInFlight`) and return the release. A transfer
 * calls it before it builds, reads or encrypts the data the bytes stand for,
 * and releases once the upload of that data has settled. An upload never asks
 * for bytes, and a builder asks for its next reservation only while it holds
 * none, so a held reservation always ends and reservations cannot wait on
 * each other. A store without a governor holds nothing.
 *
 * `objectBytes` is the size of the stored object when the memory held is
 * larger (an attachment or a part is in memory as plain and as encrypted bytes). The
 * governor refuses an object larger than the store accepts.
 */
export async function holdMemory(
  blobs: Pick<StreamSyncBlobs, "governor">,
  bytes: number,
  objectBytes?: number,
): Promise<() => void> {
  return (await blobs.governor?.reserve(bytes, objectBytes)) ?? (() => {});
}
