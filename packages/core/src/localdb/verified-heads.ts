import type { Head } from "@opendatalabs/personal-server-ts-stream-sync";
import type { LocalSyncDeps } from "./deps.js";

/**
 * Verified registry heads by (scope, data hash, key check). A head blob is
 * named by its data hash and never changes, so a head verified once need not
 * be downloaded again. Without this every cycle downloaded one head blob per
 * stream of every connection, quiet or not; the storage service rejects a
 * burst of reads, and a cycle that has real work to publish then fails before
 * it posts anything.
 *
 * The cache belongs to one blob port (`deps.blobs`): a different port is a
 * different store and starts empty. A hit says what the head's bytes are. It
 * is never permission to publish: lifetime and control are decided on every
 * snapshot, from the registry.
 */
const verifiedHeads = new WeakMap<object, Map<string, Head>>();
const MAX_VERIFIED_HEADS = 512;

function cacheOf(deps: Pick<LocalSyncDeps, "blobs">): Map<string, Head> {
  let cache = verifiedHeads.get(deps.blobs);
  if (!cache) {
    cache = new Map();
    verifiedHeads.set(deps.blobs, cache);
  }
  return cache;
}

const keyOf = (scope: string, dataHash: string, keyCheck: string): string =>
  `${scope}|${dataHash.toLowerCase()}|${keyCheck}`;

/** The head verified for this hash and key check, or `undefined`. */
export function recallHead(
  deps: Pick<LocalSyncDeps, "blobs">,
  scope: string,
  dataHash: string,
  keyCheck: string,
): Head | undefined {
  return cacheOf(deps).get(keyOf(scope, dataHash, keyCheck));
}

/** Remember a head that `verifyHead` accepted after it was downloaded. */
export function rememberHead(
  deps: Pick<LocalSyncDeps, "blobs">,
  scope: string,
  dataHash: string,
  keyCheck: string,
  head: Head,
): void {
  const cache = cacheOf(deps);
  const key = keyOf(scope, dataHash, keyCheck);
  cache.delete(key);
  cache.set(key, head);
  if (cache.size > MAX_VERIFIED_HEADS) {
    cache.delete(cache.keys().next().value!);
  }
}

/**
 * Remember the head this device built, verified and committed. The caller
 * keeps its own `head`; the cache holds a deep, frozen copy, so a later
 * mutation cannot change what the next snapshot reads.
 */
export function rememberOwnHead(
  deps: Pick<LocalSyncDeps, "blobs">,
  scope: string,
  dataHash: string,
  keyCheck: string,
  head: Head,
): void {
  const copy = structuredClone(head);
  const freeze = (value: unknown): void => {
    if (value === null || typeof value !== "object") return;
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  };
  freeze(copy);
  rememberHead(deps, scope, dataHash, keyCheck, copy);
}
