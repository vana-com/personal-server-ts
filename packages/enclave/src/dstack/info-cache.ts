/**
 * One DstackInfo read per CVM, shared by every caller on the node.
 *
 * Everything DstackInfo carries — app id, instance id, compose hash, OS image,
 * guest-agent version — is fixed when the CVM boots, but the guest agent can
 * be slow to answer Info: ~15.0 s per call on the 2026-09-11 prod5 worker
 * fleet against 0.3 s on prod9, a host property no code inside the CVM can
 * fix. GetKey and GetQuote are unaffected. So the read belongs at boot, never
 * on a request:
 *
 *   boot            warmDstackInfo()    one unbudgeted Info, duration logged
 *   identity, seal  dstackInfo()        cached; empty => budget, then throw
 *   health          cachedDstackInfo()  cached; empty => budget, then undefined
 *
 * A read past the TTL starts a refresh in the background and still answers
 * from the cache, so a guest-agent upgrade under a running CVM is picked up
 * without ever putting a 15 s call in front of a caller.
 */

import type { DstackClient, DstackInfo } from "./client.js";

/**
 * Longest any request path waits on the guest agent. Only reachable before
 * the boot-time read has landed; after that every read is served from memory.
 */
export const DSTACK_INFO_BUDGET_MS = 2_000;

/**
 * How long a cached read stands before a background refresh is started. The
 * answer is the same for the CVM's lifetime, so this TTL only exists to pick
 * up a guest agent replaced under a running CVM.
 */
export const DSTACK_INFO_TTL_MS = 300_000;

const DSTACK_INFO_READ_MESSAGE = "dstack Info read";

/** Nothing cached and the guest agent did not answer inside the budget. */
export class DstackInfoUnavailable extends Error {
  constructor() {
    super("dstack Info is unavailable on this node");
    this.name = new.target.name;
  }
}

/** Just enough of the agent and controller loggers to record the boot read. */
interface InfoLogger {
  info(context: Record<string, unknown>, message: string): void;
}

interface InfoCache {
  info?: DstackInfo;
  readAt: number;
  pending?: Promise<DstackInfo>;
}

// Keyed by client so each agent — and each test — has its own cache, and so a
// discarded client does not keep one alive.
const caches = new WeakMap<DstackClient, InfoCache>();

/**
 * Populates the cache at boot, unbudgeted: 15 s once is the price of never
 * paying it on a request. Callers await this before serving. Idempotent, so a
 * boot path that warms in two places still reads the guest agent once.
 */
export async function warmDstackInfo(
  client: DstackClient,
  logger?: InfoLogger,
): Promise<DstackInfo> {
  const cache = cacheFor(client);
  if (cache.info) {
    return cache.info;
  }

  const startedAt = Date.now();
  const info = await refresh(client, cache);

  logger?.info(
    {
      durationMs: Date.now() - startedAt,
      appId: info.appId,
      instanceId: info.instanceId,
      composeHash: info.composeHash,
    },
    DSTACK_INFO_READ_MESSAGE,
  );

  return info;
}

/**
 * The cached Info, for callers that cannot proceed without it — identity
 * evidence must never be minted with an unknown compose hash. Fails closed
 * when the cache is empty and the guest agent does not answer in budget.
 */
export async function dstackInfo(client: DstackClient): Promise<DstackInfo> {
  const info = await cachedDstackInfo(client);
  if (!info) {
    throw new DstackInfoUnavailable();
  }

  return info;
}

/**
 * The cached Info, for callers that would rather answer without it than hang.
 * A read that fails still throws; only a read that is merely slow resolves
 * undefined.
 */
export async function cachedDstackInfo(
  client: DstackClient,
): Promise<DstackInfo | undefined> {
  const cache = cacheFor(client);

  if (cache.info) {
    // Stale while revalidate: answer from the cache now, let the refresh land
    // for a later caller.
    if (Date.now() - cache.readAt >= DSTACK_INFO_TTL_MS) {
      void refresh(client, cache).catch(() => undefined);
    }

    return cache.info;
  }

  // Nothing cached yet, so wait — but only for the budget. A failure still
  // propagates, and an unexpected one is what makes the health route 500.
  const pending = refresh(client, cache);
  void pending.catch(() => undefined);

  return Promise.race([pending, expire(DSTACK_INFO_BUDGET_MS)]);
}

function cacheFor(client: DstackClient): InfoCache {
  const existing = caches.get(client);
  if (existing) {
    return existing;
  }

  const created: InfoCache = { readAt: 0 };
  caches.set(client, created);

  return created;
}

// One read at a time: a guest agent that takes 15 s must not accumulate a call
// per request behind it.
function refresh(client: DstackClient, cache: InfoCache): Promise<DstackInfo> {
  cache.pending ??= client.info().then(
    (info) => {
      cache.info = info;
      cache.readAt = Date.now();
      cache.pending = undefined;

      return info;
    },
    (error: unknown) => {
      cache.pending = undefined;

      throw error;
    },
  );

  return cache.pending;
}

function expire(ms: number): Promise<undefined> {
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve(undefined);
    }, ms).unref();
  });
}
