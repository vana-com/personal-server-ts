import type { DstackClient, DstackInfo } from "../dstack/client.js";
import type { FleetConfigValidity } from "../fleet/security-config.js";
import type { HealthResponse } from "./types.js";

/**
 * Longest health will wait on the dstack guest agent. Callers poll this route
 * with short budgets (the fleet poller used 8 s), so a guest agent that answers
 * Info slowly — ~15.0 s per call on the 2026-09-11 worker fleet — must never be
 * on the critical path of a reply.
 */
export const HEALTH_INFO_BUDGET_MS = 2_000;

/**
 * How long a cached read stands before a refresh is started. Everything in
 * DstackInfo is fixed when the CVM boots, so the cache is the same answer; the
 * TTL only exists so a guest-agent upgrade under a running CVM is picked up.
 */
export const HEALTH_INFO_TTL_MS = 60_000;

/** Reported in place of the dstack fields when nothing has ever been read. */
const DSTACK_UNREACHABLE = "unreachable";

interface InfoCache {
  info?: DstackInfo;
  readAt: number;
  pending?: Promise<DstackInfo>;
}

// Keyed by client so each agent — and each test — has its own cache, and so a
// discarded client does not keep one alive.
const caches = new WeakMap<DstackClient, InfoCache>();

export async function readHealth(
  client: DstackClient,
  nodeId: string | null,
  activeSandboxes = 0,
  draining = false,
  config?: FleetConfigValidity,
): Promise<HealthResponse> {
  const info = await currentInfo(client);

  return {
    ...info,
    // Answering without appId/composeHash/instanceId beats hanging: a caller
    // that needs them retries, one that only needs draining is served.
    ...(info ? {} : { dstack: DSTACK_UNREACHABLE }),
    nodeId,
    activeSandboxes,
    draining,
    configIssuedAt: config?.issuedAt ?? null,
    // A signed non-expiring bundle and an unsigned agent both report null here;
    // configIssuedAt distinguishes them.
    configExpiresAt: config?.expiresAt ?? null,
  };
}

async function currentInfo(
  client: DstackClient,
): Promise<DstackInfo | undefined> {
  const cache = cacheFor(client);

  if (cache.info) {
    // Stale while revalidate: answer from the cache now, let the refresh land
    // for a later caller.
    if (Date.now() - cache.readAt >= HEALTH_INFO_TTL_MS) {
      void refresh(client, cache).catch(() => undefined);
    }

    return cache.info;
  }

  // Nothing cached yet, so wait — but only for the budget. A failure still
  // propagates, and an unexpected one is what makes the route report 500.
  const pending = refresh(client, cache);
  void pending.catch(() => undefined);

  return Promise.race([pending, expire(HEALTH_INFO_BUDGET_MS)]);
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
// per health request behind it.
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
