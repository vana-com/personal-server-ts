/**
 * The request quota a storage service publishes in a `RateLimit-Policy`
 * response header (IETF draft-ietf-httpapi-ratelimit-headers), and the feed
 * that carries it from an adapter's responses to the send governor.
 *
 * A storage service that publishes no policy leaves the governor with no
 * quota to pace to: it then paces nothing and reacts only to the answers.
 */

/** Bounds of a quota read from the wire, so a bad header cannot stall or unleash the gate. */
export const QUOTA_LIMIT_MAX = 1_000_000;
export const QUOTA_WINDOW_MAX_SECONDS = 24 * 60 * 60;

/** At most `limit` requests in any `windowMs` window. */
export interface QuotaPolicy {
  readonly limit: number;
  readonly windowMs: number;
}

/**
 * Reads a `RateLimit-Policy` value: a list of policies, each `q` requests per
 * `w` seconds, as `"name";q=240;w=60` or in the older `240;w=60` form. When it
 * lists several, the slowest one binds, so it is the one returned.
 * `undefined` when no policy in it is readable.
 */
export function parseRateLimitPolicy(
  value: string | null | undefined,
): QuotaPolicy | undefined {
  if (!value) return undefined;
  let slowest: QuotaPolicy | undefined;
  for (const item of value.split(",")) {
    const parts = item.split(";").map((part) => part.trim());
    const quota =
      numberParam(parts, "q") ??
      (/^\d+$/.test(parts[0] ?? "") ? Number(parts[0]) : undefined);
    const seconds = numberParam(parts, "w");
    if (
      !quota ||
      !seconds ||
      !Number.isFinite(quota) ||
      !Number.isFinite(seconds) ||
      quota < 1 ||
      seconds < 1 ||
      quota > QUOTA_LIMIT_MAX ||
      seconds > QUOTA_WINDOW_MAX_SECONDS
    )
      continue;
    const policy = { limit: quota, windowMs: seconds * 1000 };
    if (
      !slowest ||
      policy.limit / policy.windowMs < slowest.limit / slowest.windowMs
    ) {
      slowest = policy;
    }
  }
  return slowest;
}

function numberParam(
  parts: readonly string[],
  name: string,
): number | undefined {
  for (const part of parts) {
    const match = new RegExp(`^${name}=(\\d+(?:\\.\\d+)?)$`).exec(part);
    if (match) return Number(match[1]);
  }
  return undefined;
}

export type QuotaListener = (policy: QuotaPolicy) => void;

/** Fans the policy an adapter's responses publish out to its subscribers. */
export interface RateLimitPolicyFeed {
  /** `fetch`, which reports every response's `RateLimit-Policy` to the feed. */
  readonly fetch: typeof fetch;
  /**
   * Calls `listener` with the policy now in force, if a response already
   * published one, and then with every change.
   */
  subscribe(listener: QuotaListener): () => void;
}

export function createRateLimitPolicyFeed(): RateLimitPolicyFeed {
  const listeners = new Set<QuotaListener>();
  let latest: string | undefined;
  let current: QuotaPolicy | undefined;
  return {
    // `globalThis.fetch` is read per call, so a replaced global is honoured.
    async fetch(input, init) {
      const response = await globalThis.fetch(input, init);
      const header = response.headers.get("ratelimit-policy");
      if (header && header !== latest) {
        latest = header;
        const policy = parseRateLimitPolicy(header);
        if (policy) {
          current = policy;
          for (const listener of listeners) listener(policy);
        }
      }
      return response;
    },
    subscribe(listener) {
      listeners.add(listener);
      // A response seen before this subscriber attached is not lost.
      if (current) listener(current);
      return () => listeners.delete(listener);
    },
  };
}
