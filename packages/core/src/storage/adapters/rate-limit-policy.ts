/**
 * The request quotas a storage service publishes in a `RateLimit-Policy`
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
 * What a `RateLimit-Policy` value says, by the request kind each policy names.
 * A service limits its kinds separately (vana-storage: `"put";q=240;w=60,
 * "delete";q=30;w=60`), so one number for all requests would pace a PUT to the
 * DELETE limit.
 */
export interface QuotaPolicies {
  /** Policies that name a kind, by lower-case name (`put`, `delete`, ...). */
  readonly named: Readonly<Record<string, QuotaPolicy>>;
  /**
   * The unnamed form (`240;w=60`): it applies to every request, and only when
   * the value names no readable policy.
   */
  readonly unnamed?: QuotaPolicy;
}

/** The quota that paces a kind, and the bucket whose tokens it spends. */
export interface QuotaForKind {
  /**
   * Kinds with the same bucket share one allowance: the kind's own name for a
   * named policy, `"*"` for the unnamed form, which limits all requests together.
   */
  readonly bucket: string;
  readonly quota: QuotaPolicy;
}

/**
 * The quota that paces requests of `kind`, or `undefined` when none does: a
 * kind no policy names is not paced by quota (a 429 or 503 still backs it
 * off). The unnamed form applies to every kind only when no policy is named.
 */
export function quotaFor(
  policies: QuotaPolicies,
  kind: string,
): QuotaForKind | undefined {
  if (Object.keys(policies.named).length > 0) {
    const quota = policies.named[kind];
    return quota && { bucket: kind, quota };
  }
  return policies.unnamed && { bucket: "*", quota: policies.unnamed };
}

/**
 * Reads a `RateLimit-Policy` value: a list of policies, each `q` requests per
 * `w` seconds, as `"name";q=240;w=60` or in the older `240;w=60` form. A name
 * is the request kind the policy limits. Several policies for one name: the
 * slowest binds. `undefined` when no policy in it is readable.
 */
export function parseRateLimitPolicy(
  value: string | null | undefined,
): QuotaPolicies | undefined {
  if (!value) return undefined;
  const named: Record<string, QuotaPolicy> = {};
  let unnamed: QuotaPolicy | undefined;
  for (const item of value.split(",")) {
    const parts = item.split(";").map((part) => part.trim());
    const first = parts[0] ?? "";
    const legacy = /^\d+$/.test(first);
    const quota =
      numberParam(parts, "q") ?? (legacy ? Number(first) : undefined);
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
    // No name: `240;w=60`, or a first parameter such as `q=240`.
    if (legacy || first === "" || first.includes("=")) {
      unnamed = slower(unnamed, policy);
      continue;
    }
    const name = first.replace(/^"(.*)"$/, "$1").toLowerCase();
    named[name] = slower(named[name], policy);
  }
  if (Object.keys(named).length === 0 && !unnamed) return undefined;
  return { named, ...(unnamed ? { unnamed } : {}) };
}

function slower(a: QuotaPolicy | undefined, b: QuotaPolicy): QuotaPolicy {
  return !a || b.limit / b.windowMs < a.limit / a.windowMs ? b : a;
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

export type QuotaListener = (policies: QuotaPolicies) => void;

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
  let current: QuotaPolicies | undefined;
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
