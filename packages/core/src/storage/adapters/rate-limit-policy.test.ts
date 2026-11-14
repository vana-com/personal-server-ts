import { afterEach, describe, expect, it, vi } from "vitest";
import {
  QUOTA_LIMIT_MAX,
  QUOTA_WINDOW_MAX_SECONDS,
  createRateLimitPolicyFeed,
  parseRateLimitPolicy,
  quotaFor,
} from "./rate-limit-policy.js";

afterEach(() => vi.unstubAllGlobals());

describe("createRateLimitPolicyFeed", () => {
  it("reports the policy of a response to its subscribers, once per change", async () => {
    const answers = [
      new Response("", { headers: { "ratelimit-policy": '"put";q=240;w=60' } }),
      new Response("", { headers: { "ratelimit-policy": '"put";q=240;w=60' } }),
      new Response("", { headers: { "ratelimit-policy": '"put";q=120;w=60' } }),
      new Response(""),
    ];
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => answers.shift()!),
    );
    const feed = createRateLimitPolicyFeed();
    const seen: unknown[] = [];
    const stop = feed.subscribe((policy) => seen.push(policy));
    for (let i = 0; i < 3; i++) await feed.fetch("https://storage.test/");
    expect(seen).toEqual([
      { named: { put: { limit: 240, windowMs: 60_000 } } },
      { named: { put: { limit: 120, windowMs: 60_000 } } },
    ]);
    stop();
    answers.push(
      new Response("", { headers: { "ratelimit-policy": "5;w=1" } }),
    );
    await feed.fetch("https://storage.test/");
    expect(seen).toHaveLength(2);
  });

  it("reports nothing when a response carries no policy", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("")),
    );
    const feed = createRateLimitPolicyFeed();
    const seen: unknown[] = [];
    feed.subscribe((policy) => seen.push(policy));
    await feed.fetch("https://storage.test/");
    expect(seen).toEqual([]);
  });
});

describe("a subscriber that attaches after the first response", () => {
  it("gets the policy already in force, then every change", async () => {
    const answers = [
      new Response("", { headers: { "ratelimit-policy": '"put";q=240;w=60' } }),
      new Response("", { headers: { "ratelimit-policy": '"put";q=120;w=60' } }),
    ];
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => answers.shift()!),
    );
    const feed = createRateLimitPolicyFeed();
    await feed.fetch("https://storage.test/");
    const seen: unknown[] = [];
    feed.subscribe((policy) => seen.push(policy));
    expect(seen).toEqual([
      { named: { put: { limit: 240, windowMs: 60_000 } } },
    ]);
    await feed.fetch("https://storage.test/");
    expect(seen).toEqual([
      { named: { put: { limit: 240, windowMs: 60_000 } } },
      { named: { put: { limit: 120, windowMs: 60_000 } } },
    ]);
  });

  it("gets nothing when no response has published a policy", () => {
    const seen: unknown[] = [];
    createRateLimitPolicyFeed().subscribe((policy) => seen.push(policy));
    expect(seen).toEqual([]);
  });
});

/** What a request of each kind is paced to, by the quota that names it. */
const pacing = (header: string) => {
  const policies = parseRateLimitPolicy(header)!;
  const of = (kind: string) => {
    const found = quotaFor(policies, kind);
    return found && found.quota.limit / (found.quota.windowMs / 1000);
  };
  return {
    put: of("put"),
    get: of("get"),
    head: of("head"),
    delete: of("delete"),
  };
};

describe("parseRateLimitPolicy", () => {
  // The header vana-storage dev sends on every response (policy-headers.ts).
  const DEV = '"put";q=240;w=60, "delete";q=30;w=60';

  it("paces each kind by the policy that names it: storage dev's header", () => {
    expect(parseRateLimitPolicy(DEV)).toEqual({
      named: {
        put: { limit: 240, windowMs: 60_000 },
        delete: { limit: 30, windowMs: 60_000 },
      },
    });
    // PUTs run at 240 a minute, whatever the DELETE limit is. GET and HEAD are
    // named by no policy, so no quota paces them.
    expect(pacing(DEV)).toEqual({
      put: 4,
      delete: 0.5,
      get: undefined,
      head: undefined,
    });
  });

  it("follows the 600 a minute PUT policy storage is about to send", () => {
    expect(pacing('"put";q=600;w=60')).toEqual({
      put: 10,
      get: undefined,
      head: undefined,
      delete: undefined,
    });
    expect(pacing('"put";q=600;w=60, "delete";q=30;w=60').put).toBe(10);
  });

  it("applies the unnamed form to every kind, as one allowance", () => {
    const policies = parseRateLimitPolicy("240;w=60")!;
    expect(quotaFor(policies, "put")).toEqual({
      bucket: "*",
      quota: { limit: 240, windowMs: 60_000 },
    });
    expect(quotaFor(policies, "get")?.bucket).toBe("*");
    expect(quotaFor(policies, "head")?.bucket).toBe("*");
    expect(parseRateLimitPolicy("q=240;w=60")?.unnamed).toEqual({
      limit: 240,
      windowMs: 60_000,
    });
  });

  it("ignores the unnamed form when a named policy is present", () => {
    expect(pacing('5;w=60, "put";q=240;w=60')).toEqual({
      put: 4,
      get: undefined,
      head: undefined,
      delete: undefined,
    });
  });

  it("keeps the slowest of several policies that name one kind, and of several unnamed ones", () => {
    expect(pacing('"put";q=100;w=1, "put";q=60;w=60').put).toBe(1);
    expect(pacing("100;w=1, 60;w=60").get).toBe(1);
  });

  it("reads a kind's name in any case, quoted or not", () => {
    expect(pacing('"PUT";q=240;w=60').put).toBe(4);
    expect(pacing("put;q=240;w=60").put).toBe(4);
  });

  it("takes no quota that is zero, not finite or outside the bounds", () => {
    const huge = "9".repeat(400);
    for (const bad of [
      "0;w=60",
      "10;w=0",
      `${huge};w=60`,
      `10;w=${huge}`,
      `${QUOTA_LIMIT_MAX + 1};w=60`,
      `10;w=${QUOTA_WINDOW_MAX_SECONDS + 1}`,
      '"put";q=0;w=60',
      `"put";q=${huge};w=60`,
    ]) {
      expect(parseRateLimitPolicy(bad)).toBeUndefined();
    }
    expect(
      parseRateLimitPolicy(
        `"put";q=${QUOTA_LIMIT_MAX};w=${QUOTA_WINDOW_MAX_SECONDS}`,
      ),
    ).toEqual({
      named: {
        put: {
          limit: QUOTA_LIMIT_MAX,
          windowMs: QUOTA_WINDOW_MAX_SECONDS * 1000,
        },
      },
    });
  });

  it("skips an unreadable policy and keeps a readable one beside it", () => {
    expect(parseRateLimitPolicy("junk, 5;w=10")).toEqual({
      named: {},
      unnamed: { limit: 5, windowMs: 10_000 },
    });
    // An unreadable named policy does not count as present.
    expect(parseRateLimitPolicy('"put";q=0;w=60, 5;w=10')).toEqual({
      named: {},
      unnamed: { limit: 5, windowMs: 10_000 },
    });
  });
});
