import { afterEach, describe, expect, it, vi } from "vitest";
import {
  QUOTA_LIMIT_MAX,
  QUOTA_WINDOW_MAX_SECONDS,
  createRateLimitPolicyFeed,
  parseRateLimitPolicy,
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
      { limit: 240, windowMs: 60_000 },
      { limit: 120, windowMs: 60_000 },
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
    expect(seen).toEqual([{ limit: 240, windowMs: 60_000 }]);
    await feed.fetch("https://storage.test/");
    expect(seen).toEqual([
      { limit: 240, windowMs: 60_000 },
      { limit: 120, windowMs: 60_000 },
    ]);
  });

  it("gets nothing when no response has published a policy", () => {
    const seen: unknown[] = [];
    createRateLimitPolicyFeed().subscribe((policy) => seen.push(policy));
    expect(seen).toEqual([]);
  });
});

describe("parseRateLimitPolicy", () => {
  it("returns the slowest of several policies", () => {
    expect(parseRateLimitPolicy('"burst";q=100;w=1, "sust";q=60;w=60')).toEqual(
      {
        limit: 60,
        windowMs: 60_000,
      },
    );
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
    ]) {
      expect(parseRateLimitPolicy(bad)).toBeUndefined();
    }
    expect(
      parseRateLimitPolicy(`${QUOTA_LIMIT_MAX};w=${QUOTA_WINDOW_MAX_SECONDS}`),
    ).toEqual({
      limit: QUOTA_LIMIT_MAX,
      windowMs: QUOTA_WINDOW_MAX_SECONDS * 1000,
    });
  });

  it("skips an unreadable policy and keeps a readable one beside it", () => {
    expect(parseRateLimitPolicy("junk, 5;w=10")).toEqual({
      limit: 5,
      windowMs: 10_000,
    });
  });
});
