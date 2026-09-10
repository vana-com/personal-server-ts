import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { PersonalServerReadFulfillment } from "@opendatalabs/personal-server-ts-core/api";
import { createAccessReporter } from "./access-reporter.js";

const AGENT_URL = "http://agent.invalid";
const ACCESS_TOKEN = "sandbox-access-token";
const CHAIN_ID = 14_800;
const GRANTEE = "0x1111111111111111111111111111111111111111";
const FLUSH_INTERVAL_MS = 5_000;
const BATCH_LIMIT = 50;
const QUEUE_LIMIT = 500;

function event(
  index: number,
  overrides: Partial<PersonalServerReadFulfillment> = {},
): PersonalServerReadFulfillment {
  return {
    builder: GRANTEE,
    grantId: "grant-1",
    logId: `log-${index}`,
    outcome: "served",
    scope: "instagram.profile",
    servedAt: "2026-09-09T00:00:00.000Z",
    source: "mcp",
    ...overrides,
  };
}

function okFetch() {
  return vi.fn(async () => new Response(null, { status: 202 }));
}

function reporter(fetchImpl: typeof fetch, warn = vi.fn()) {
  return {
    warn,
    instance: createAccessReporter({
      agentEndpoint: AGENT_URL,
      accessToken: ACCESS_TOKEN,
      chainId: CHAIN_ID,
      fetch: fetchImpl,
      logger: { warn },
    }),
  };
}

function bodyOf(call: unknown[]): { records: Record<string, unknown>[] } {
  const init = call[1] as RequestInit;
  return JSON.parse(String(init.body));
}

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("access reporter batching", () => {
  it("holds a partial batch until the flush interval", async () => {
    const send = okFetch();
    const { instance } = reporter(send as unknown as typeof fetch);
    await instance.report(event(1));
    expect(send).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(FLUSH_INTERVAL_MS);
    expect(send).toHaveBeenCalledTimes(1);
    expect(bodyOf(send.mock.calls[0]).records).toHaveLength(1);
  });

  it("sends immediately once the batch limit is reached", async () => {
    const send = okFetch();
    const { instance } = reporter(send as unknown as typeof fetch);
    for (let i = 0; i < BATCH_LIMIT; i += 1) await instance.report(event(i));

    await instance.flush();
    expect(send).toHaveBeenCalledTimes(1);
    expect(bodyOf(send.mock.calls[0]).records).toHaveLength(BATCH_LIMIT);
  });

  it("drops the oldest records past the queue bound", async () => {
    const warn = vi.fn();
    // A request that never settles keeps the queue growing past its bound.
    const stalled = vi.fn(() => new Promise<Response>(() => undefined));
    const { instance } = reporter(stalled as unknown as typeof fetch, warn);
    for (let i = 0; i < QUEUE_LIMIT + BATCH_LIMIT + 2; i += 1) {
      await instance.report(event(i));
    }

    expect(warn).toHaveBeenCalledWith(
      expect.objectContaining({ dropped: expect.any(Number) }),
      expect.stringContaining("queue is full"),
    );
  });

  it("flushes what is buffered on shutdown", async () => {
    const send = okFetch();
    const { instance } = reporter(send as unknown as typeof fetch);
    await instance.reportDenied?.(
      event(1, { denyReason: "scope_not_granted", outcome: "denied" }),
    );

    await instance.stop();
    expect(send).toHaveBeenCalledTimes(1);
  });

  it("never throws when the agent is unreachable", async () => {
    const send = vi.fn(async () => {
      throw new Error("connect ECONNREFUSED");
    });
    const { instance, warn } = reporter(send as unknown as typeof fetch);
    await instance.report(event(1));

    await expect(instance.stop()).resolves.toBeUndefined();
    expect(warn).toHaveBeenCalled();
  });

  it("warns but does not throw when the agent refuses the batch", async () => {
    const send = vi.fn(async () => new Response(null, { status: 400 }));
    const { instance, warn } = reporter(send as unknown as typeof fetch);
    await instance.report(event(1));

    await instance.stop();
    expect(warn).toHaveBeenCalledWith(
      expect.objectContaining({ status: 400 }),
      expect.any(String),
    );
  });
});

describe("access reporter payload", () => {
  it("maps a denial onto the wire record", async () => {
    const send = okFetch();
    const { instance } = reporter(send as unknown as typeof fetch);
    await instance.reportDenied?.(
      event(1, {
        denyReason: "scope_not_granted",
        grantId: "none",
        outcome: "denied",
        tool: "read_scope",
      }),
    );
    await instance.stop();

    const [url, init] = send.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${AGENT_URL}/agent/v1/access-records`);
    expect((init.headers as Record<string, string>).Authorization).toBe(
      `Bearer ${ACCESS_TOKEN}`,
    );
    expect(bodyOf(send.mock.calls[0]).records[0]).toEqual({
      action: "read",
      chainId: CHAIN_ID,
      denyReason: "scope_not_granted",
      grantId: "none",
      granteeAddress: GRANTEE,
      logId: "log-1",
      occurredAt: "2026-09-09T00:00:00.000Z",
      outcome: "denied",
      scope: "instagram.profile",
      source: "mcp",
      tool: "read_scope",
    });
  });

  it("omits tool and denyReason on a served read", async () => {
    const send = okFetch();
    const { instance } = reporter(send as unknown as typeof fetch);
    await instance.report(event(1));
    await instance.stop();

    const record = bodyOf(send.mock.calls[0]).records[0];
    expect(record).not.toHaveProperty("tool");
    expect(record).not.toHaveProperty("denyReason");
    expect(record.outcome).toBe("served");
  });
});
