import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { PersonalServerReadFulfillment } from "@opendatalabs/personal-server-ts-core/api";
import {
  ACCESS_RECORDS_DROPPED,
  createAccessReporter,
} from "./access-reporter.js";

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

function refusal(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function logIdsOf(call: unknown[]) {
  return bodyOf(call).records.map((record) => record.logId);
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
      expect.objectContaining({
        count: expect.any(Number),
        droppedTotal: expect.any(Number),
        reason: "queue_full",
      }),
      ACCESS_RECORDS_DROPPED,
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

  it("drops a refused batch without retrying and without throwing", async () => {
    const send = vi.fn(async () => new Response(null, { status: 400 }));
    const { instance, warn } = reporter(send as unknown as typeof fetch);
    await instance.report(event(1));

    await instance.stop();
    // A 4xx is the agent refusing these records, not a blip worth repeating.
    expect(send).toHaveBeenCalledTimes(1);
    expect(warn).toHaveBeenCalledWith(
      expect.objectContaining({ count: 1, reason: "refused_400", attempts: 1 }),
      ACCESS_RECORDS_DROPPED,
    );
  });

  it("drops only the record a 400 names and resends the rest", async () => {
    const send = vi.fn(async () =>
      send.mock.calls.length === 1
        ? // The Gateway rejected record 1; records 0 and 2 are untouched by it.
          refusal(400, {
            code: "INVALID_PAYLOAD",
            error: "bad source",
            index: 1,
          })
        : new Response(null, { status: 202 }),
    );
    const { instance, warn } = reporter(send as unknown as typeof fetch);
    for (const i of [0, 1, 2]) await instance.report(event(i));

    await instance.stop();

    expect(send).toHaveBeenCalledTimes(2);
    expect(logIdsOf(send.mock.calls[0])).toEqual(["log-0", "log-1", "log-2"]);
    expect(logIdsOf(send.mock.calls[1])).toEqual(["log-0", "log-2"]);
    // Exactly one record is an audit gap, not three.
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn).toHaveBeenCalledWith(
      expect.objectContaining({
        count: 1,
        droppedTotal: 1,
        reason: "refused_400",
        code: "INVALID_PAYLOAD",
      }),
      ACCESS_RECORDS_DROPPED,
    );
  });

  it("honours a per-record rejected list", async () => {
    const send = vi.fn(async () =>
      send.mock.calls.length === 1
        ? refusal(400, {
            code: "PARTIAL_REJECT",
            rejected: [
              { index: 0, code: "INVALID_PAYLOAD" },
              { index: 2, code: "INVALID_PAYLOAD" },
            ],
          })
        : new Response(null, { status: 202 }),
    );
    const { instance, warn } = reporter(send as unknown as typeof fetch);
    for (const i of [0, 1, 2]) await instance.report(event(i));

    await instance.stop();

    expect(logIdsOf(send.mock.calls[1])).toEqual(["log-1"]);
    expect(warn).toHaveBeenCalledWith(
      expect.objectContaining({ count: 2, reason: "refused_400" }),
      ACCESS_RECORDS_DROPPED,
    );
  });

  it("drops the remainder too when the resend is refused as well", async () => {
    const send = vi.fn(async () =>
      send.mock.calls.length === 1
        ? refusal(400, { code: "INVALID_PAYLOAD", index: 0 })
        : refusal(400, { code: "IDENTITY_UNKNOWN", error: "unknown identity" }),
    );
    const { instance, warn } = reporter(send as unknown as typeof fetch);
    for (const i of [0, 1]) await instance.report(event(i));

    await instance.stop();

    // One retry of the remainder, never a loop.
    expect(send).toHaveBeenCalledTimes(2);
    expect(warn).toHaveBeenCalledWith(
      expect.objectContaining({ count: 1, code: "IDENTITY_UNKNOWN" }),
      ACCESS_RECORDS_DROPPED,
    );
  });

  it("keeps whole-batch drop when a 4xx names no record", async () => {
    const send = vi.fn(async () =>
      refusal(403, { code: "STALE_PLACEMENT", error: "stale placement" }),
    );
    const { instance, warn } = reporter(send as unknown as typeof fetch);
    for (const i of [0, 1]) await instance.report(event(i));

    await instance.stop();

    expect(send).toHaveBeenCalledTimes(1);
    // The count and the first error code are what makes the gap diagnosable.
    expect(warn).toHaveBeenCalledWith(
      expect.objectContaining({
        count: 2,
        reason: "refused_403",
        code: "STALE_PLACEMENT",
        attempts: 1,
      }),
      ACCESS_RECORDS_DROPPED,
    );
  });

  it("ignores an out-of-range index rather than dropping an unnamed record", async () => {
    const send = vi.fn(async () =>
      refusal(400, { code: "INVALID_PAYLOAD", index: 7 }),
    );
    const { instance, warn } = reporter(send as unknown as typeof fetch);
    await instance.report(event(0));

    await instance.stop();

    expect(send).toHaveBeenCalledTimes(1);
    expect(warn).toHaveBeenCalledWith(
      expect.objectContaining({ count: 1, reason: "refused_400" }),
      ACCESS_RECORDS_DROPPED,
    );
  });

  it("retries a transient failure with backoff before giving up", async () => {
    const send = vi.fn(async () => {
      throw new Error("connect ECONNREFUSED");
    });
    const { instance, warn } = reporter(send as unknown as typeof fetch);
    await instance.report(event(1));

    const flushed = instance.flush();
    // Two backoffs (500 ms, 1 s) separate the three attempts.
    await vi.advanceTimersByTimeAsync(2_000);
    await flushed;

    expect(send).toHaveBeenCalledTimes(3);
    expect(warn).toHaveBeenCalledWith(
      expect.objectContaining({ attempts: 3, droppedTotal: 1 }),
      ACCESS_RECORDS_DROPPED,
    );
  });

  it("delivers a batch that fails once and then succeeds", async () => {
    let attempts = 0;
    const send = vi.fn(async () => {
      attempts += 1;
      if (attempts === 1) throw new Error("connect ECONNREFUSED");
      return new Response(null, { status: 202 });
    });
    const { instance, warn } = reporter(send as unknown as typeof fetch);
    await instance.report(event(1));

    const flushed = instance.flush();
    await vi.advanceTimersByTimeAsync(500);
    await flushed;

    expect(send).toHaveBeenCalledTimes(2);
    expect(warn).not.toHaveBeenCalled();
  });

  it("sends once on shutdown rather than waiting out the backoff", async () => {
    const send = vi.fn(async () => {
      throw new Error("connect ECONNREFUSED");
    });
    const { instance, warn } = reporter(send as unknown as typeof fetch);
    await instance.report(event(1));

    await instance.stop();

    expect(send).toHaveBeenCalledTimes(1);
    expect(warn).toHaveBeenCalledWith(
      expect.objectContaining({ attempts: 1 }),
      ACCESS_RECORDS_DROPPED,
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
