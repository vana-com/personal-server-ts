import { describe, expect, it } from "vitest";
import {
  retryAfterMsOf,
  settleFailure,
  throttleAwareFetch,
} from "./throttle.js";

/** A body that records whether it was cancelled and how much of it was read. */
function trackedBody(chunks: readonly string[], endless = false) {
  const state = { cancelled: false, pulled: 0 };
  const encoder = new TextEncoder();
  let at = 0;
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      state.pulled += 1;
      if (at < chunks.length) controller.enqueue(encoder.encode(chunks[at++]));
      else if (endless) controller.enqueue(encoder.encode("x".repeat(1024)));
      else controller.close();
    },
    cancel() {
      state.cancelled = true;
    },
  });
  return { state, body };
}

const respond = (
  status: number,
  body: ReadableStream<Uint8Array> | null,
  headers: Record<string, string> = {},
) => new Response(body, { status, headers });

describe("a throttle answer's body", () => {
  it("is cancelled unread when the header already says how long to wait", async () => {
    const { state, body } = trackedBody(['{"retryAfter":99}']);
    const ms = await retryAfterMsOf(respond(429, body, { "retry-after": "7" }));
    expect(ms).toBe(7_000);
    expect(state.cancelled).toBe(true);
    expect(state.pulled).toBe(0);
  });

  it("is read for its retryAfter when the header gives nothing, then cancelled", async () => {
    const { state, body } = trackedBody(
      ['{"error":"X","retryAfter":60}'],
      true,
    );
    expect(await retryAfterMsOf(respond(429, body))).toBe(60_000);
    expect(state.cancelled).toBe(true);
  });

  it("is read for no more than 4 KiB, however long it runs", async () => {
    const { state, body } = trackedBody([], true);
    expect(await retryAfterMsOf(respond(503, body))).toBeUndefined();
    expect(state.cancelled).toBe(true);
    // 1 KiB a pull: the read stopped at the limit and did not drain the stream.
    expect(state.pulled).toBeLessThanOrEqual(6);
  });

  it("is cancelled when it is the body of another status", async () => {
    const { state, body } = trackedBody(["nope"]);
    expect(await settleFailure(respond(500, body))).toBeUndefined();
    expect(state.cancelled).toBe(true);
  });

  it("is cancelled when the throttling fetch throws on it", async () => {
    const { state, body } = trackedBody(["slow down"]);
    const fetchLike = throttleAwareFetch(async () =>
      respond(503, body, { "retry-after": "2" }),
    );
    await expect(fetchLike("https://storage.test/")).rejects.toMatchObject({
      status: 503,
      retryAfterMs: 2_000,
    });
    expect(state.cancelled).toBe(true);
  });
});
