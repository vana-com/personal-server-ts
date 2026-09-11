import { afterEach, describe, expect, it, vi } from "vitest";
import type { DstackInfo } from "../dstack/client.js";
import { createFakeDstackClient } from "../dstack/fake.js";
import {
  HEALTH_INFO_BUDGET_MS,
  HEALTH_INFO_TTL_MS,
  readHealth,
} from "./health.js";

const NODE_ID = "node-health";
const FAKE_APP_ID = "0000000000000000000000000000000000000004";
const UNREACHABLE = { dstack: "unreachable" };
const INFO: DstackInfo = {
  appId: FAKE_APP_ID,
  composeHash: "a".repeat(64),
  instanceId: "b".repeat(40),
  osVersion: "0.5.9",
};
/** The whole payload for an idle unsigned agent that has read INFO. */
const SERVED = {
  ...INFO,
  nodeId: NODE_ID,
  activeSandboxes: 0,
  draining: false,
  configIssuedAt: null,
  configExpiresAt: null,
};

/**
 * A client standing in for the 2026-09-11 fleet's guest agent: every info()
 * hangs until the test hands out an answer.
 */
function heldClient(): {
  client: ReturnType<typeof createFakeDstackClient>;
  release: () => void;
  inFlight: () => number;
} {
  const waiting: ((info: DstackInfo) => void)[] = [];
  const client = createFakeDstackClient({ appId: FAKE_APP_ID });
  client.info = () =>
    new Promise<DstackInfo>((resolve) => {
      waiting.push(resolve);
    });

  return {
    client,
    release: () => waiting.shift()?.(INFO),
    inFlight: () => waiting.length,
  };
}

describe("agent health", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("answers within its budget when the dstack agent is slow", async () => {
    vi.useFakeTimers();
    const { client } = heldClient();

    const pending = readHealth(client, NODE_ID, 2, true);
    await vi.advanceTimersByTimeAsync(HEALTH_INFO_BUDGET_MS);

    await expect(pending).resolves.toEqual({
      ...UNREACHABLE,
      nodeId: NODE_ID,
      activeSandboxes: 2,
      draining: true,
      configIssuedAt: null,
      configExpiresAt: null,
    });
  });

  it("reads once for requests that pile up behind a slow agent", async () => {
    vi.useFakeTimers();
    const { client, inFlight } = heldClient();

    const both = Promise.all([
      readHealth(client, NODE_ID),
      readHealth(client, NODE_ID),
    ]);
    await vi.advanceTimersByTimeAsync(HEALTH_INFO_BUDGET_MS);

    await expect(both).resolves.toMatchObject([UNREACHABLE, UNREACHABLE]);
    expect(inFlight()).toBe(1);
  });

  it("serves the read that lands after the budget has answered", async () => {
    vi.useFakeTimers();
    const { client, release } = heldClient();
    const pending = readHealth(client, NODE_ID);
    await vi.advanceTimersByTimeAsync(HEALTH_INFO_BUDGET_MS);

    await expect(pending).resolves.toMatchObject(UNREACHABLE);

    release();
    await vi.advanceTimersByTimeAsync(0);

    await expect(readHealth(client, NODE_ID)).resolves.toEqual(SERVED);
  });

  it("serves the cached read and refreshes it once the TTL lapses", async () => {
    vi.useFakeTimers();
    const { client, release, inFlight } = heldClient();
    const first = readHealth(client, NODE_ID);
    release();

    await expect(first).resolves.toEqual(SERVED);

    // Past the TTL a refresh starts but is never awaited, so this answer is
    // immediate even though the second read is still hanging.
    await vi.advanceTimersByTimeAsync(HEALTH_INFO_TTL_MS);

    await expect(readHealth(client, NODE_ID)).resolves.toEqual(SERVED);
    expect(inFlight()).toBe(1);
  });

  it("reports a failure that leaves nothing to serve", async () => {
    const failure = new Error("info failed");
    const client = createFakeDstackClient({ appId: FAKE_APP_ID });
    client.info = () => Promise.reject(failure);

    await expect(readHealth(client, NODE_ID)).rejects.toBe(failure);
  });
});
