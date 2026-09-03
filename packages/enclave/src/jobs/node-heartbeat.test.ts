import { vi } from "vitest";
import { createFakeDstackClient } from "../dstack/fake.js";
import type { SandboxRegistry } from "../sandbox/registry.js";
import type { JobLogger } from "./claim-loop.js";
import type { GatewayClient } from "./gateway-client.js";
import {
  NODE_HEARTBEAT_INTERVAL_MS,
  startNodeHeartbeat,
} from "./node-heartbeat.js";

const APP_ID = "77".repeat(20);
const NODE_ID = "node-1";

function gatewayFake(): GatewayClient {
  return {
    claim: vi.fn(),
    heartbeat: vi.fn(),
    complete: vi.fn(),
    fail: vi.fn(),
    nodeHeartbeat: vi.fn().mockResolvedValue({ state: "admitted" }),
  };
}

describe("node heartbeat", () => {
  it("reports measurements and active sandbox capacity every 20 seconds", async () => {
    vi.useFakeTimers();
    const gateway = gatewayFake();
    const registry = {
      activeCount: vi.fn().mockReturnValue(3),
    } as unknown as SandboxRegistry;
    const logger = { info: vi.fn(), warn: vi.fn() } satisfies JobLogger;
    const heartbeat = startNodeHeartbeat({
      gateway,
      nodeId: NODE_ID,
      client: createFakeDstackClient({ appId: APP_ID }),
      registry,
      capacity: 20,
      logger,
    });
    await vi.waitFor(() =>
      expect(gateway.nodeHeartbeat).toHaveBeenCalledOnce(),
    );

    expect(gateway.nodeHeartbeat).toHaveBeenCalledWith(
      NODE_ID,
      expect.objectContaining({
        composeHash: expect.stringMatching(/^0x[0-9a-f]{64}$/),
        instanceId: expect.any(String),
        activeSandboxes: 3,
        capacity: 20,
      }),
    );
    await vi.advanceTimersByTimeAsync(NODE_HEARTBEAT_INTERVAL_MS);
    expect(gateway.nodeHeartbeat).toHaveBeenCalledTimes(2);

    await heartbeat.stop();
    vi.useRealTimers();
  });

  it("logs only failure and recovery transitions", async () => {
    vi.useFakeTimers();
    const gateway = gatewayFake();
    vi.mocked(gateway.nodeHeartbeat)
      .mockRejectedValueOnce(new Error("offline"))
      .mockRejectedValueOnce(new Error("offline"))
      .mockResolvedValue({ state: "admitted" });
    const logger = { info: vi.fn(), warn: vi.fn() } satisfies JobLogger;
    const heartbeat = startNodeHeartbeat({
      gateway,
      nodeId: NODE_ID,
      client: createFakeDstackClient({ appId: APP_ID }),
      registry: { activeCount: () => 0 } as SandboxRegistry,
      capacity: 20,
      logger,
    });
    await vi.waitFor(() => expect(logger.warn).toHaveBeenCalledOnce());

    await vi.advanceTimersByTimeAsync(NODE_HEARTBEAT_INTERVAL_MS * 2);
    expect(logger.warn).toHaveBeenCalledOnce();
    expect(logger.info).toHaveBeenCalledOnce();

    await heartbeat.stop();
    vi.useRealTimers();
  });
});
