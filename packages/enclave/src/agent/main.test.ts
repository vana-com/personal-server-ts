import { vi } from "vitest";
import type { Address, Hex } from "viem";
import type { UserPsId } from "../identity/paths.js";
import type { PrewarmRequestBody } from "./types.js";
import type * as SandboxRegistry from "../sandbox/registry.js";

const mocks = vi.hoisted(() => {
  const registry = {
    activeCount: vi.fn().mockReturnValue(0),
    listSandboxes: vi.fn().mockResolvedValue([]),
    sandboxLogs: vi.fn().mockResolvedValue(undefined),
    lookupJob: vi.fn().mockReturnValue({ kind: "inactive" }),
  };

  return {
    registry,
    prewarmSandbox: vi.fn().mockResolvedValue(undefined),
    createAgentServer: vi.fn().mockReturnValue({ listen: vi.fn() }),
    startClaimLoop: vi.fn().mockReturnValue({
      drain: vi.fn().mockResolvedValue(undefined),
      draining: vi.fn().mockReturnValue(false),
    }),
    startNodeHeartbeat: vi.fn().mockReturnValue({ stop: vi.fn() }),
  };
});

const client = {
  info: vi.fn().mockResolvedValue({
    appId: "0".repeat(40),
    composeHash: "a".repeat(64),
    instanceId: "b".repeat(40),
  }),
};
const contracts = {
  dataRegistry: "0x1111111111111111111111111111111111111111",
  dataPortabilityServer: "0x2222222222222222222222222222222222222222",
  dataPortabilityGrantees: "0x3333333333333333333333333333333333333333",
  dataPortabilityPermissions: "0x4444444444444444444444444444444444444444",
} as const;
const config = {
  runtime: "fake",
  nodeId: "node-1",
  nodeSecret: "node-secret",
  gatewayUrl: "https://gateway.example",
  storageApiUrl: "https://storage.example",
  image: "personal-server:test",
  chainId: 14_800,
  contracts,
  gatewayBypassSecret: "preview-secret",
  leaseSeconds: 30,
  sync: "enabled",
  workDelayMs: 0,
  jobResultMaxBytes: 64 * 1024 * 1024,
  sandboxMax: 20,
  idleTtlMs: 600_000,
  sandboxDebug: false,
  dockerHost: "unix:///var/run/docker.sock",
  sandboxMemory: "128m",
  sandboxCpus: 1,
  sandboxPidsLimit: 256,
};

vi.mock("./bootstrap.js", () => ({
  agentConfigFromEnv: vi.fn().mockReturnValue({
    client,
    host: "127.0.0.1",
    jobs: config,
    port: 8787,
    secret: "agent-secret",
  }),
  resolveSandboxAgentUrl: vi.fn().mockResolvedValue("http://agent:8787"),
  dstackClientFromEnv: vi.fn().mockReturnValue(client),
}));
vi.mock("./http.js", () => ({ createAgentServer: mocks.createAgentServer }));
vi.mock("../jobs/claim-loop.js", () => ({
  startClaimLoop: mocks.startClaimLoop,
}));
vi.mock("../jobs/node-heartbeat.js", () => ({
  startNodeHeartbeat: mocks.startNodeHeartbeat,
}));
vi.mock("../jobs/run.js", () => ({
  prewarmSandbox: mocks.prewarmSandbox,
  runJob: vi.fn(),
}));
vi.mock("../sandbox/fake-runtime.js", () => ({
  createFakeRuntime: vi.fn().mockReturnValue({
    reconcile: vi.fn().mockResolvedValue(undefined),
  }),
}));
vi.mock("../sandbox/registry.js", async (importOriginal) => ({
  ...(await importOriginal<typeof SandboxRegistry>()),
  createSandboxRegistry: vi.fn().mockReturnValue(mocks.registry),
}));

describe("agent main prewarm wiring", () => {
  it("starts prewarm with the same sandbox dependencies as job execution", async () => {
    await import("./main.js");
    await vi.waitFor(() => expect(mocks.createAgentServer).toHaveBeenCalled());
    // The node reads dstack Info once, at boot, before it serves anything.
    expect(client.info).toHaveBeenCalledTimes(1);
    expect(client.info.mock.invocationCallOrder[0]).toBeLessThan(
      mocks.createAgentServer.mock.invocationCallOrder[0] ?? 0,
    );
    const options = mocks.createAgentServer.mock.calls[0]?.[0] as {
      jobs: { prewarm(body: PrewarmRequestBody): void };
    };
    const body = {
      userPsId: `0x${"11".repeat(32)}` as UserPsId,
      epoch: 2,
      enclaveAddress: `0x${"22".repeat(20)}` as Address,
      enclavePublicKey: `0x04${"33".repeat(64)}` as Hex,
      sealedEnvelope: {
        v: 1,
        iv: "aXY=",
        ciphertext: "Y2lwaGVydGV4dA==",
        tag: "dGFn",
        wrappedContentKey: {
          iv: "aXY=",
          ciphertext: "a2V5",
          tag: "dGFn",
        },
      },
      scope: "chatgpt.conversations",
    } satisfies PrewarmRequestBody;

    options.jobs.prewarm(body);

    expect(mocks.prewarmSandbox).toHaveBeenCalledWith(
      body,
      body.scope,
      expect.objectContaining({
        client,
        registry: mocks.registry,
        image: config.image,
        gatewayUrl: config.gatewayUrl,
        storageApiUrl: config.storageApiUrl,
        agentUrl: "http://agent:8787",
        chainId: config.chainId,
        contracts,
        gatewayBypassSecret: config.gatewayBypassSecret,
        sync: config.sync,
        jobResultMaxBytes: config.jobResultMaxBytes,
      }),
    );
  });
});
