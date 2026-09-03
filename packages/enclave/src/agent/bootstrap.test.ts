import { agentConfigFromEnv } from "./bootstrap.js";

const TAGGED_IMAGE = "personal-server:test";
const DIGEST_IMAGE = `personal-server@sha256:${"a".repeat(64)}`;

describe("agentConfigFromEnv", () => {
  it("boots the fake with the default app id", async () => {
    const config = agentConfigFromEnv({
      DSTACK_FAKE: "1",
      ENCLAVE_AGENT_SECRET: "x",
    });

    expect(config.host).toBe("127.0.0.1");
    expect(config.port).toBe(8787);
    expect(config.secret).toBe("x");
    expect(config.jobs).toBeUndefined();
    await expect(config.client.info()).resolves.toMatchObject({
      appId: expect.stringMatching(/^[0-9a-f]{40}$/),
    });
  });

  it("rejects a missing secret", () => {
    expect(() => agentConfigFromEnv({ DSTACK_FAKE: "1" })).toThrow(
      "ENCLAVE_AGENT_SECRET is required",
    );
  });

  it("rejects an invalid port", () => {
    expect(() =>
      agentConfigFromEnv({
        DSTACK_FAKE: "1",
        ENCLAVE_AGENT_PORT: "invalid",
        ENCLAVE_AGENT_SECRET: "x",
      }),
    ).toThrow("ENCLAVE_AGENT_PORT must be an integer from 1 to 65535");
  });

  it("parses the fake jobs profile and numeric overrides", () => {
    const config = agentConfigFromEnv({
      DSTACK_FAKE: "1",
      ENCLAVE_AGENT_SECRET: "agent-secret",
      GATEWAY_URL: "https://gateway.example",
      NODE_ID: "node-1",
      NODE_SECRET: "node-secret",
      PS_IMAGE: TAGGED_IMAGE,
      SANDBOX_RUNTIME: "fake",
      SANDBOX_FAKE_ROOT: "/tmp/sandboxes",
      PS_ENTRY: "/tmp/server.js",
      SANDBOX_MAX: "4",
      SANDBOX_IDLE_TTL_SECONDS: "9",
      LEASE_SECONDS: "60",
      SANDBOX_SYNC: "disabled",
      WORK_DELAY_MS: "250",
      VERCEL_PROTECTION_BYPASS: "preview-secret",
    });

    expect(config.jobs).toEqual({
      gatewayUrl: "https://gateway.example",
      nodeId: "node-1",
      nodeSecret: "node-secret",
      runtime: "fake",
      image: TAGGED_IMAGE,
      sandboxMax: 4,
      idleTtlMs: 9_000,
      leaseSeconds: 60,
      dockerHost: "tcp://sandbox-runtime:2375",
      psEntry: "/tmp/server.js",
      fakeRoot: "/tmp/sandboxes",
      sync: "disabled",
      workDelayMs: 250,
      gatewayBypassSecret: "preview-secret",
    });
  });

  it("stays identity-only when the jobs credentials are incomplete", () => {
    const config = agentConfigFromEnv({
      DSTACK_FAKE: "1",
      ENCLAVE_AGENT_SECRET: "agent-secret",
      GATEWAY_URL: "https://gateway.example",
      NODE_ID: "node-1",
    });

    expect(config.jobs).toBeUndefined();
  });

  it("uses the production jobs defaults", () => {
    const config = agentConfigFromEnv({
      DSTACK_FAKE: "1",
      ENCLAVE_AGENT_SECRET: "agent-secret",
      GATEWAY_URL: "https://gateway.example",
      NODE_ID: "node-1",
      NODE_SECRET: "node-secret",
      PS_IMAGE: DIGEST_IMAGE,
    });

    expect(config.jobs).toMatchObject({
      runtime: "docker",
      sandboxMax: 20,
      idleTtlMs: 600_000,
      leaseSeconds: 30,
      dockerHost: "tcp://sandbox-runtime:2375",
      sync: "enabled",
      workDelayMs: 0,
    });
  });

  it("rejects a tagged image for the docker runtime", () => {
    expect(() =>
      agentConfigFromEnv({
        DSTACK_FAKE: "1",
        ENCLAVE_AGENT_SECRET: "agent-secret",
        GATEWAY_URL: "https://gateway.example",
        NODE_ID: "node-1",
        NODE_SECRET: "node-secret",
        PS_IMAGE: TAGGED_IMAGE,
      }),
    ).toThrow("PS_IMAGE must use a sha256 digest for the docker runtime");
  });

  it("rejects an insecure gateway URL for the docker runtime", () => {
    expect(() =>
      agentConfigFromEnv({
        DSTACK_FAKE: "1",
        ENCLAVE_AGENT_SECRET: "agent-secret",
        GATEWAY_URL: "http://gateway.example",
        NODE_ID: "node-1",
        NODE_SECRET: "node-secret",
        PS_IMAGE: DIGEST_IMAGE,
      }),
    ).toThrow("GATEWAY_URL must use https for the docker runtime");
  });

  it("accepts a tagged image and http gateway for the fake runtime", () => {
    const config = agentConfigFromEnv({
      DSTACK_FAKE: "1",
      ENCLAVE_AGENT_SECRET: "agent-secret",
      GATEWAY_URL: "http://gateway.example",
      NODE_ID: "node-1",
      NODE_SECRET: "node-secret",
      PS_IMAGE: TAGGED_IMAGE,
      SANDBOX_RUNTIME: "fake",
    });

    expect(config.jobs).toMatchObject({
      gatewayUrl: "http://gateway.example",
      image: TAGGED_IMAGE,
      runtime: "fake",
    });
  });

  it.each([
    ["SANDBOX_RUNTIME", "invalid", "SANDBOX_RUNTIME"],
    ["SANDBOX_MAX", "0", "SANDBOX_MAX"],
    ["LEASE_SECONDS", "301", "LEASE_SECONDS"],
    ["SANDBOX_SYNC", "sometimes", "SANDBOX_SYNC"],
  ])("names %s in validation errors", (name, value, expected) => {
    expect(() =>
      agentConfigFromEnv({
        DSTACK_FAKE: "1",
        ENCLAVE_AGENT_SECRET: "agent-secret",
        GATEWAY_URL: "https://gateway.example",
        NODE_ID: "node-1",
        NODE_SECRET: "node-secret",
        PS_IMAGE: TAGGED_IMAGE,
        [name]: value,
      }),
    ).toThrow(expected);
  });
});
