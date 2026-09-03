import { agentConfigFromEnv } from "./bootstrap.js";

describe("agentConfigFromEnv", () => {
  it("boots the fake with the default app id", async () => {
    const config = agentConfigFromEnv({
      DSTACK_FAKE: "1",
      ENCLAVE_AGENT_SECRET: "x",
    });

    expect(config.host).toBe("127.0.0.1");
    expect(config.port).toBe(8787);
    expect(config.secret).toBe("x");
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
});
