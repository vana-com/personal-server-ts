import { afterEach, describe, expect, it, vi } from "vitest";
import { sandboxSpec } from "./run.js";
import { assertSandboxEnv } from "../sandbox/runtime.js";

type Deps = Parameters<typeof sandboxSpec>[1];
const identity = {
  userPsId: `0x${"11".repeat(32)}`,
  epoch: 1,
  enclaveAddress: `0x${"22".repeat(20)}`,
  enclavePublicKey: `0x${"33".repeat(65)}`,
} as Parameters<typeof sandboxSpec>[0];

function deps(): Deps {
  return {
    image: "test-image",
    gatewayUrl: "https://gateway.example",
    agentUrl: "https://agent.example",
    chainId: 1,
    sync: "disabled",
    jobResultMaxBytes: 1024,
    contracts: {
      dataRegistry: `0x${"44".repeat(20)}`,
      dataPortabilityServer: `0x${"55".repeat(20)}`,
      dataPortabilityGrantees: `0x${"66".repeat(20)}`,
      dataPortabilityPermissions: `0x${"77".repeat(20)}`,
    },
  };
}
function spec(input: Deps) {
  return sandboxSpec(
    identity,
    input,
    "test-token",
    new Uint8Array([1]),
    "test.scope",
    () => {},
    () => {},
  );
}
afterEach(() => vi.unstubAllEnvs());

describe("sandbox stream-sync read setting", () => {
  it.each(["true", "false", ""])(
    "forwards the exact supplied value %j (mutant: drop-forwarding)",
    (value) => {
      const result = spec({ ...deps(), streamSyncRead: value });
      expect(result.env).toHaveProperty("PS_STREAM_SYNC_READ", value);
      expect(() => assertSandboxEnv(result.env)).not.toThrow();
    },
  );
  it("omits an absent setting rather than inventing a default or reading global env", () => {
    vi.stubEnv("PS_STREAM_SYNC_READ", "true");
    expect(spec(deps()).env).not.toHaveProperty("PS_STREAM_SYNC_READ");
  });
});
