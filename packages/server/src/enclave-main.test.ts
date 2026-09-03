import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { afterEach, describe, expect, it, vi } from "vitest";
import { readEnclaveEnv, runEnclaveMain } from "./enclave-main.js";

const serviceMocks = vi.hoisted(() => ({
  createPublicOnlyAccount: vi.fn().mockReturnValue({}),
  createServer: vi.fn(),
  listenHttpServer: vi.fn(),
  loadConfig: vi.fn(),
}));

vi.mock("@opendatalabs/personal-server-ts-core/keys", () => ({
  createPublicOnlyAccount: serviceMocks.createPublicOnlyAccount,
}));
vi.mock("./bootstrap.js", () => ({ createServer: serviceMocks.createServer }));
vi.mock("./config/index.js", () => ({ loadConfig: serviceMocks.loadConfig }));
vi.mock("./listen.js", () => ({
  listenHttpServer: serviceMocks.listenHttpServer,
}));

const MASTER_SIGNATURE = `0x${"11".repeat(65)}`;
const SERVER_ADDRESS = "0x2222222222222222222222222222222222222222";
const SERVER_PUBLIC_KEY = `0x04${"33".repeat(64)}`;

describe("readEnclaveEnv", () => {
  const originalOwnerKey = process.env.VANA_OWNER_PRIVATE_KEY;

  afterEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
    vi.unstubAllEnvs();

    if (originalOwnerKey === undefined) {
      delete process.env.VANA_OWNER_PRIVATE_KEY;
      return;
    }

    process.env.VANA_OWNER_PRIVATE_KEY = originalOwnerKey;
  });

  it("consumes the master signature and reads the public identity", () => {
    const env: NodeJS.ProcessEnv = {
      VANA_MASTER_KEY_SIGNATURE: MASTER_SIGNATURE,
      PS_ACCESS_TOKEN: "sandbox-token",
      PS_SERVER_ADDRESS: SERVER_ADDRESS,
      PS_SERVER_PUBLIC_KEY: SERVER_PUBLIC_KEY,
    };

    const result = readEnclaveEnv(env);

    expect(result).toEqual({
      ownerSignature: MASTER_SIGNATURE,
      accessToken: "sandbox-token",
      serverAddress: SERVER_ADDRESS,
      serverPublicKey: SERVER_PUBLIC_KEY,
    });
    expect(env.VANA_MASTER_KEY_SIGNATURE).toBeUndefined();
  });

  it("refuses an owner private key", () => {
    const env: NodeJS.ProcessEnv = {
      VANA_OWNER_PRIVATE_KEY: `0x${"44".repeat(32)}`,
    };

    expect(() => readEnclaveEnv(env)).toThrow(
      "VANA_OWNER_PRIVATE_KEY is forbidden in enclave profile",
    );
  });

  it.each([
    ["true", true],
    ["false", false],
  ])(
    "sets sync enabled to %s from the sandbox environment",
    async (value, expected) => {
      const config = ServerConfigSchema.parse({});
      const context = {
        app: { fetch: vi.fn() },
        logger: { info: vi.fn() },
        startBackgroundServices: vi.fn(),
        cleanup: vi.fn(),
      };
      serviceMocks.loadConfig.mockResolvedValue(config);
      serviceMocks.createServer.mockResolvedValue(context);
      serviceMocks.listenHttpServer.mockResolvedValue({ close: vi.fn() });
      vi.spyOn(process, "on").mockImplementation(() => process);
      vi.stubEnv("VANA_MASTER_KEY_SIGNATURE", MASTER_SIGNATURE);
      vi.stubEnv("PS_ACCESS_TOKEN", "sandbox-token");
      vi.stubEnv("PS_SERVER_ADDRESS", SERVER_ADDRESS);
      vi.stubEnv("PS_SERVER_PUBLIC_KEY", SERVER_PUBLIC_KEY);
      vi.stubEnv("SYNC_ENABLED", value);

      await runEnclaveMain();

      expect(config.sync.enabled).toBe(expected);
    },
  );
});
