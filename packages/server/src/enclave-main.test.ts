import { afterEach, describe, expect, it } from "vitest";
import { readEnclaveEnv } from "./enclave-main.js";

const MASTER_SIGNATURE = `0x${"11".repeat(65)}`;
const SERVER_ADDRESS = "0x2222222222222222222222222222222222222222";
const SERVER_PUBLIC_KEY = `0x04${"33".repeat(64)}`;

describe("readEnclaveEnv", () => {
  const originalOwnerKey = process.env.VANA_OWNER_PRIVATE_KEY;

  afterEach(() => {
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
});
