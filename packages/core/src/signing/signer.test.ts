import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { recoverTypedDataAddress } from "viem";

import { loadOrCreateServerAccount } from "../../../server/src/keys/server-account.js";
import type { GatewayConfig } from "../schemas/server-config.js";
import { createServerSigner } from "./signer.js";
import {
  fileRegistrationDomain,
  grantRegistrationDomain,
  grantRevocationDomain,
  dataRegistryDomain,
  FILE_REGISTRATION_TYPES,
  GRANT_REGISTRATION_TYPES,
  GRANT_REVOCATION_TYPES,
  ADD_DATA_TYPES,
} from "@opendatalabs/vana-sdk/browser";

const TEST_GATEWAY_CONFIG: GatewayConfig = {
  chainId: 14800,
  contracts: {
    dataRegistry: "0x1111111111111111111111111111111111111111",
    dataPortabilityPermissions: "0x2222222222222222222222222222222222222222",
    dataPortabilityServer: "0x3333333333333333333333333333333333333333",
  },
};

let tempDir: string;

function setup() {
  const keyPath = join(tempDir, "key.json");
  const account = loadOrCreateServerAccount(keyPath);
  const signer = createServerSigner(account, TEST_GATEWAY_CONFIG);
  return { account, signer };
}

describe("ServerSigner", () => {
  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "signer-test-"));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  describe("signFileRegistration", () => {
    it("produces a signature recoverable to the server address", async () => {
      const { account, signer } = setup();
      const msg = {
        ownerAddress:
          "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" as `0x${string}`,
        url: "https://storage.example.com/file.json",
        schemaId: ("0x" + "ab".repeat(32)) as `0x${string}`,
      };

      const signature = await signer.signFileRegistration(msg);
      expect(signature).toMatch(/^0x[0-9a-fA-F]+$/);

      const recovered = await recoverTypedDataAddress({
        domain: fileRegistrationDomain(TEST_GATEWAY_CONFIG),
        types: FILE_REGISTRATION_TYPES,
        primaryType: "FileRegistration",
        message: msg,
        signature,
      });
      expect(recovered.toLowerCase()).toBe(account.address.toLowerCase());
    });
  });

  describe("signGrantRegistration", () => {
    it("produces a signature recoverable to the server address", async () => {
      const { account, signer } = setup();
      const msg = {
        grantorAddress:
          "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" as `0x${string}`,
        granteeId: ("0x" + "bb".repeat(32)) as `0x${string}`,
        scopes: ["instagram.*"],
        grantVersion: 1n,
        expiresAt: 9999999999n,
      };

      const signature = await signer.signGrantRegistration(msg);
      expect(signature).toMatch(/^0x[0-9a-fA-F]+$/);

      const recovered = await recoverTypedDataAddress({
        domain: grantRegistrationDomain(TEST_GATEWAY_CONFIG),
        types: GRANT_REGISTRATION_TYPES,
        primaryType: "GrantRegistration",
        message: msg,
        signature,
      });
      expect(recovered.toLowerCase()).toBe(account.address.toLowerCase());
    });
  });

  describe("signGrantRevocation", () => {
    it("produces a signature recoverable to the server address", async () => {
      const { account, signer } = setup();
      const msg = {
        grantorAddress:
          "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" as `0x${string}`,
        grantId: ("0x" + "cc".repeat(32)) as `0x${string}`,
        // Canary requires grantVersion on revocation — shares the
        // monotonic nonce with registration so an old revocation sig
        // can't survive a revoke -> re-register cycle.
        grantVersion: 2n,
      };

      const signature = await signer.signGrantRevocation(msg);
      expect(signature).toMatch(/^0x[0-9a-fA-F]+$/);

      const recovered = await recoverTypedDataAddress({
        domain: grantRevocationDomain(TEST_GATEWAY_CONFIG),
        types: GRANT_REVOCATION_TYPES,
        primaryType: "GrantRevocation",
        message: msg,
        signature,
      });
      expect(recovered.toLowerCase()).toBe(account.address.toLowerCase());
    });
  });

  describe("signAddData", () => {
    it("produces a signature recoverable to the server address", async () => {
      const { account, signer } = setup();
      const msg = {
        ownerAddress:
          "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" as `0x${string}`,
        scope: "instagram.profile",
        dataHash: ("0x" + "11".repeat(32)) as `0x${string}`,
        metadataHash: ("0x" + "22".repeat(32)) as `0x${string}`,
        expectedVersion: 1n,
      };

      const signature = await signer.signAddData(msg);
      expect(signature).toMatch(/^0x[0-9a-fA-F]+$/);

      const recovered = await recoverTypedDataAddress({
        domain: dataRegistryDomain(TEST_GATEWAY_CONFIG),
        types: ADD_DATA_TYPES,
        primaryType: "AddData",
        message: msg,
        signature,
      });
      expect(recovered.toLowerCase()).toBe(account.address.toLowerCase());
    });
  });

  it("all three signing methods are deterministic", async () => {
    const { signer } = setup();
    const fileMsg = {
      ownerAddress:
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" as `0x${string}`,
      url: "https://example.com/file.json",
      schemaId: ("0x" + "ab".repeat(32)) as `0x${string}`,
    };

    const sig1 = await signer.signFileRegistration(fileMsg);
    const sig2 = await signer.signFileRegistration(fileMsg);
    expect(sig1).toBe(sig2);
  });
});
