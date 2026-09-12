import { describe, expect, it, vi } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import {
  BUILDER_REGISTRATION_TYPES,
  GRANT_REGISTRATION_TYPES,
  builderRegistrationDomain,
  grantRegistrationDomain,
} from "@opendatalabs/vana-sdk/node";
import {
  deriveBuilderId,
  type SignedBuilder,
  type SignedGrant,
} from "@opendatalabs/personal-server-ts-core/policy";
import {
  createInMemoryMcpConnectionStore,
  createMcpConnection,
  loadMcpGranteeAccount,
} from "@opendatalabs/personal-server-ts-core/mcp";
import { DEFAULTS } from "@opendatalabs/personal-server-ts-core/schemas";
import { verifyTeeMcpGrants } from "./grants.js";

describe("TEE owner grant proof", () => {
  it("accepts the signed owner/grantee binding and rejects a different owner or expanded scopes", async () => {
    const owner = privateKeyToAccount(`0x${"12".repeat(32)}`);
    const store = createInMemoryMcpConnectionStore();
    const created = await createMcpConnection(
      {},
      { store, publicOrigin: "https://mcp-dev.vana.org" },
    );
    const connection = (await store.getById(created.connectionId))!;
    const grantee = loadMcpGranteeAccount({
      address: connection.granteeAddress,
      publicKey: connection.granteePublicKey,
      encryptedPrivateKey: connection.encryptedGranteePrivateKey,
    });
    const gatewayConfig = {
      chainId: 14800,
      contracts: DEFAULTS.gateway.contracts,
    };
    const builderMessage = {
      ownerAddress: grantee.address,
      granteeAddress: grantee.address,
      publicKey: grantee.publicKey,
      appUrl: "https://claude.ai",
    };
    const builder: SignedBuilder = {
      ...builderMessage,
      id: deriveBuilderId(builderMessage, gatewayConfig),
      addedAt: new Date().toISOString(),
      signature: await grantee.signTypedData({
        domain: builderRegistrationDomain(gatewayConfig),
        types: BUILDER_REGISTRATION_TYPES,
        primaryType: "BuilderRegistration",
        message: builderMessage,
      }),
    };
    const grantMessage = {
      grantorAddress: owner.address,
      granteeId: builder.id as `0x${string}`,
      scopes: ["spotify.profile"],
      grantVersion: 1n,
      expiresAt: 0n,
    };
    const grant = {
      id: `0x${"34".repeat(32)}`,
      ...grantMessage,
      grantVersion: "1",
      expiresAt: null,
      revokedAt: null,
      signature: await owner.signTypedData({
        domain: grantRegistrationDomain(gatewayConfig),
        types: GRANT_REGISTRATION_TYPES,
        primaryType: "GrantRegistration",
        message: grantMessage,
      }),
    } as SignedGrant;
    const options = {
      connection,
      binding: { owner: owner.address, chainId: 14800 },
      grants: [{ grantId: grant.id, scopes: ["spotify.profile"] }],
      gateway: {
        getBuilder: vi.fn().mockResolvedValue(builder),
        getGrant: vi.fn().mockResolvedValue(grant),
      },
      gatewayConfig,
      chainId: 14800,
    };
    await expect(verifyTeeMcpGrants(options)).resolves.toBeUndefined();
    await expect(
      verifyTeeMcpGrants({
        ...options,
        binding: { owner: grantee.address, chainId: 14800 },
      }),
    ).rejects.toThrow();
    await expect(
      verifyTeeMcpGrants({
        ...options,
        grants: [{ grantId: grant.id, scopes: ["spotify.history"] }],
      }),
    ).rejects.toThrow("scope");
    await expect(
      verifyTeeMcpGrants({
        ...options,
        connection: { ...connection, granteePublicKey: "0x04" },
      }),
    ).rejects.toThrow("grantee");
  });
});
