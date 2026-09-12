import type {
  GatewayClient,
  DataPortabilityGatewayConfig,
} from "@opendatalabs/vana-sdk/node";
import { verifySignedArtifacts } from "@opendatalabs/personal-server-ts-core/policy";
import type {
  McpConnectionGrant,
  McpConnectionRecord,
} from "@opendatalabs/personal-server-ts-core/mcp";
import type { McpOwnerBinding } from "./durable-state.js";

export async function verifyTeeMcpGrants(options: {
  connection: McpConnectionRecord;
  binding: McpOwnerBinding;
  grants: McpConnectionGrant[];
  gateway: Pick<GatewayClient, "getGrant" | "getBuilder">;
  gatewayConfig: DataPortabilityGatewayConfig;
  chainId: number;
}): Promise<void> {
  if (options.binding.chainId !== options.chainId)
    throw new Error("MCP chain mismatch");
  const builder = await options.gateway.getBuilder(
    options.connection.granteeAddress,
  );
  if (
    !builder ||
    builder.granteeAddress.toLowerCase() !==
      options.connection.granteeAddress.toLowerCase() ||
    builder.publicKey.toLowerCase() !==
      options.connection.granteePublicKey.toLowerCase()
  )
    throw new Error("MCP grantee mismatch");
  for (const requested of options.grants) {
    const grant = await options.gateway.getGrant(requested.grantId);
    if (!grant || grant.id.toLowerCase() !== requested.grantId.toLowerCase())
      throw new Error("MCP grant missing");
    await verifySignedArtifacts({
      grant,
      builder,
      gatewayConfig: options.gatewayConfig,
      ownerAddress: options.binding.owner,
    });
    if (requested.scopes.some((scope) => !grant.scopes.includes(scope)))
      throw new Error("MCP scope mismatch");
    if (grant.expiresAt && grant.expiresAt !== "0") {
      const expiry = /^\d+$/.test(grant.expiresAt)
        ? Number(grant.expiresAt) * 1000
        : Date.parse(grant.expiresAt);
      if (!Number.isFinite(expiry) || expiry <= Date.now())
        throw new Error("MCP grant expired");
    }
  }
}
