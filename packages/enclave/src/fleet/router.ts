import { randomUUID } from "node:crypto";
import {
  userPsId,
  type IdentityResponse,
} from "@opendatalabs/vana-sdk/protocol/identity";
import type {
  McpOwnerBinding,
  TeeMcpIngressDeps,
} from "@opendatalabs/personal-server-ts-server/mcp/tee";
import type { FleetController } from "./placement.js";
import { sameAssignment, type FleetOwner } from "./contracts.js";
/** Read current protocol identity; never require a controller-side envelope cache. */
export async function resolveFleetOwner(
  binding: McpOwnerBinding,
  options: { chainId: number; gatewayUrl: string; fetch?: typeof fetch },
): Promise<FleetOwner> {
  if (binding.chainId !== options.chainId)
    throw new Error("MCP identity chain mismatch");
  const url = new URL("/v1/identity", options.gatewayUrl);
  url.searchParams.set("owner", binding.owner);
  url.searchParams.set("chainId", String(binding.chainId));
  const response = await (options.fetch ?? fetch)(url, {
    signal: AbortSignal.timeout(15_000),
  });
  if (!response.ok) throw new Error("Current owner identity unavailable");
  const live = (await response.json()) as IdentityResponse;
  const id = userPsId(binding.chainId, binding.owner);
  if (
    live.state !== "sealed" ||
    !live.sealed ||
    !live.identity ||
    live.identity.userPsId !== id ||
    live.identity.ownerAddress.toLowerCase() !== binding.owner.toLowerCase() ||
    live.identity.chainId !== binding.chainId
  )
    throw new Error("Current owner identity unavailable");
  return {
    chainId: binding.chainId,
    userPsId: id,
    identityEpoch: live.identity.epoch,
  };
}
export function createFleetMcpRouting(options: {
  controller: FleetController;
  chainId: number;
  gatewayUrl: string;
  fetch?: typeof fetch;
}): Pick<TeeMcpIngressDeps, "dispatch" | "ownerReady"> {
  return {
    ownerReady: async (binding) => {
      try {
        await resolveFleetOwner(binding, options);
        return true;
      } catch {
        return false;
      }
    },
    dispatch: async (request, connection, binding) => {
      const owner = await resolveFleetOwner(binding, options);
      const scopes = [
        ...new Set(connection.grants.flatMap((g) => g.scopes)),
      ].map((scope) => ({ scope }));
      const assignment = await options.controller.ensure(owner, scopes);
      const deadline = new Date(Date.now() + 120_000).toISOString();
      const result = await options.controller.worker(assignment).execute({
        assignment,
        scopes,
        requestId: randomUUID(),
        deadline,
        connection,
        binding,
        message: await request.json(),
      });
      const current = options.controller.assignment(owner);
      if (
        request.signal.aborted ||
        !current ||
        !sameAssignment(current, assignment) ||
        !sameAssignment(result.assignment, assignment) ||
        Date.parse(deadline) <= Date.now()
      )
        throw new Error("Stale fleet response rejected");
      if (
        !Number.isInteger(result.status) ||
        result.status < 200 ||
        result.status > 599 ||
        typeof result.body !== "string" ||
        Buffer.byteLength(result.body) > 8 * 1024 * 1024
      )
        throw new Error("Invalid fleet response");
      return new Response(result.body || null, {
        status: result.status,
        headers: {
          "content-type":
            result.contentType === "text/event-stream"
              ? "text/event-stream"
              : "application/json",
          "cache-control": "no-store",
        },
      });
    },
  };
}
