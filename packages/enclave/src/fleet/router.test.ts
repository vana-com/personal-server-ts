import { describe, expect, it, vi } from "vitest";
import { McpOwnerAccessRevokedError } from "@opendatalabs/personal-server-ts-server/mcp/tee";
import { userPsId } from "@opendatalabs/vana-sdk/protocol/identity";
import { resolveFleetOwner } from "./router.js";

const OWNER = "0x1111111111111111111111111111111111111111";
const BINDING = { owner: OWNER, chainId: 14800 } as const;

describe("fleet owner resolution", () => {
  const options = (fetch: typeof globalThis.fetch) => ({
    chainId: 14800,
    gatewayUrl: "https://gateway.example",
    fetch,
  });

  it("separates a withdrawn owner identity from a gateway outage", async () => {
    const retired = vi
      .fn()
      .mockResolvedValue(Response.json({ state: "retired", sealed: false }));
    await expect(
      resolveFleetOwner(BINDING, options(retired as never)),
    ).rejects.toBeInstanceOf(McpOwnerAccessRevokedError);

    const down = vi.fn().mockResolvedValue(new Response(null, { status: 500 }));
    const outage = resolveFleetOwner(BINDING, options(down as never));
    await expect(outage).rejects.not.toBeInstanceOf(McpOwnerAccessRevokedError);
  });

  it("returns the live epoch while the identity is sealed", async () => {
    const fetch = vi.fn().mockResolvedValue(
      Response.json({
        state: "sealed",
        sealed: true,
        identity: {
          userPsId: userPsId(14800, OWNER),
          epoch: 3,
          ownerAddress: OWNER,
          chainId: 14800,
        },
      }),
    );
    await expect(
      resolveFleetOwner(BINDING, options(fetch as never)),
    ).resolves.toEqual({
      chainId: 14800,
      userPsId: userPsId(14800, OWNER),
      identityEpoch: 3,
    });
  });
});
