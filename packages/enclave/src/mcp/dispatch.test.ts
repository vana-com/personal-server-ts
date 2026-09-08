import { describe, expect, it, vi } from "vitest";
import { dispatchOwnerMcp } from "./dispatch.js";
import { userPsId } from "@opendatalabs/vana-sdk/protocol/identity";

describe("TEE MCP owner wakeup", () => {
  it("refuses a retired or replaced cached identity before opening its sealed envelope", async () => {
    const owner = "0x1111111111111111111111111111111111111111";
    const id = userPsId(14800, owner);
    const client = { deriveKey: vi.fn() };
    const registry = { acquire: vi.fn() };
    const state = {
      getIdentity: vi
        .fn()
        .mockResolvedValue({ userPsId: id, epoch: 1, enclaveAddress: owner }),
    };
    const fetch = vi.fn().mockResolvedValue(
      Response.json({
        state: "sealed",
        sealed: true,
        identity: {
          userPsId: id,
          epoch: 2,
          ownerAddress: owner,
          chainId: 14800,
        },
      }),
    );
    await expect(
      dispatchOwnerMcp(
        new Request("https://mcp-dev.vana.org/mcp", {
          method: "POST",
          body: "{}",
        }),
        { grants: [{ scopes: ["spotify.profile"] }] } as never,
        { owner, chainId: 14800 },
        {
          state,
          client,
          registry,
          gatewayUrl: "https://gateway.example",
          chainId: 14800,
          fetch,
        } as never,
      ),
    ).rejects.toThrow("identity");
    expect(client.deriveKey).not.toHaveBeenCalled();
    expect(registry.acquire).not.toHaveBeenCalled();
  });
});
