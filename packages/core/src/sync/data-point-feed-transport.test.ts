import { describe, expect, it, vi } from "vitest";
import { createGatewayDataPointFeed } from "./data-point-feed.js";
import { computeDataPointId } from "./data-point-id.js";

const OWNER = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12";
const GATEWAY = "https://gateway.test";
const PHYSICAL = "pdpp.chatgpt~0123456789abcdef.conversations";
const LOGICAL = "instagram.profile";

// Test 7: a physical point lookup is a private transport read, so the owner
// capability signs it. The lookup itself still happens and is not filtered out.
describe("physical point lookup owner authorization", () => {
  it("signs the physical point lookup with the owner capability and still fetches it", async () => {
    const signRequest = vi.fn(async () => "Web3Signed owner-proof");
    const seen: { url: string; authorization: string | null }[] = [];
    const fetchImpl: typeof fetch = async (input, init) => {
      seen.push({
        url: String(input),
        authorization: new Headers(init?.headers).get("authorization"),
      });
      return new Response(null, { status: 404 });
    };
    const feed = createGatewayDataPointFeed({
      gatewayUrl: GATEWAY,
      fetch: fetchImpl,
      ownerRequestSigner: { signRequest },
    });

    await expect(
      feed.getDataPoint({ ownerAddress: OWNER, scope: PHYSICAL }),
    ).resolves.toBeNull();

    const id = computeDataPointId(OWNER, PHYSICAL);
    expect(signRequest).toHaveBeenCalledExactlyOnceWith({
      aud: GATEWAY,
      method: "GET",
      uri: `/v1/data/${id}`,
    });
    expect(seen).toEqual([
      {
        url: `${GATEWAY}/v1/data/${id}?includeDeleted=true`,
        authorization: "Web3Signed owner-proof",
      },
    ]);
  });

  it("leaves an ordinary logical point lookup unsigned", async () => {
    const signRequest = vi.fn(async () => "Web3Signed owner-proof");
    const fetchImpl = vi.fn(async () => new Response(null, { status: 404 }));
    const feed = createGatewayDataPointFeed({
      gatewayUrl: GATEWAY,
      fetch: fetchImpl as unknown as typeof fetch,
      ownerRequestSigner: { signRequest },
    });
    await feed.getDataPoint({ ownerAddress: OWNER, scope: LOGICAL });
    expect(signRequest).not.toHaveBeenCalled();
  });
});
