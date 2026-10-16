import { describe, expect, it, vi } from "vitest";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { AdditionsBudget } from "@opendatalabs/personal-server-ts-core/additions";
import { parseWeb3SignedHeader } from "@opendatalabs/vana-sdk/browser";
import { createMemoryPsLiteStateStore } from "./test-support/memory.js";
import { createPsLiteAdditionsTransport } from "./additions-transport.js";

const ownerAddress = "0x1111111111111111111111111111111111111111";
const prepared = {
  scope: "vana.system.additions.spotify.profile",
  expectedVersion: "3",
  dataHash: `0x${"ab".repeat(32)}` as `0x${string}`,
  metadataHash: `0x${"cd".repeat(32)}` as `0x${string}`,
  encrypted: new Uint8Array([34, 67, 89]),
};
function setup(fetcher: typeof fetch) {
  const stateStore = createMemoryPsLiteStateStore();
  stateStore.bounded = {
    async get(key, signal) {
      signal?.throwIfAborted();
      return stateStore.get(key);
    },
    async set(key, value, signal) {
      signal?.throwIfAborted();
      await stateStore.set(key, value);
    },
    async delete(key, signal) {
      signal?.throwIfAborted();
      await stateStore.delete(key);
    },
  };
  const config = ServerConfigSchema.parse({
    gateway: { url: "https://gateway.example" },
    storage: { config: { vana: { apiUrl: "https://storage.example" } } },
  });
  const ownerSigner = {
    signMessageBounded: vi.fn(async () => "0x1234" as const),
    signAddDataBounded: vi.fn(async () => "0x5678" as const),
  };
  const transport = createPsLiteAdditionsTransport({
    config,
    ownerAddress,
    masterKey: new Uint8Array(32).fill(4),
    stateStore,
    ownerSigner,
    fetch: fetcher,
  });
  return { transport, stateStore, config, ownerSigner };
}

describe("bounded owner checkpoint transport", () => {
  it("sends the installed SDK wire contract and retains interrupted publication across restart", async () => {
    const requests: { url: string; init: RequestInit }[] = [];
    const fetcher = vi.fn<typeof fetch>(async (input, init) => {
      requests.push({ url: String(input), init: init ?? {} });
      return new Response("{}", { status: requests.length === 2 ? 503 : 200 });
    });
    const { transport, stateStore, config, ownerSigner } = setup(fetcher);
    await expect(
      transport.publish(prepared, new AdditionsBudget(100_000)),
    ).rejects.toThrow("registration failed");
    expect(requests[0].url).toBe(
      `https://storage.example/v1/chains/${config.gateway.chainId}/blobs/${ownerAddress}/vana.system.additions.spotify.profile/3`,
    );
    const header = new Headers(requests[0].init.headers).get("authorization");
    expect(parseWeb3SignedHeader(header ?? "").payload).toMatchObject({
      aud: "https://storage.example",
      method: "PUT",
      uri: new URL(requests[0].url).pathname,
    });
    expect(requests[0].init.body).toEqual(prepared.encrypted);
    expect(new Headers(requests[1].init.headers).get("authorization")).toBe(
      "Web3Signed 0x5678",
    );
    expect(
      JSON.parse(
        String(
          requests[1].init.body instanceof Uint8Array
            ? new TextDecoder().decode(requests[1].init.body)
            : requests[1].init.body,
        ),
      ),
    ).toEqual({
      ownerAddress,
      scope: prepared.scope,
      dataHash: prepared.dataHash,
      metadataHash: prepared.metadataHash,
      expectedVersion: "3",
    });
    const restarted = createPsLiteAdditionsTransport({
      config,
      ownerAddress,
      masterKey: new Uint8Array(32).fill(4),
      stateStore,
      ownerSigner,
      fetch: fetcher,
    });
    expect(
      await restarted.readPending(prepared.scope, new AdditionsBudget(100_000)),
    ).toEqual(prepared);
    await expect(
      restarted.publish(
        { ...prepared, expectedVersion: "4" },
        new AdditionsBudget(100_000),
      ),
    ).rejects.toThrow("reconciled");
    expect(fetcher).toHaveBeenCalledTimes(2);
    await restarted.clearPending(prepared.scope, new AdditionsBudget(100_000));
    expect(
      await restarted.readPending(prepared.scope, new AdditionsBudget(100_000)),
    ).toBeNull();
  });

  it("passes cancellation to the actual signing operation before any network write", async () => {
    const fetcher = vi.fn<typeof fetch>();
    const { transport, ownerSigner } = setup(fetcher);
    const budget = new AdditionsBudget(100_000, 5);
    ownerSigner.signMessageBounded.mockImplementation(
      async (_message, signal?: AbortSignal) => {
        await new Promise<void>((resolve) =>
          signal?.addEventListener("abort", () => resolve(), { once: true }),
        );
        signal?.throwIfAborted();
        return "0x1234";
      },
    );
    await expect(transport.publish(prepared, budget)).rejects.toThrow();
    expect(fetcher).not.toHaveBeenCalled();
    expect(
      await transport.readPending(prepared.scope, new AdditionsBudget(100_000)),
    ).toEqual(prepared);
  });
});
