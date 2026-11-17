import { afterEach, expect, it, vi } from "vitest";
import { ServerConfigSchema } from "../../schemas/server-config.js";
import { createVanaSyncStorageAdapter } from "./vana.js";

afterEach(() => vi.unstubAllGlobals());

const owner = "0x1111111111111111111111111111111111111111";

it("sends every storage request through the fetch the host gave it, not globalThis.fetch", async () => {
  const global = vi.fn(async () => {
    throw new Error("globalThis.fetch must not be used");
  });
  vi.stubGlobal("fetch", global);
  const sent: string[] = [];
  const hostFetch = (async (
    input: string | URL | Request,
    init?: RequestInit,
  ) => {
    sent.push(`${init?.method ?? "GET"} ${String(input)}`);
    return new Response(JSON.stringify({ url: String(input) }), {
      status: init?.method === "HEAD" ? 200 : 201,
    });
  }) as typeof fetch;
  const adapter = createVanaSyncStorageAdapter({
    config: ServerConfigSchema.parse({
      storage: {
        backend: "vana",
        config: { vana: { apiUrl: "https://storage.test" } },
      },
      gateway: { chainId: 14800 },
    }),
    serverOwner: owner,
    serverAccount: {
      address: owner,
      signMessage: async () => `0x${"ab".repeat(65)}`,
    },
    fetch: hostFetch,
  });

  await adapter.upload("scope/1", new Uint8Array([1, 2, 3])).catch(() => {});
  await adapter.exists(adapter.urlForKey("scope/1"));

  expect(sent.map((request) => request.split(" ")[0])).toEqual(
    expect.arrayContaining(["PUT", "HEAD"]),
  );
  expect(sent.every((request) => request.includes("storage.test"))).toBe(true);
  expect(global).not.toHaveBeenCalled();
});
