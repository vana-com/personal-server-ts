import { afterEach, describe, expect, it, vi } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { ServerConfigSchema } from "../../schemas/server-config.js";
import { createVanaSyncStorageAdapter } from "./vana.js";

const owner = privateKeyToAccount(`0x${"47".repeat(32)}`);

function adapter() {
  return createVanaSyncStorageAdapter({
    config: ServerConfigSchema.parse({
      gateway: { chainId: 14800 },
      storage: { config: { vana: { apiUrl: "http://storage.test" } } },
    }),
    serverOwner: owner.address,
    serverAccount: {
      address: owner.address,
      signMessage: (message) => owner.signMessage({ message }),
    },
  });
}

function answer(status: number) {
  const fetchMock = vi.fn(async () => new Response(null, { status }));
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

afterEach(() => vi.unstubAllGlobals());

describe("Vana adapter exists (mocked HTTP)", () => {
  it("probes with HEAD, no redirects, and reads 200 as present", async () => {
    const fetchMock = answer(200);
    const a = adapter();
    await expect(a.exists(a.urlForKey("scope/blob"))).resolves.toBe(true);
    const init = (
      fetchMock.mock.calls[0] as unknown as [string, RequestInit]
    )[1];
    expect(init.method).toBe("HEAD");
    expect(init.redirect).toBe("error");
  });

  it("reads 404 as absent", async () => {
    answer(404);
    const a = adapter();
    await expect(a.exists(a.urlForKey("scope/blob"))).resolves.toBe(false);
  });

  it.each([201, 202, 204, 206, 401, 403, 410, 429, 500])(
    "throws on %i with the status, never present or absent",
    async (status) => {
      answer(status);
      const a = adapter();
      await expect(a.exists(a.urlForKey("scope/blob"))).rejects.toMatchObject({
        status,
      });
    },
  );

  it.each([301, 302, 307, 308])(
    "does not read redirect %i as present",
    async (status) => {
      // redirect:'error' makes real fetch reject; a mocked fetch that returns
      // the redirect response must still not yield true.
      answer(status);
      const a = adapter();
      await expect(a.exists(a.urlForKey("scope/blob"))).rejects.toMatchObject({
        status,
      });
    },
  );

  it("propagates a fetch rejection", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new TypeError("fetch failed");
      }),
    );
    const a = adapter();
    await expect(a.exists(a.urlForKey("scope/blob"))).rejects.toThrow(
      "fetch failed",
    );
  });
});
