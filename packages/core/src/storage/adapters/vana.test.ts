import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Capture the config handed to the SDK provider factory so we can assert the
// resolved chainId passthrough without hitting the network. Hoisted so the
// vi.mock factory (also hoisted) can reference it. The provider stub only needs
// the SdkStorageProvider surface the adapter delegates to.
const { createVanaStorageProvider } = vi.hoisted(() => ({
  createVanaStorageProvider: vi.fn(() => ({
    upload: vi.fn(),
    download: vi.fn(),
    delete: vi.fn(),
  })),
}));

vi.mock("@opendatalabs/vana-sdk/browser", () => ({
  createVanaStorageProvider,
}));

import { ServerConfigSchema } from "../../schemas/server-config.js";
import type { ServerAccount } from "../../keys/server-account.js";
import { ServerSigningUnavailableError } from "../../errors/catalog.js";
import { createVanaSyncStorageAdapter } from "./vana.js";

const OWNER = "0xAbC0000000000000000000000000000000000001" as `0x${string}`;
const OWNER_LOWER = OWNER.toLowerCase();

const account: ServerAccount = {
  address: OWNER,
  publicKey: `0x04${"00".repeat(64)}` as `0x${string}`,
  signMessage: async () => "0xsig" as `0x${string}`,
  signTypedData: async () => "0xsig" as `0x${string}`,
};

function buildAdapter(
  overrides: Record<string, unknown>,
  reads?: "signed" | "public",
) {
  const config = ServerConfigSchema.parse({
    storage: { backend: "vana", config: { vana: {} } },
    ...overrides,
  });
  const adapter = createVanaSyncStorageAdapter({
    config,
    serverOwner: OWNER,
    serverAccount: account,
    ...(reads ? { reads } : {}),
  });
  return adapter;
}

describe("createVanaSyncStorageAdapter — chain-scoped storage", () => {
  beforeEach(() => {
    createVanaStorageProvider.mockClear();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("downloads public blobs without constructing a signer", async () => {
    const body = new Uint8Array([1, 2, 3]);
    const fetchMock = vi.fn().mockResolvedValue(new Response(body));
    vi.stubGlobal("fetch", fetchMock);
    const adapter = buildAdapter({ gateway: { chainId: 14800 } }, "public");
    const url = `https://storage.vana.org/v1/chains/14800/blobs/${OWNER_LOWER}/scope.name/v1`;

    await expect(adapter.download(url)).resolves.toEqual(body);
    expect(fetchMock).toHaveBeenCalledWith(url, { method: "GET" });
    expect(createVanaStorageProvider).not.toHaveBeenCalled();
    await expect(adapter.upload("scope.name/v1", body)).rejects.toBeInstanceOf(
      ServerSigningUnavailableError,
    );
    await expect(adapter.delete(url)).rejects.toBeInstanceOf(
      ServerSigningUnavailableError,
    );
  });

  it.each(["%2f", "%5c"])(
    "rejects an encoded %s separator in a public blob URL",
    async (separator) => {
      const fetchMock = vi.fn();
      vi.stubGlobal("fetch", fetchMock);
      const adapter = buildAdapter({ gateway: { chainId: 14800 } }, "public");
      const url = `https://storage.vana.org/v1/chains/14800/blobs/${OWNER_LOWER}/scope${separator}..${separator}other`;

      await expect(adapter.download(url)).rejects.toThrow(
        "Public blob URL does not match the configured storage namespace",
      );
      expect(fetchMock).not.toHaveBeenCalled();
    },
  );

  it("scopes blob paths by the gateway chainId (moksha, 14800)", () => {
    const adapter = buildAdapter({ gateway: { chainId: 14800 } });

    expect(createVanaStorageProvider).toHaveBeenCalledWith(
      expect.objectContaining({ chainId: 14800 }),
    );
    expect(adapter.urlForKey("scope.name/2026-01-01T00:00:00.000Z")).toBe(
      `https://storage.vana.org/v1/chains/14800/blobs/${OWNER_LOWER}/scope.name/2026-01-01T00%3A00%3A00.000Z`,
    );
  });

  it("scopes blob paths by the gateway chainId (mainnet, 1480)", () => {
    const adapter = buildAdapter({ gateway: { chainId: 1480 } });

    expect(createVanaStorageProvider).toHaveBeenCalledWith(
      expect.objectContaining({ chainId: 1480 }),
    );
    expect(adapter.urlForKey("scope.name/v1")).toBe(
      `https://storage.vana.org/v1/chains/1480/blobs/${OWNER_LOWER}/scope.name/v1`,
    );
  });

  it("keeps apiUrl (product host) independent of the resolved chainId", () => {
    const adapter = buildAdapter({
      gateway: { chainId: 14800 },
      storage: {
        backend: "vana",
        config: { vana: { apiUrl: "https://storage-dev.vana.org" } },
      },
    });

    // Product host stays whatever apiUrl configured; chainId still scopes path.
    expect(createVanaStorageProvider).toHaveBeenCalledWith(
      expect.objectContaining({
        endpoint: "https://storage-dev.vana.org",
        chainId: 14800,
      }),
    );
    expect(adapter.urlForKey("scope/v1")).toBe(
      `https://storage-dev.vana.org/v1/chains/14800/blobs/${OWNER_LOWER}/scope/v1`,
    );
  });
});
