import { describe, expect, it, vi, beforeEach } from "vitest";

// Capture the config handed to the SDK provider factory so we can assert the
// resolved network passthrough without hitting the network. Hoisted so the
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
import { createVanaSyncStorageAdapter } from "./vana.js";

const OWNER = "0xAbC0000000000000000000000000000000000001" as `0x${string}`;
const OWNER_LOWER = OWNER.toLowerCase();

const account: ServerAccount = {
  address: OWNER,
  publicKey: `0x04${"00".repeat(64)}` as `0x${string}`,
  signMessage: async () => "0xsig" as `0x${string}`,
  signTypedData: async () => "0xsig" as `0x${string}`,
};

function buildAdapter(overrides: Record<string, unknown>) {
  const config = ServerConfigSchema.parse({
    storage: { backend: "vana", config: { vana: {} } },
    ...overrides,
  });
  const adapter = createVanaSyncStorageAdapter({
    config,
    serverOwner: OWNER,
    serverAccount: account,
  });
  return adapter;
}

describe("createVanaSyncStorageAdapter — network scoping", () => {
  beforeEach(() => {
    createVanaStorageProvider.mockClear();
  });

  it("maps gateway chainId 14800 to moksha URLs and network", () => {
    const adapter = buildAdapter({ gateway: { chainId: 14800 } });

    expect(createVanaStorageProvider).toHaveBeenCalledWith(
      expect.objectContaining({ network: "moksha" }),
    );
    expect(adapter.urlForKey("scope.name/2026-01-01T00:00:00.000Z")).toBe(
      `https://storage.vana.org/v1/networks/moksha/blobs/${OWNER_LOWER}/scope.name/2026-01-01T00%3A00%3A00.000Z`,
    );
  });

  it("maps gateway chainId 1480 to mainnet URLs and network", () => {
    const adapter = buildAdapter({ gateway: { chainId: 1480 } });

    expect(createVanaStorageProvider).toHaveBeenCalledWith(
      expect.objectContaining({ network: "mainnet" }),
    );
    expect(adapter.urlForKey("scope.name/v1")).toBe(
      `https://storage.vana.org/v1/networks/mainnet/blobs/${OWNER_LOWER}/scope.name/v1`,
    );
  });

  it("lets explicit config network override the chainId mapping", () => {
    const adapter = buildAdapter({
      gateway: { chainId: 14800 },
      storage: { backend: "vana", config: { vana: { network: "mainnet" } } },
    });

    expect(createVanaStorageProvider).toHaveBeenCalledWith(
      expect.objectContaining({ network: "mainnet" }),
    );
    expect(adapter.urlForKey("scope/v1")).toBe(
      `https://storage.vana.org/v1/networks/mainnet/blobs/${OWNER_LOWER}/scope/v1`,
    );
  });

  it("preserves legacy /v1/blobs URLs and omits network for unknown chainId", () => {
    const adapter = buildAdapter({ gateway: { chainId: 999999 } });

    expect(createVanaStorageProvider).toHaveBeenCalledWith(
      expect.objectContaining({ network: undefined }),
    );
    expect(adapter.urlForKey("scope/v1")).toBe(
      `https://storage.vana.org/v1/blobs/${OWNER_LOWER}/scope/v1`,
    );
  });

  it("keeps apiUrl (product host) independent of the resolved network", () => {
    const adapter = buildAdapter({
      gateway: { chainId: 14800 },
      storage: {
        backend: "vana",
        config: { vana: { apiUrl: "https://storage-dev.vana.org" } },
      },
    });

    // Product host stays whatever apiUrl configured; network still scopes path.
    expect(createVanaStorageProvider).toHaveBeenCalledWith(
      expect.objectContaining({
        endpoint: "https://storage-dev.vana.org",
        network: "moksha",
      }),
    );
    expect(adapter.urlForKey("scope/v1")).toBe(
      `https://storage-dev.vana.org/v1/networks/moksha/blobs/${OWNER_LOWER}/scope/v1`,
    );
  });
});
