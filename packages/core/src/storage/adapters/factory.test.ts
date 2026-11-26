import { beforeEach, describe, expect, it, vi } from "vitest";
import { ServerConfigSchema } from "../../schemas/server-config.js";
import type { BoundedStorageAdapter } from "./interface.js";

const gdriveCtor = vi.fn();
const vanaCtor = vi.fn();
vi.mock("./gdrive.js", () => ({
  createGoogleDriveStorageAdapter: (...args: unknown[]) => {
    gdriveCtor(...args);
    return { kind: "gdrive" } as unknown as BoundedStorageAdapter;
  },
}));
vi.mock("./vana.js", () => ({
  createVanaSyncStorageAdapter: (...args: unknown[]) => {
    vanaCtor(...args);
    return { kind: "vana" } as unknown as BoundedStorageAdapter;
  },
}));

const { createSyncStorageAdapter } = await import("./factory.js");

function paramsFor(backend: string) {
  const config = ServerConfigSchema.parse({});
  return {
    config: { ...config, storage: { ...config.storage, backend } } as never,
    serverOwner: `0x${"11".repeat(20)}` as const,
    serverAccount: {
      address: `0x${"22".repeat(20)}` as const,
      signMessage: async () => "0x00" as const,
    },
  };
}

describe("createSyncStorageAdapter backend selection", () => {
  beforeEach(() => {
    gdriveCtor.mockClear();
    vanaCtor.mockClear();
  });

  it.each(["local", "vana", "ipfs", "dropbox"])(
    "%s uses Vana Hosted Storage",
    (backend) => {
      createSyncStorageAdapter(paramsFor(backend));
      expect(vanaCtor).toHaveBeenCalledTimes(1);
      expect(gdriveCtor).not.toHaveBeenCalled();
    },
  );

  it("a value outside the schema throws and constructs neither adapter", () => {
    expect(() => createSyncStorageAdapter(paramsFor("not-a-backend"))).toThrow(
      /storage backend/i,
    );
    expect(vanaCtor).not.toHaveBeenCalled();
    expect(gdriveCtor).not.toHaveBeenCalled();
  });
});
