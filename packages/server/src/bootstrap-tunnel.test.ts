import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { createServer } from "./bootstrap.js";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";

const tunnelMocks = vi.hoisted(() => ({
  reserve: vi.fn((): string => "https://0xabc.server.test"),
  connect: vi.fn(async (): Promise<string> => "https://0xabc.server.test"),
  stop: vi.fn(async (): Promise<void> => {}),
  getStatus: vi.fn(() => ({
    enabled: true,
    status: "connected" as const,
    publicUrl: "https://0xabc.server.test",
    connectedSince: null,
  })),
  ensureFrpcBinary: vi.fn(async (): Promise<string> => "/tmp/fake-frpc"),
}));

vi.mock("./tunnel/index.js", async (importOriginal) => {
  const actual = (await importOriginal()) as Record<string, unknown>;
  return {
    ...actual,
    ensureFrpcBinary: tunnelMocks.ensureFrpcBinary,
    TunnelManager: class {
      reserve = tunnelMocks.reserve;
      connect = tunnelMocks.connect;
      stop = tunnelMocks.stop;
      getStatus = tunnelMocks.getStatus;
    },
  };
});

// Same known-good signature the sync wiring tests use; the recovered owner
// only needs to be a valid address.
const knownSig =
  "0xedbb7743cce459345238442dcfb291f234a321d253485eaa58251aa0f28ea8f1410ab988bae2657b689cd24417b41e315efc22ba333024f4a6269c424ded8d361b";

function makeTunnelConfig() {
  return ServerConfigSchema.parse({
    tunnel: { enabled: true },
    sync: { enabled: false },
  });
}

function makeGateway(getServer: ReturnType<typeof vi.fn>) {
  return { getServer } as never;
}

describe("bootstrap tunnel gating (BUI-611)", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "bootstrap-tunnel-"));
    vi.stubEnv("VANA_MASTER_KEY_SIGNATURE", knownSig);
    tunnelMocks.reserve.mockClear();
    tunnelMocks.connect.mockClear();
    tunnelMocks.connect.mockResolvedValue("https://0xabc.server.test");
    tunnelMocks.stop.mockClear();
  });

  afterEach(async () => {
    vi.useRealTimers();
    vi.unstubAllEnvs();
    await rm(tempDir, { recursive: true, force: true });
  });

  it("connects immediately when the server is already registered", async () => {
    const getServer = vi.fn().mockResolvedValue({ id: "srv-1" });
    const ctx = await createServer(makeTunnelConfig(), {
      serverDir: tempDir,
      dataDir: join(tempDir, "data"),
      gatewayClient: makeGateway(getServer),
    });
    await ctx.startBackgroundServices();

    expect(tunnelMocks.reserve).toHaveBeenCalledTimes(1);
    expect(tunnelMocks.connect).toHaveBeenCalledTimes(1);
    expect(ctx.tunnelUrl).toBe("https://0xabc.server.test");
    await ctx.cleanup();
  });

  it("defers frpc until the registration poll sees the server", async () => {
    const getServer = vi.fn().mockResolvedValue(null);
    const ctx = await createServer(makeTunnelConfig(), {
      serverDir: tempDir,
      dataDir: join(tempDir, "data"),
      gatewayClient: makeGateway(getServer),
    });

    vi.useFakeTimers();
    await ctx.startBackgroundServices();

    // Reserved but NOT dialing: this is the whole point of the reorder.
    expect(tunnelMocks.reserve).toHaveBeenCalledTimes(1);
    expect(tunnelMocks.connect).not.toHaveBeenCalled();
    expect(ctx.tunnelUrl).toBe("https://0xabc.server.test");

    // First poll at 5s: still unregistered.
    await vi.advanceTimersByTimeAsync(5_000);
    expect(tunnelMocks.connect).not.toHaveBeenCalled();

    // Registration lands; next 5s poll starts the tunnel.
    getServer.mockResolvedValue({ id: "srv-9" });
    await vi.advanceTimersByTimeAsync(5_000);
    expect(tunnelMocks.connect).toHaveBeenCalledTimes(1);
    expect(ctx.isServerRegistered()).toBe(true);

    // Poll stopped: no further gateway lookups.
    const calls = getServer.mock.calls.length;
    await vi.advanceTimersByTimeAsync(60_000);
    expect(getServer.mock.calls.length).toBe(calls);
    await ctx.cleanup();
  });

  it("falls back to the local origin when connect fails", async () => {
    const getServer = vi.fn().mockResolvedValue({ id: "srv-1" });
    tunnelMocks.connect.mockRejectedValue(new Error("spawn failed"));
    const ctx = await createServer(makeTunnelConfig(), {
      serverDir: tempDir,
      dataDir: join(tempDir, "data"),
      gatewayClient: makeGateway(getServer),
    });
    await ctx.startBackgroundServices();

    // Local-only mode: no dead public URL left behind for signers/health.
    expect(ctx.tunnelUrl).toBeUndefined();
    expect(ctx.tunnelManager).toBeUndefined();
    const res = await ctx.app.request("/health");
    const body = await res.json();
    expect(body.apiOrigin).toBe(ctx.config.server.origin);
    await ctx.cleanup();
  });

  it("cleanup stops a mid-flight poll before it can spawn frpc", async () => {
    let resolveLookup: (value: unknown) => void = () => {};
    const getServer = vi
      .fn()
      .mockResolvedValueOnce(null) // boot registration check
      .mockImplementationOnce(
        () => new Promise((resolve) => (resolveLookup = resolve)),
      );
    const ctx = await createServer(makeTunnelConfig(), {
      serverDir: tempDir,
      dataDir: join(tempDir, "data"),
      gatewayClient: makeGateway(getServer),
    });

    vi.useFakeTimers();
    await ctx.startBackgroundServices();

    // Poll fires and is now awaiting the gateway lookup (timer handle null).
    await vi.advanceTimersByTimeAsync(5_000);
    expect(getServer).toHaveBeenCalledTimes(2);

    await ctx.cleanup();

    // The lookup settles AFTER shutdown with a registered server — the
    // orphaned poll must neither spawn frpc nor reschedule itself.
    resolveLookup({ id: "srv-late" });
    await vi.advanceTimersByTimeAsync(120_000);
    expect(tunnelMocks.connect).not.toHaveBeenCalled();
    expect(getServer).toHaveBeenCalledTimes(2);
  });
});
