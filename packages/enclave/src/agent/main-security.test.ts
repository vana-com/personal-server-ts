const runtime = vi.hoisted(() => ({
  listen: vi.fn(),
  createServer: vi.fn(),
  createDstack: vi.fn(),
  startMcp: vi.fn(),
}));
vi.mock("./http.js", () => ({
  createAgentServer: runtime.createServer,
}));
vi.mock("../dstack/real.js", () => ({
  createRealDstackClient: runtime.createDstack,
}));
vi.mock("../mcp/service.js", () => ({ startMcpIngress: runtime.startMcp }));

describe("measured fleet worker entrypoint", () => {
  it("does not start when an unsigned flag disables fleet beside the measured trust key", async () => {
    const previousExitCode = process.exitCode;
    const previousSignals = new Set(process.listeners("SIGTERM"));
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    runtime.createServer.mockReturnValue({ listen: runtime.listen });
    vi.stubEnv("FLEET_CONFIG_PUBLIC_KEY", "measured-operator-public-key");
    vi.stubEnv("FLEET_SIGNED_CONFIG", undefined);
    vi.stubEnv("FLEET_ENABLED", "false");
    vi.stubEnv("DSTACK_FAKE", "1");
    vi.stubEnv("ENCLAVE_AGENT_SECRET", "unsigned-replacement-secret");
    vi.stubEnv("GATEWAY_URL", "");
    try {
      await import("./main.js");
      await vi.waitFor(() => expect(process.exitCode).toBe(1));
      expect(runtime.createDstack).not.toHaveBeenCalled();
      expect(runtime.startMcp).not.toHaveBeenCalled();
      expect(runtime.createServer).not.toHaveBeenCalled();
      expect(runtime.listen).not.toHaveBeenCalled();
    } finally {
      for (const handler of process.listeners("SIGTERM")) {
        if (!previousSignals.has(handler)) process.off("SIGTERM", handler);
      }
      process.exitCode = previousExitCode;
      errors.mockRestore();
      vi.unstubAllEnvs();
      vi.resetModules();
    }
  });
});
