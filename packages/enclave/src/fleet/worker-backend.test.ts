import { describe, expect, it, vi } from "vitest";
import { createFakeDstackClient } from "../dstack/fake.js";
import { deriveEnclaveIdentity } from "../identity/wallet.js";
import { userPsId } from "../identity/paths.js";
import { seal } from "../sealing/envelope.js";
import { createSandboxRegistry } from "../sandbox/registry.js";
import { createFleetWorkerBackend } from "./worker-backend.js";
import type { FleetAssignment, FleetExecuteRequest } from "./contracts.js";
import type { PrewarmDeps } from "../jobs/run.js";

const owner = "0x1111111111111111111111111111111111111111" as const;
async function setup() {
  const client = createFakeDstackClient({ appId: "22".repeat(20) });
  const id = userPsId(14800, owner);
  const derived = await deriveEnclaveIdentity(client, id, 1);
  const sealed = await seal(client, id, 1, new Uint8Array(65).fill(7));
  const assignment: FleetAssignment = {
    chainId: 14800,
    userPsId: id,
    identityEpoch: 1,
    nodeId: "a",
    nodeIncarnation: "boot",
    generation: 1,
    controllerTerm: 1,
    state: "ready",
    leaseExpiresAt: new Date(Date.now() + 30_000).toISOString(),
  };
  const runtime = {
    reconcile: vi.fn(),
    start: vi
      .fn()
      .mockResolvedValue({ id: "sandbox-a", origin: "http://sandbox-a" }),
    stop: vi.fn(),
    inspect: vi.fn(),
  };
  const registry = createSandboxRegistry({ runtime });
  const envelope = vi.fn().mockResolvedValue({
    assignment,
    identity: {
      userPsId: id,
      epoch: 1,
      enclaveAddress: derived.address,
      enclavePublicKey: derived.publicKey,
      sealedEnvelope: sealed,
    },
  });
  const requestFetch = vi.fn(async (input: string, init: RequestInit) => {
    if (input.endsWith("/readiness"))
      return Response.json(
        JSON.parse(String(init.body)).scopes.map((s: { scope: string }) => ({
          scope: s.scope,
          dataVersion: 2,
          state: "ready",
          observedAt: new Date().toISOString(),
        })),
      );
    return Response.json({ jsonrpc: "2.0", id: 1, result: { content: [] } });
  });
  const verifyGrants = vi.fn().mockResolvedValue(undefined);
  const backend = createFleetWorkerBackend({
    envelope,
    verifyGrants,
    fetch: requestFetch as never,
    sandbox: {
      client,
      registry,
      chainId: 14800,
      contracts: {},
      logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
    } as unknown as PrewarmDeps,
  });
  const request: FleetExecuteRequest = {
    assignment,
    binding: { owner, chainId: 14800 },
    scopes: [{ scope: "spotify.profile" }],
    requestId: "read",
    deadline: new Date(Date.now() + 30_000).toISOString(),
    message: { jsonrpc: "2.0", id: 1, method: "tools/list" },
    connection: {
      status: "approved",
      grants: [{ grantId: "grant", scopes: ["spotify.profile"] }],
    } as never,
  };
  return {
    backend,
    request,
    envelope,
    runtime,
    registry,
    requestFetch,
    verifyGrants,
  };
}
describe("worker peer execution", () => {
  it("cold-wakes from the authenticated envelope endpoint and reuses the same local generation", async () => {
    const f = await setup();
    const signal = new AbortController().signal;
    await f.backend.prepare(f.request, signal);
    const result = await f.backend.execute(f.request, signal);
    expect(result.status).toBe(200);
    expect(f.envelope).toHaveBeenCalledTimes(2);
    expect(f.verifyGrants.mock.invocationCallOrder[0]).toBeLessThan(
      f.envelope.mock.invocationCallOrder[1],
    );
    expect(f.runtime.start).toHaveBeenCalledOnce();
    await f.backend.release(f.request.assignment);
    expect(f.runtime.stop).toHaveBeenCalledWith("sandbox-a");
  });
  it("rejects a substituted owner or revoked grant before any envelope access or startup", async () => {
    const f = await setup();
    const signal = new AbortController().signal;
    await expect(
      f.backend.execute(
        {
          ...f.request,
          binding: {
            owner: "0x2222222222222222222222222222222222222222",
            chainId: 14800,
          },
        },
        signal,
      ),
    ).rejects.toThrow("owner mismatch");
    f.verifyGrants.mockRejectedValue(new Error("revoked grant"));
    await expect(f.backend.execute(f.request, signal)).rejects.toThrow(
      "revoked grant",
    );
    expect(f.envelope).not.toHaveBeenCalled();
    expect(f.runtime.start).not.toHaveBeenCalled();
  });
});
