import { fleetSandboxKey } from "./worker-key.js";
import { userPsId } from "@opendatalabs/vana-sdk/protocol/identity";
import type { McpWakeupIdentity } from "@opendatalabs/personal-server-ts-server/mcp/tee";
import { deriveEnclaveIdentity } from "../identity/wallet.js";
import { unseal } from "../sealing/envelope.js";
import { sandboxSpec, type PrewarmDeps } from "../jobs/run.js";
import type { SandboxLease } from "../sandbox/registry.js";
import {
  sameAssignment,
  type FleetAssignment,
  type FleetEnvelopeResponse,
  type FleetExecuteRequest,
  type FleetPrepareRequest,
  type FleetReadiness,
} from "./contracts.js";
import type { FleetWorkerBackend } from "./worker.js";

export function createFleetWorkerBackend(options: {
  sandbox: PrewarmDeps;
  envelope(
    assignment: FleetAssignment,
    signal: AbortSignal,
  ): Promise<FleetEnvelopeResponse>;
  verifyGrants(request: FleetExecuteRequest): Promise<void>;
  fetch?: typeof fetch;
}): FleetWorkerBackend {
  const requestFetch = options.fetch ?? fetch;
  async function identity(
    a: FleetAssignment,
    signal: AbortSignal,
  ): Promise<McpWakeupIdentity> {
    const result = await options.envelope(a, signal);
    if (
      !sameAssignment(a, result.assignment) ||
      result.identity.userPsId.toLowerCase() !== a.userPsId.toLowerCase() ||
      result.identity.epoch !== a.identityEpoch ||
      a.chainId !== options.sandbox.chainId
    )
      throw new Error("Fleet identity mismatch");
    return result.identity;
  }
  async function acquire(
    request: FleetPrepareRequest,
    signal: AbortSignal,
  ): Promise<SandboxLease> {
    signal.throwIfAborted();
    const material = await identity(request.assignment, signal);
    const derived = await deriveEnclaveIdentity(
      options.sandbox.client,
      material.userPsId,
      material.epoch,
    );
    if (
      derived.address.toLowerCase() !== material.enclaveAddress.toLowerCase() ||
      derived.publicKey.toLowerCase() !==
        material.enclavePublicKey.toLowerCase()
    )
      throw new Error("Fleet identity derivation mismatch");
    const signature = await unseal(
      options.sandbox.client,
      material.userPsId,
      material.epoch,
      material.sealedEnvelope,
    );
    try {
      signal.throwIfAborted();
      return await options.sandbox.registry.acquire(
        fleetSandboxKey(request.assignment),
        (accessToken) =>
          sandboxSpec(
            material,
            options.sandbox,
            accessToken,
            signature,
            request.scopes.map((s) => s.scope).join(","),
            () => {},
            () => {},
          ),
        signal,
      );
    } finally {
      signature.fill(0);
    }
  }
  async function observe(
    request: FleetPrepareRequest,
    sandbox: SandboxLease,
    signal: AbortSignal,
    hydrate: boolean,
  ): Promise<FleetReadiness[]> {
    const response = await requestFetch(
      `${sandbox.handle.origin}/enclave/v1/fleet/readiness`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${sandbox.accessToken}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ scopes: request.scopes, hydrate }),
        signal,
      },
    );
    if (!response.ok) throw new Error("Fleet scoped readiness unavailable");
    const reports = (await response.json()) as Omit<
      FleetReadiness,
      "assignment"
    >[];
    if (
      !Array.isArray(reports) ||
      reports.length !== request.scopes.length ||
      reports.some(
        (r, i) =>
          r.scope !== request.scopes[i].scope ||
          !["pending", "ready", "error"].includes(r.state) ||
          !Number.isFinite(Date.parse(r.observedAt)) ||
          (r.dataVersion !== null &&
            (!Number.isSafeInteger(r.dataVersion) || r.dataVersion < 1)) ||
          (r.state === "ready" &&
            (r.dataVersion === null ||
              r.dataVersion < (request.scopes[i].minimumVersion ?? 1))),
      )
    )
      throw new Error("Invalid fleet readiness response");
    return reports.map((r) => ({ ...r, assignment: request.assignment }));
  }
  async function readiness(
    request: FleetPrepareRequest,
    signal: AbortSignal,
  ): Promise<FleetReadiness[]> {
    const sandbox = await acquire(request, signal);
    try {
      return await observe(request, sandbox, signal, true);
    } finally {
      options.sandbox.registry.release(fleetSandboxKey(request.assignment));
    }
  }
  return {
    activity: (a) => options.sandbox.registry.activity(fleetSandboxKey(a)),
    prepare: readiness,
    readiness,
    async execute(request, signal) {
      if (
        request.connection.status !== "approved" ||
        request.connection.revokedAt ||
        !request.connection.grants.length ||
        request.binding.chainId !== request.assignment.chainId ||
        userPsId(
          request.binding.chainId,
          request.binding.owner,
        ).toLowerCase() !== request.assignment.userPsId.toLowerCase()
      )
        throw new Error("Fleet MCP owner mismatch");
      const granted = new Set(
        request.connection.grants.flatMap((g) => g.scopes),
      );
      if (request.scopes.some((s) => !granted.has(s.scope)))
        throw new Error("Fleet MCP scope mismatch");
      await options.verifyGrants(request);
      signal.throwIfAborted();
      const sandbox = await acquire(request, signal);
      try {
        const reports = await observe(request, sandbox, signal, true);
        if (reports.some((r) => r.state !== "ready"))
          throw new Error("Fleet MCP data pending");
        const response = await requestFetch(
          `${sandbox.handle.origin}/enclave/v1/mcp`,
          {
            method: "POST",
            headers: {
              authorization: `Bearer ${sandbox.accessToken}`,
              "content-type": "application/json",
            },
            body: JSON.stringify({
              owner: request.binding.owner,
              connection: request.connection,
              request: request.message,
            }),
            signal,
          },
        );
        const body = await readBounded(response, signal);
        signal.throwIfAborted();
        return {
          status: response.status,
          contentType:
            response.headers.get("content-type") ?? "application/json",
          body,
        };
      } finally {
        options.sandbox.registry.release(fleetSandboxKey(request.assignment));
      }
    },
    release: (a) => options.sandbox.registry.evict(fleetSandboxKey(a)),
  };
}
async function readBounded(
  response: Response,
  signal: AbortSignal,
): Promise<string> {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      signal.throwIfAborted();
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 4 * 1024 * 1024)
        throw new Error("Fleet MCP response too large");
      chunks.push(value);
    }
    return Buffer.concat(chunks).toString("utf8");
  } finally {
    await reader.cancel().catch(() => {});
  }
}
