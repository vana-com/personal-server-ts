import { expect, it, vi } from "vitest";
import {
  ScopeSchema,
  DataFileEnvelopeSchema,
} from "@opendatalabs/vana-sdk/browser";
import { isSystemScope } from "../policy/reserved-scopes.js";
import { verifyDataReadPolicy } from "../policy/data-read.js";
import { scopeCoveredByWriteGrant } from "../policy/data-write.js";
import { resolveGrantForRawScopeResource } from "../mcp/resources.js";
import { replicaScope, fragmentReplicaPayload } from "./transport.js";
import { downloadOne } from "../sync/workers/download.js";
import { uploadOne } from "../sync/workers/upload.js";
const scope = replicaScope("a".repeat(32), "b".repeat(32), 0);
it("keeps replica scope grammar separate from legacy scopes and private to owner transport", async () => {
  expect(ScopeSchema.parse(scope)).toBe(scope);
  expect(isSystemScope(scope)).toBe(true);
  expect(scopeCoveredByWriteGrant(scope, ["write:*"])).toBe(false);
  const getBuilder = vi.fn();
  await expect(
    verifyDataReadPolicy(
      {
        requestedScope: scope,
        signer: "0x1",
        serverOwner: "0x2",
        grantId: "old-wildcard",
      },
      {
        authSessionVerifier: { getBuilder },
        grantVerifier: { getGrant: vi.fn() },
      } as never,
    ),
  ).rejects.toThrow();
  expect(getBuilder).not.toHaveBeenCalled();
  expect(
    resolveGrantForRawScopeResource(
      { grants: [{ grantId: "old-wildcard", scopes: ["*"] }] } as never,
      scope,
    ),
  ).toBeNull();
  // Raw replica scopes must never enter the ordinary file index or rebase worker.
  expect(await downloadOne({} as never, { scope } as never)).toBeNull();
  await expect(uploadOne({} as never, { scope } as never)).rejects.toThrow(
    "replica",
  );
});
it("PS-Lite 1.33.2-shaped cache accepts fragments but exact legacy reads ignore them", async () => {
  const parts = await fragmentReplicaPayload({
    owner: "owner",
    writer: "a".repeat(32),
    batch: "b".repeat(32),
    sequence: 1,
    previous: null,
    bytes: new TextEncoder().encode("opaque"),
    collectedAt: "2026-10-20T00:00:00.000Z",
    encrypt: async (_scope, bytes) => bytes,
  });
  // v1.33.2 download.ts:348-357 uses DataFileEnvelopeSchema; read ports select by exact scope.
  const legacyCache = parts.map((p) =>
    DataFileEnvelopeSchema.parse(
      JSON.parse(new TextDecoder().decode(p.plaintext)),
    ),
  );
  for (const legacy of [
    "chatgpt.conversations",
    "oura.sleep",
    "claude.conversations",
    "spotify.savedTracks",
  ]) {
    expect(legacyCache.find((row) => row.scope === legacy)).toBeUndefined();
  }
  expect(legacyCache[0]!.scope).toBe(scope);
});

it("refuses new grants that explicitly name the transport namespace", async () => {
  const { createGrantContract } = await import("../contracts/grants.js");
  const getBuilder = vi.fn();
  for (const granted of [scope, "pdpp_replica_v1.*", `write:${scope}`]) {
    const result = await createGrantContract({
      serverOwner: "0x1234",
      serverSigner: { signGrantRegistration: vi.fn() },
      gateway: { getBuilder, createGrant: vi.fn() },
      body: {
        granteeAddress: "0x0000000000000000000000000000000000000001",
        scopes: [granted],
      },
    });
    expect(result.status).toBe(400);
  }
  expect(getBuilder).not.toHaveBeenCalled();
});

it("omits internal transport addresses from the actual inventory API even with wildcard grants", async () => {
  const { handlePersonalServerDataRequest } = await import("../api/index.js");
  const { createMemoryDataStorage } =
    await import("../test-utils/memory-storage.js");
  const storage = createMemoryDataStorage();
  for (const s of [scope, "chatgpt.conversations"]) {
    const envelope = {
      version: "1.0" as const,
      scope: s,
      collectedAt: "2026-10-20T00:00:00.000Z",
      data: {},
    };
    const written = await storage.writeEnvelope(envelope);
    storage.insertEntry({
      ...written,
      scope: s,
      collectedAt: envelope.collectedAt,
      version: 1,
    } as never);
  }
  const response = await handlePersonalServerDataRequest(
    new Request("http://ps/"),
    {
      storage,
      auth: {
        authorizeOwner: vi.fn(),
        authorizeBuilderRead: vi.fn(),
        authorizeBuilderList: vi.fn(async () => ({ grantedScopes: ["*"] })),
      },
      accessLogWriter: { write: vi.fn() },
    } as never,
  );
  expect(response.status).toBe(200);
  const body = await response.json();
  expect(body.scopes.map((r: { scope: string }) => r.scope)).toEqual([
    "chatgpt.conversations",
  ]);
  expect(body.total).toBe(1);
});
