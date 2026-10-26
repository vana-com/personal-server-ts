import { describe, it, expect, vi } from "vitest";
import { createHash } from "node:crypto";
import {
  createPersistentPsLiteStorage,
  createIndexedDbFallbackDataFileStore,
} from "./storage.js";
import { createMcpDataReadClient } from "../../core/src/mcp/read-client.js";
import { buildDataBlocksAsync } from "../../core/src/storage/blocks/build.js";

const windowHook = vi.hoisted(() => ({
  afterBuilderYield: undefined as undefined | ((input: any) => void),
}));
vi.mock("../../core/src/storage/blocks/build.js", async (importOriginal) => {
  const original = await importOriginal<any>();
  return {
    ...original,
    buildDataBlocksAsync(input: any) {
      // Call the REAL async builder first. For JSON it has now executed extraction
      // and suspended at its existing await, before buildDataBlocksInternal.
      const pending = original.buildDataBlocksAsync(input);
      windowHook.afterBuilderYield?.(input);
      return pending;
    },
  };
});
function digest(value: unknown) {
  return createHash("sha256")
    .update(
      JSON.stringify(value, (_key, item) =>
        item && typeof item === "object" && !Array.isArray(item)
          ? Object.fromEntries(
              Object.entries(item).sort(([a], [b]) =>
                a < b ? -1 : a > b ? 1 : 0,
              ),
            )
          : item,
      ),
    )
    .digest("hex");
}

describe("Fallback immutable ownership at real Lite + MCP boundary", () => {
  for (const mode of ["page", "selection", "manifest"] as const)
    for (const kind of ["control", "legacy", "pdpp"] as const)
      for (const bytes of [false, true]) {
        it(`${mode}: ${kind} mutation at real builder yield; bytes primitive=${bytes}`, async () => {
          windowHook.afterBuilderYield = undefined;
          const envelopes = new Map();
          const manifests = new Map();
          const payloads = new Map();
          const files = createIndexedDbFallbackDataFileStore(
            envelopes,
            manifests,
            payloads,
          );
          let persisted: any;
          const storage = await createPersistentPsLiteStorage(
            { kind: "custom" },
            {
              read: async () => persisted,
              write: async (value) => {
                persisted = value;
              },
            },
            files,
          );
          const source: any = {
            version: "1.0",
            scope: "test.fallback",
            collectedAt: "2026-10-01T00:00:00.000Z",
            data: { nested: { message: "authorized-original" } },
          };
          const published = await storage.writeEnvelope(source);
          await storage.insertEntry({
            fileId: null,
            path: published.relativePath,
            scope: source.scope,
            collectedAt: source.collectedAt,
            sizeBytes: published.sizeBytes,
          });
          const built = await buildDataBlocksAsync({
            scope: source.scope,
            collectedAt: source.collectedAt,
            content: source,
          });
          // An actual older sidecar with no generation-bound stamp context forces
          // withDisclosurePolicy.readCheckedBlocks, not a fake storage response.
          delete built.manifest.redaction;
          await storage.writeBlockManifest!(
            source.scope,
            source.collectedAt,
            built.manifest,
            built.blocks,
          );
          const pinned = storage.findEntry({ scope: source.scope })!.generation;
          expect(pinned).toBe(digest(source));
          expect([...envelopes.values()][0]).toBe(source);
          expect(storage.readEnvelopeBytes).toBeUndefined();
          if (bytes)
            storage.readEnvelopeBytes = async (scope, at) =>
              new TextEncoder().encode(
                JSON.stringify(await storage.readEnvelope(scope, at)),
              );
          const auth = vi.fn(async (_request: { metadataOnly?: boolean }) => ({
            grantId: "grant",
            builder: "0x2222",
          }));
          const access = vi.fn(async () => undefined);
          const client = createMcpDataReadClient({
            serverOrigin: "https://server.test",
            granteeAccount: {
              address: "0x1111111111111111111111111111111111111111",
              publicKey: "0x04deadbeef",
              signTypedData: vi.fn(),
              signMessage: vi.fn().mockResolvedValue(`0x${"11".repeat(65)}`),
            },
            dataApiDeps: {
              storage,
              auth: {
                authorizeOwner: vi.fn(),
                authorizeBuilderList: vi.fn(),
                authorizeBuilderRead: auth,
              },
              accessLogWriter: { write: access },
            },
          });
          let hookCount = 0;
          windowHook.afterBuilderYield = (input) => {
            windowHook.afterBuilderYield = undefined;
            hookCount++;
            expect(digest(input.content)).toBe(pinned);
            expect(input.content.data.nested.message).toBe(
              "authorized-original",
            );
            if (kind !== "control") {
              source.data.nested.message = `${kind}-unverified-after-check`;
              if (kind === "pdpp")
                source.data.$pdpp = {
                  version: 1,
                  sourceId: "https://registry.pdpp.dev/oura",
                };
            }
          };
          let result: any, failure: any;
          try {
            result =
              mode === "manifest"
                ? await client.readBlockManifest!({
                    scope: source.scope,
                    grantId: "grant",
                  })
                : await client.readScopeBlocks({
                    scope: source.scope,
                    grantId: "grant",
                    maxBytes: 4096,
                    ...(mode === "selection"
                      ? { blockIds: ["block-000002"] }
                      : {}),
                  });
          } catch (error) {
            failure = error;
          } finally {
            windowHook.afterBuilderYield = undefined;
          }
          expect(hookCount).toBe(1);
          expect([...manifests.values()][0]).toMatchObject({
            envelopeDigest: pinned,
            pdppOrigin: false,
          });
          expect(failure).toBeUndefined();
          if (mode !== "manifest") expect(result.status).toBe(200);
          expect(
            auth.mock.calls.filter(([request]) => !request.metadataOnly),
          ).toHaveLength(mode === "manifest" ? 0 : 1);
          if (kind !== "control") expect(digest(source)).not.toBe(pinned);
          // Security oracle: a success serves the original authorized value only.
          expect(JSON.stringify(result.blocks)).not.toContain(
            "unverified-after-check",
          );
          expect(JSON.stringify(result.blocks)).not.toContain(
            "registry.pdpp.dev",
          );
          if (mode !== "manifest")
            expect(JSON.stringify(result.blocks)).toContain(
              "authorized-original",
            );
        });
      }
});
