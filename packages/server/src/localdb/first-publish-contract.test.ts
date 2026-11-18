import { describe, expect, it } from "vitest";
import { MemoryStreamSyncRegistry } from "../../../core/src/stream-sync/memory-registry.js";
import { createGatewayStreamSyncRegistry } from "../../../core/src/stream-sync/registry.js";
import type { SignedBatchRow } from "../../../core/src/stream-sync/ports.js";
import { createFakeGateway } from "./fake-gateway.js";

const owner = `0x${"11".repeat(20)}`;
const hash = (byte: string) => `0x${byte.repeat(32)}` as `0x${string}`;
const row = (
  byte: string,
  extra: Partial<SignedBatchRow> = {},
): SignedBatchRow => ({
  scope: "pdpp.fixture~.~log",
  expectedVersion: "1",
  dataHash: hash(byte),
  metadataHash: hash("cc"),
  signature: `0x${byte.repeat(65)}`,
  ...extra,
});

// The same contract cases run through both in-process adapters. The real
// gateway runs these schedules against PostgreSQL in its own repository.
for (const adapter of ["memory", "http"] as const) {
  describe(`first publication contract: ${adapter}`, () => {
    const registry = () =>
      adapter === "memory"
        ? new MemoryStreamSyncRegistry()
        : createGatewayStreamSyncRegistry({
            gatewayUrl: "https://gateway.test",
            ownerAddress: owner,
            fetch: createFakeGateway({
              owner,
              isTombstone: () => false,
              refresh: true,
              replay: "created",
            }).fetch,
          });

    it("first create, same signed replay, and another first writer", async () => {
      const r = registry();
      const first = row("aa", { expectedHeadAbsent: true });
      const post = (entry: SignedBatchRow) =>
        r.postBatch!({ ownerAddress: owner, rows: [entry], requires: [] });
      expect((await post(first)).kind).toBe("committed");
      expect((await post(first)).kind).toBe("committed");
      const loser = await post(row("bb", { expectedHeadAbsent: true }));
      expect(loser).toMatchObject({
        kind: "refused",
        rows: [
          {
            kind: "conflict",
            latestVersion: "1",
            latestDataHash: first.dataHash,
          },
        ],
      });
      expect(await r.read(first.scope)).toMatchObject({
        found: true,
        version: 1,
        dataHash: first.dataHash,
      });
    });

    it("unconditional pending refresh works, and a stale hash condition refuses it", async () => {
      const r = registry();
      const post = (entry: SignedBatchRow) =>
        r.postBatch!({ ownerAddress: owner, rows: [entry], requires: [] });
      expect((await post(row("aa"))).kind).toBe("committed");
      expect((await post(row("bb"))).kind).toBe("committed");
      expect(await r.read(row("bb").scope)).toMatchObject({
        version: 1,
        dataHash: hash("bb"),
      });
      expect(
        (await post(row("aa", { expectedHeadDataHash: hash("aa") }))).kind,
      ).toBe("refused");
    });
  });
}
