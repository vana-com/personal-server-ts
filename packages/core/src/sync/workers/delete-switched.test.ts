/**
 * A legacy delete after the switch to stream sync, through the real seal.
 *
 * Once an account has switched, the gateway admits one kind of legacy write:
 * the exact tombstone over a live head, signed by the owner or a registered
 * server (cutover policy v3). The seal must let that tombstone out as a
 * removal (`seal.remove`) and keep every other legacy write closed
 * (`seal.commit`).
 */
import { describe, expect, it, vi } from "vitest";
import { deleteScope } from "./delete.js";
import { LegacyWriteRefusedError } from "../../api/legacy-write-gate.js";
import { createLegacyWriteSeal } from "../../storage/legacy-write-seal.js";
import { authorityHearing } from "../../test-utils/account-mode.js";
import {
  createLegacyGatewayFake,
  FAKE_CHAIN_ID,
  FAKE_GATEWAY,
  FAKE_STORAGE,
  type FakeCutover,
  type FakeSignerRole,
} from "../../test-utils/legacy-gateway-fake.js";
import { createMemoryDataStorage } from "../../test-utils/memory-storage.js";
import { createGatewayDeleteDataPort } from "../delete-data-port.js";
import { createMemoryPendingBlobDeletionStore } from "../pending-blob-deletions.js";
import type { Logger } from "../../logger/index.js";

const OWNER = "0x1111111111111111111111111111111111111111" as const;
const SCOPE = "notes.entries";

const logger = () =>
  ({
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  }) as unknown as Logger;

async function switchedDelete(
  cutover: FakeCutover,
  signer: FakeSignerRole = "server",
) {
  const fake = createLegacyGatewayFake({ owner: OWNER, cutover, signer });
  fake.seed(SCOPE, 2);
  const authority = await authorityHearing(OWNER, "on");
  const seal = createLegacyWriteSeal({ authority, owner: OWNER });
  const storage = createMemoryDataStorage({ legacyWriteSeal: seal });
  const deleteData = createGatewayDeleteDataPort({
    gatewayUrl: FAKE_GATEWAY,
    dataPointFeed: fake.feed,
    serverOwner: OWNER,
    signer: fake.signer,
    storage: {
      endpoint: FAKE_STORAGE,
      chainId: FAKE_CHAIN_ID,
      signMessage: async () => `0x${"ab".repeat(65)}`,
    },
    fetch: fake.fetch,
  });
  const deps = {
    storage,
    serverOwner: OWNER,
    deleteData,
    pendingBlobDeletions: createMemoryPendingBlobDeletionStore(),
    dataPointFeed: fake.feed,
    logger: logger(),
  };
  return { fake, seal, storage, deps };
}

describe("a delete on a switched account", () => {
  it("sends the legacy tombstone through the seal, and the gateway lists the point as deleted", async () => {
    const f = await switchedDelete("v3");
    const result = await deleteScope(f.deps, SCOPE);
    expect(result.steps.gateway.status).toBe("ok");
    expect(result.durable).toBe(true);
    expect(
      f.fake.requests.filter((r) => r.url.startsWith(FAKE_GATEWAY)),
    ).toHaveLength(1);
    expect(f.fake.isLive(SCOPE)).toBe(false);
    expect(f.fake.tombstones.get(SCOPE)).toEqual([3]);
  });

  it("still refuses every other legacy write: only the removal is admitted", async () => {
    const f = await switchedDelete("v3");
    await deleteScope(f.deps, SCOPE);
    await expect(f.seal.commit(async () => undefined)).rejects.toBeInstanceOf(
      LegacyWriteRefusedError,
    );
  });

  it("carries a policy-v1 refusal as a typed, terminal gateway answer", async () => {
    const f = await switchedDelete("v1");
    const result = await deleteScope(f.deps, SCOPE);
    expect(result.steps.gateway).toMatchObject({
      status: "failed",
      code: "owner_stream_sync_required",
    });
    expect(f.fake.isLive(SCOPE)).toBe(true);
  });

  it.each([
    ["revoked", "server_revoked"],
    ["unregistered", "server_unregistered"],
  ] as const)("names a %s signer", async (role, code) => {
    const f = await switchedDelete("v3", role);
    const result = await deleteScope(f.deps, SCOPE);
    expect(result.steps.gateway).toMatchObject({ status: "failed", code });
  });
});
