import { describe, it, expect, vi } from "vitest";

import type { DeleteWorkerDeps } from "./delete.js";
import { deleteScopeRemote } from "./delete.js";
import type { IndexEntry } from "../../storage/index/types.js";
import type { StorageAdapter } from "../../storage/adapters/interface.js";
import type { GatewayClient } from "@opendatalabs/vana-sdk/browser";
import type { ServerSigner } from "../../signing/signer.js";
import type { Logger } from "../../logger/index.js";
import type { DataStoragePort } from "../../ports/index.js";

const SCOPE = "instagram.profile";
const OWNER = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12";

function makeEntry(overrides?: Partial<IndexEntry>): IndexEntry {
  return {
    id: 1,
    fileId: null,
    schemaId: null,
    path: `${SCOPE}/2026-01-21T10:00:00Z.json`,
    scope: SCOPE,
    collectedAt: "2026-01-21T10:00:00Z",
    createdAt: "2026-01-21T10:00:00Z",
    sizeBytes: 128,
    version: 1,
    dataPointId: "0xdp-1",
    ...overrides,
  };
}

function makeLogger(): Logger {
  return {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  } as unknown as Logger;
}

function makeDeps(entries: IndexEntry[]): DeleteWorkerDeps {
  const storage: Partial<DataStoragePort> = {
    listVersions: vi.fn().mockReturnValue(entries),
  };
  // Remote calls must never be made on DPv2 — track them to assert absence.
  const gateway = {
    getDataPoint: vi.fn(),
    registerDataPoint: vi.fn(),
  } as unknown as GatewayClient;
  const storageAdapter: Partial<StorageAdapter> = {
    delete: vi.fn(async () => true),
  };
  const signer = {} as ServerSigner;
  return {
    storage: storage as DataStoragePort,
    storageAdapter: storageAdapter as StorageAdapter,
    gateway,
    signer,
    serverOwner: OWNER,
    logger: makeLogger(),
  };
}

// The DPv2 gateway has no data-point de-registration / deletion endpoint, so
// remote scope deletion is a no-op (local data is removed elsewhere via the
// storage port's deleteScope). These tests pin that contract: no remote calls,
// zero counts, and a warning when synced versions would otherwise be orphaned.
describe("deleteScopeRemote (DPv2 no-op)", () => {
  it("makes no remote calls and reports zero de-registrations / blob deletes", async () => {
    const deps = makeDeps([
      makeEntry({ id: 1, dataPointId: "0xdp-1" }),
      makeEntry({ id: 2, dataPointId: "0xdp-2" }),
    ]);

    const result = await deleteScopeRemote(deps, SCOPE);

    expect(result).toEqual({
      scope: SCOPE,
      filesDeregistered: 0,
      blobsDeleted: 0,
      errors: [],
    });
    expect(deps.storageAdapter.delete).not.toHaveBeenCalled();
  });

  it("warns when synced versions exist (remote copies left in place)", async () => {
    const deps = makeDeps([makeEntry({ dataPointId: "0xdp-1" })]);

    await deleteScopeRemote(deps, SCOPE);

    expect(deps.logger.warn).toHaveBeenCalledWith(
      expect.objectContaining({ scope: SCOPE, syncedVersions: 1 }),
      expect.stringContaining("not supported on the DPv2 gateway"),
    );
  });

  it("does not warn for local-only versions (never synced)", async () => {
    const deps = makeDeps([makeEntry({ dataPointId: null })]);

    const result = await deleteScopeRemote(deps, SCOPE);

    expect(result.filesDeregistered).toBe(0);
    expect(deps.logger.warn).not.toHaveBeenCalled();
  });
});
