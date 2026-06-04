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
    fileId: "file-1",
    schemaId: null,
    path: `${SCOPE}/2026-01-21T10:00:00Z.json`,
    scope: SCOPE,
    collectedAt: "2026-01-21T10:00:00Z",
    createdAt: "2026-01-21T10:00:00Z",
    sizeBytes: 128,
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

function makeDeps(
  entries: IndexEntry[],
  overrides?: {
    getFile?: GatewayClient["getFile"];
    deleteFile?: GatewayClient["deleteFile"];
    storageDelete?: StorageAdapter["delete"];
  },
): DeleteWorkerDeps {
  const storage: Partial<DataStoragePort> = {
    listVersions: vi.fn().mockReturnValue(entries),
  };
  const gateway: Partial<GatewayClient> = {
    getFile:
      overrides?.getFile ??
      vi.fn(async (fileId: string) => ({
        fileId,
        owner: OWNER,
        url: `https://storage.vana.org/v1/blobs/${OWNER}/${SCOPE}/${fileId}`,
        schemaId: "0xschema",
        createdAt: "2026-01-21T10:00:00Z",
        deletedAt: null,
      })),
    deleteFile: overrides?.deleteFile ?? vi.fn(async () => undefined),
  };
  const storageAdapter: Partial<StorageAdapter> = {
    delete: overrides?.storageDelete ?? vi.fn(async () => true),
  };
  const signer: Partial<ServerSigner> = {
    signFileDeletion: vi.fn(async () => "0xsig" as `0x${string}`),
  };
  return {
    storage: storage as DataStoragePort,
    storageAdapter: storageAdapter as StorageAdapter,
    gateway: gateway as GatewayClient,
    signer: signer as ServerSigner,
    serverOwner: OWNER,
    logger: makeLogger(),
  };
}

describe("deleteScopeRemote", () => {
  it("de-registers each synced version: blob delete + owner-signed gateway deleteFile", async () => {
    const deps = makeDeps([
      makeEntry({ id: 1, fileId: "file-1" }),
      makeEntry({ id: 2, fileId: "file-2" }),
    ]);

    const result = await deleteScopeRemote(deps, SCOPE);

    expect(result).toMatchObject({
      scope: SCOPE,
      filesDeregistered: 2,
      blobsDeleted: 2,
      errors: [],
    });
    expect(deps.signer.signFileDeletion).toHaveBeenCalledWith({
      ownerAddress: OWNER,
      fileId: "file-1",
    });
    expect(deps.gateway.deleteFile).toHaveBeenCalledWith({
      fileId: "file-1",
      ownerAddress: OWNER,
      signature: "0xsig",
    });
    // blob deleted via the URL recovered from the gateway file record
    expect(deps.storageAdapter.delete).toHaveBeenCalledWith(
      `https://storage.vana.org/v1/blobs/${OWNER}/${SCOPE}/file-1`,
    );
  });

  it("skips local-only versions (fileId === null) — no remote calls", async () => {
    const deps = makeDeps([makeEntry({ id: 1, fileId: null })]);

    const result = await deleteScopeRemote(deps, SCOPE);

    expect(result.filesDeregistered).toBe(0);
    expect(result.blobsDeleted).toBe(0);
    expect(deps.gateway.deleteFile).not.toHaveBeenCalled();
    expect(deps.storageAdapter.delete).not.toHaveBeenCalled();
  });

  it("is best-effort: a per-file failure is collected and the rest continue", async () => {
    const deleteFile = vi
      .fn()
      .mockRejectedValueOnce(new Error("gateway 500"))
      .mockResolvedValueOnce(undefined);
    const deps = makeDeps(
      [
        makeEntry({ id: 1, fileId: "file-1" }),
        makeEntry({ id: 2, fileId: "file-2" }),
      ],
      { deleteFile: deleteFile as unknown as GatewayClient["deleteFile"] },
    );

    const result = await deleteScopeRemote(deps, SCOPE);

    expect(result.filesDeregistered).toBe(1);
    expect(result.errors).toEqual([
      { fileId: "file-1", message: "gateway 500" },
    ]);
    expect(deleteFile).toHaveBeenCalledTimes(2);
  });

  it("does not delete a blob when the gateway has no URL for the file", async () => {
    const deps = makeDeps([makeEntry({ id: 1, fileId: "file-1" })], {
      getFile: vi.fn(async () => null) as unknown as GatewayClient["getFile"],
    });

    const result = await deleteScopeRemote(deps, SCOPE);

    expect(deps.storageAdapter.delete).not.toHaveBeenCalled();
    // still de-registers at the gateway (idempotent)
    expect(result.filesDeregistered).toBe(1);
    expect(result.blobsDeleted).toBe(0);
  });
});
