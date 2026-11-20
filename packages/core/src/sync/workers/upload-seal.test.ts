/**
 * The upload worker and the legacy-write seal.
 *
 * Classification of the worker's durable steps:
 * - `storageAdapter.upload` (the blob) and the registry registration
 *   (`gateway.registerDataPoint`, `lineageGateway`, `fencedPublication.commit`):
 *   each is a NEW remote legacy object. Each runs as its own
 *   `legacyWriteSeal.commit` inside `publishVersion`, so neither starts after
 *   the account has moved to stream sync.
 * - `updateEntryVersion`, `updateDataPointId`: local metadata about a version
 *   that already exists. Not sealed.
 * - `deleteVersion`, `dropUnsyncedEntry`: local removals. Sealed in every mode
 *   by the storage's own `remove`.
 * A refused write stops the pass: it is not an entry failure and spends no
 * retry budget.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import type {
  DataFileEnvelope,
  GatewayClient,
  Schema,
} from "@opendatalabs/vana-sdk/browser";

vi.mock("@opendatalabs/vana-sdk/browser", () => ({
  deriveScopeKey: vi.fn(),
  encryptWithPassword: vi.fn(),
}));

import {
  deriveScopeKey,
  encryptWithPassword,
} from "@opendatalabs/vana-sdk/browser";
import { uploadAll, uploadOne, type UploadWorkerDeps } from "./upload.js";
import { createUploadStateTracker } from "../upload-state.js";
import { createLegacyWriteSeal } from "../../storage/legacy-write-seal.js";
import { LegacyWriteRefusedError } from "../../api/legacy-write-gate.js";
import {
  authorityHearing,
  fixedLegacyWriteSeal,
} from "../../test-utils/index.js";
import type { LegacyWriteSeal } from "../../storage/legacy-write-seal.js";
import type { IndexEntry } from "../../storage/index/types.js";
import type { StorageAdapter } from "../../storage/adapters/interface.js";
import type { ServerSigner } from "../../signing/signer.js";
import type { Logger } from "../../logger/index.js";
import type { DataStoragePort } from "../../ports/index.js";

const SCOPE = "instagram.profile";
const COLLECTED_AT = "2026-01-21T10:00:00Z";
const OWNER = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12";
const DATA_POINT_ID =
  "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
const tick = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

function entry(n = 1): IndexEntry {
  return {
    id: n,
    fileId: null,
    schemaId: null,
    path: `${SCOPE}/${n}-${COLLECTED_AT}.json`,
    scope: SCOPE,
    collectedAt: COLLECTED_AT,
    createdAt: COLLECTED_AT,
    sizeBytes: 256,
    version: 1,
    dataPointId: null,
  };
}

function build(seal: LegacyWriteSeal | undefined, entries: IndexEntry[] = []) {
  const envelope: DataFileEnvelope = {
    version: "1.0",
    scope: SCOPE,
    collectedAt: COLLECTED_AT,
    data: { username: "testuser" },
  };
  const storage = {
    findUnsynced: vi.fn().mockReturnValue(entries),
    updateDataPointId: vi.fn().mockReturnValue(true),
    updateEntryVersion: vi.fn().mockReturnValue(true),
    readEnvelope: vi.fn().mockResolvedValue(envelope),
    legacyWriteSeal: seal,
  };
  const adapter = {
    upload: vi.fn().mockResolvedValue("https://storage.test/blob"),
    urlForKey: vi.fn((key: string) => `https://storage.test/${OWNER}/${key}`),
    exists: vi.fn().mockResolvedValue(true),
  };
  const gateway = {
    getSchemaForScope: vi.fn().mockResolvedValue({
      id: "0x12",
      ownerAddress: OWNER,
      name: "n",
      definitionUrl: "https://schemas.test/n.json",
      scope: SCOPE,
      addedAt: COLLECTED_AT,
    } satisfies Schema),
    getDataPoint: vi.fn().mockResolvedValue(null),
    registerDataPoint: vi
      .fn()
      .mockResolvedValue({ dataPointId: DATA_POINT_ID, expectedVersion: "1" }),
  };
  const signer = {
    signAddData: vi.fn().mockResolvedValue("0xsig" as `0x${string}`),
    signLineageAttestation: vi.fn().mockResolvedValue("0xsig"),
  };
  const logger = {
    info: vi.fn(),
    error: vi.fn(),
    warn: vi.fn(),
    debug: vi.fn(),
  };
  const state = createUploadStateTracker();
  const deps: UploadWorkerDeps = {
    storage: storage as unknown as DataStoragePort,
    storageAdapter: adapter as unknown as StorageAdapter,
    gateway: gateway as unknown as GatewayClient,
    signer: signer as unknown as ServerSigner,
    masterKey: new Uint8Array(65).fill(0xaa),
    serverOwner: OWNER,
    logger: logger as unknown as Logger,
    uploadState: state,
  } as UploadWorkerDeps;
  return { deps, storage, adapter, gateway, logger, state };
}

beforeEach(() => {
  vi.clearAllMocks();
  (deriveScopeKey as ReturnType<typeof vi.fn>).mockReturnValue(
    new Uint8Array(32).fill(0xbb),
  );
  (encryptWithPassword as ReturnType<typeof vi.fn>).mockResolvedValue(
    new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
  );
});

describe("uploadOne when legacy storage is closed", () => {
  // PUBLISH_UPLOAD_UNSEALED
  it.each(["switched", "unknown"] as const)(
    "uploads and registers nothing on a %s account",
    async (mode) => {
      const f = build(fixedLegacyWriteSeal(mode));
      await expect(uploadOne(f.deps, entry())).rejects.toBeInstanceOf(
        LegacyWriteRefusedError,
      );
      expect(f.adapter.upload).not.toHaveBeenCalled();
      expect(f.gateway.registerDataPoint).not.toHaveBeenCalled();
      expect(f.storage.updateDataPointId).not.toHaveBeenCalled();
    },
  );

  it("uploads and registers on an unswitched account", async () => {
    const f = build(fixedLegacyWriteSeal("unswitched"));
    await uploadOne(f.deps, entry());
    expect(f.adapter.upload).toHaveBeenCalledTimes(1);
    expect(f.gateway.registerDataPoint).toHaveBeenCalledTimes(1);
    expect(f.storage.updateDataPointId).toHaveBeenCalledTimes(1);
  });

  it("is unsealed when the storage carries no seal (a host with no switch)", async () => {
    const f = build(undefined);
    await uploadOne(f.deps, entry());
    expect(f.gateway.registerDataPoint).toHaveBeenCalledTimes(1);
  });
});

describe("uploadAll when legacy storage is closed", () => {
  // UPLOAD_REFUSAL_COUNTED_AS_FAILURE
  it("stops the pass cleanly: no error callback, no retry budget, no later entry", async () => {
    const f = build(fixedLegacyWriteSeal("switched"), [entry(1), entry(2)]);
    const onError = vi.fn();
    const results = await uploadAll(f.deps, { onError });
    expect(results).toEqual([]);
    expect(onError).not.toHaveBeenCalled();
    expect(f.logger.error).not.toHaveBeenCalled();
    // The second entry was never offered: the pass stopped at the first.
    expect(f.storage.readEnvelope).toHaveBeenCalledTimes(1);
    // The refused entry stays eligible: nothing was recorded against it.
    expect(f.state.shouldAttempt(entry(1).path, Date.now())).toBe(true);
    expect(f.state.shouldAttempt(entry(1).path, Number.MAX_SAFE_INTEGER)).toBe(
      true,
    );
  });
});

describe("against a real mode authority", () => {
  const onEvidence = () => ({
    owner: OWNER,
    state: "on" as const,
  });

  // Each remote write is its own commit: a switch that lands between the blob
  // and the registration refuses the registration.
  it("lets the blob upload in flight finish, then refuses the registration", async () => {
    const authority = await authorityHearing(OWNER, "off");
    const seal = createLegacyWriteSeal({ authority, owner: OWNER });
    const f = build(seal);
    let release!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    let uploading = false;
    f.adapter.upload.mockImplementation(async () => {
      uploading = true;
      await held;
      return "https://storage.test/blob";
    });

    const running = uploadOne(f.deps, entry());
    const settled = running.then(
      () => "ok" as const,
      (error: unknown) => error,
    );
    await vi.waitFor(() => expect(uploading).toBe(true));
    let uploadsWhenAnswered = -1;
    const answered = authority.submitEvidence(onEvidence()).then(() => {
      uploadsWhenAnswered = f.adapter.upload.mock.results.length;
    });
    await tick();
    await tick();
    expect(uploadsWhenAnswered).toBe(-1);
    release();

    expect(await settled).toBeInstanceOf(LegacyWriteRefusedError);
    await answered;
    expect(f.adapter.upload).toHaveBeenCalledTimes(1);
    expect(f.gateway.registerDataPoint).not.toHaveBeenCalled();
    expect(f.storage.updateDataPointId).not.toHaveBeenCalled();
  });
});
