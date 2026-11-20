/**
 * The download worker and the legacy-write seal.
 *
 * Classification of the worker's durable steps (see also the table in the
 * PR description):
 * - install the blob and its index row (`commitVersion`, `writeEnvelopeAndIndex`
 *   or `writeEnvelope` + `insertEntry`): a NEW legacy version. Sealed inside
 *   the storage port; the worker only has to stop cleanly when it is refused.
 * - `updateDataPointId`, `updateEntryVersion`, block sidecars, the first-seen
 *   ledger: metadata about a version that already exists. Not sealed.
 * - `deleteVersion`, `deleteByFileId`, `deleteFirstSeenLedger`: removals.
 *   Sealed in every mode by the storage's own `remove`.
 * - the PDPP import: a canonical publish, sealed in the importer.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import type {
  DataFileEnvelope,
  DataPointRecord,
  GatewayClient,
} from "@opendatalabs/vana-sdk/browser";

vi.mock("@opendatalabs/vana-sdk/browser", async (importOriginal) => ({
  ...(await importOriginal()),
  deriveScopeKey: vi.fn(),
  decryptWithPassword: vi.fn(),
}));

import {
  decryptWithPassword,
  deriveScopeKey,
} from "@opendatalabs/vana-sdk/browser";
import {
  downloadAll,
  downloadScopes,
  type DownloadWorkerDeps,
} from "./download.js";
import { createDownloadRetryMemory } from "../retry-memory.js";
import { createLegacyWriteSeal } from "../../storage/legacy-write-seal.js";
import {
  authorityHearing,
  fixedLegacyWriteSeal,
} from "../../test-utils/index.js";
import {
  createMemoryDataStorage,
  type MemoryDataStorage,
} from "../../test-utils/memory-storage.js";
import { LegacyWriteRefusedError } from "../../api/legacy-write-gate.js";
import type { StorageAdapter } from "../../storage/adapters/interface.js";
import type { Logger } from "../../logger/index.js";
import type { LegacyWriteSeal } from "../../storage/legacy-write-seal.js";

const OWNER = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12";

function gate() {
  let open!: () => void;
  const opened = new Promise<void>((resolve) => {
    open = resolve;
  });
  return { opened, open };
}
const tick = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

const point = (n: number): DataPointRecord => ({
  id: `0x${String(n).repeat(64)}`,
  ownerAddress: OWNER,
  scope: `notes.entries${n}`,
  dataHash: "0x" + "11".repeat(32),
  metadataHash: "0x" + "22".repeat(32),
  expectedVersion: "1",
  addedAt: "2026-11-01T10:00:00Z",
});

const envelopeFor = (n: number): DataFileEnvelope => ({
  version: "1.0",
  scope: `notes.entries${n}`,
  collectedAt: "2026-11-01T10:00:00Z",
  data: { n },
});

function build(
  storage: MemoryDataStorage,
  listed: DataPointRecord[],
  cursorWrite = vi.fn().mockResolvedValue(undefined),
) {
  const download = vi.fn().mockResolvedValue(new Uint8Array([1, 2, 3]));
  const logger = {
    info: vi.fn(),
    error: vi.fn(),
    warn: vi.fn(),
    debug: vi.fn(),
  };
  const deps: DownloadWorkerDeps = {
    storage,
    storageAdapter: {
      urlForKey: (key: string) => `https://storage.example/${key}`,
      download,
    } as unknown as StorageAdapter,
    gateway: {
      listDataPointsByOwner: vi
        .fn()
        .mockResolvedValue({ dataPoints: listed, cursor: "next" }),
    } as unknown as GatewayClient,
    dataPointFeed: {
      listDataPointsByOwner: vi
        .fn()
        .mockResolvedValue({ dataPoints: listed, cursor: "next" }),
      getDataPoint: vi.fn(
        async ({ scope }: { scope: string }) =>
          listed.find((row) => row.scope === scope) ?? null,
      ),
    } as never,
    cursor: { read: vi.fn().mockResolvedValue(null), write: cursorWrite },
    masterKey: new Uint8Array(65).fill(0xaa),
    serverOwner: OWNER,
    logger: logger as unknown as Logger,
  } as DownloadWorkerDeps;
  return { deps, download, logger, cursorWrite };
}

beforeEach(() => {
  vi.clearAllMocks();
  (deriveScopeKey as ReturnType<typeof vi.fn>).mockReturnValue(
    new Uint8Array(32).fill(0xbb),
  );
  // Each blob decrypts to the envelope of the scope it was fetched for.
  let served = 0;
  (decryptWithPassword as ReturnType<typeof vi.fn>).mockImplementation(
    async () => {
      served += 1;
      return new TextEncoder().encode(JSON.stringify(envelopeFor(served)));
    },
  );
});

async function sealFor(state: "off" | "on") {
  const authority = await authorityHearing(OWNER, state);
  return {
    authority,
    seal: createLegacyWriteSeal({ authority, owner: OWNER }),
  };
}

describe("downloadAll when legacy storage is closed", () => {
  // DOWNLOAD_REFUSAL_COUNTED_AS_FAILURE
  it.each(["switched", "unknown"] as const)(
    "stops cleanly on a %s account: nothing stored, no record failure, cursor held",
    async (mode) => {
      const storage = createMemoryDataStorage({
        legacyWriteSeal: fixedLegacyWriteSeal(mode),
      });
      const f = build(storage, [point(1), point(2)]);
      const retryMemory = createDownloadRetryMemory();
      const recordFailure = vi.spyOn(retryMemory, "recordFailure");

      const results = await downloadAll(f.deps, { retryMemory });

      expect(results).toEqual([]);
      expect(storage.entries).toHaveLength(0);
      expect(recordFailure).not.toHaveBeenCalled();
      expect(f.cursorWrite).not.toHaveBeenCalled();
      // The seal said no before the blob was fetched: no wasted download.
      expect(f.download).not.toHaveBeenCalled();
      expect(f.logger.error).not.toHaveBeenCalled();
    },
  );

  // DOWNLOAD_REFUSAL_COUNTED_AS_FAILURE
  it("stops at the first refused write when the account switches after the early check", async () => {
    // The early verdict said allow (the record fetch is under way); On lands
    // while the blob is being decrypted; the write is then refused.
    const { authority, seal } = await sealFor("off");
    const storage = createMemoryDataStorage({ legacyWriteSeal: seal });
    const f = build(storage, [point(1), point(2)]);
    const decrypting = gate();
    (decryptWithPassword as ReturnType<typeof vi.fn>).mockImplementation(
      async () => {
        await decrypting.opened;
        return new TextEncoder().encode(JSON.stringify(envelopeFor(1)));
      },
    );
    const retryMemory = createDownloadRetryMemory();
    const recordFailure = vi.spyOn(retryMemory, "recordFailure");

    const running = downloadAll(f.deps, { retryMemory });
    await vi.waitFor(() => expect(f.download).toHaveBeenCalledTimes(1));
    await authority.submitEvidence({
      owner: OWNER,
      state: "on",
    });
    decrypting.open();

    expect(await running).toEqual([]);
    // Nothing was kept: no file, no row. The second record is not attempted.
    expect(storage.entries).toHaveLength(0);
    expect(f.download).toHaveBeenCalledTimes(1);
    expect(recordFailure).not.toHaveBeenCalled();
    expect(f.cursorWrite).not.toHaveBeenCalled();
    expect(f.logger.error).not.toHaveBeenCalled();
  });

  it("downloads for an unswitched account and advances the cursor", async () => {
    const { seal } = await sealFor("off");
    const storage = createMemoryDataStorage({ legacyWriteSeal: seal });
    const f = build(storage, [point(1)]);
    const results = await downloadAll(f.deps);
    expect(results).toHaveLength(1);
    expect(storage.entries).toHaveLength(1);
    expect(f.cursorWrite).toHaveBeenCalledWith("next");
  });

  it("lets a write in flight when On is submitted land before On is answered", async () => {
    const { authority, seal } = await sealFor("off");
    const writing = gate();
    let reached = false;
    const storage = createMemoryDataStorage({
      legacyWriteSeal: seal,
      insideSealed: async () => {
        reached = true;
        await writing.opened;
      },
    });
    const f = build(storage, [point(1)]);
    const running = downloadAll(f.deps);
    await vi.waitFor(() => expect(reached).toBe(true));

    let rowsWhenAnswered = -1;
    const on = authority
      .submitEvidence({
        owner: OWNER,
        state: "on",
      })
      .then((decision) => {
        rowsWhenAnswered = storage.entries.length;
        return decision;
      });
    await tick();
    await tick();
    expect(rowsWhenAnswered).toBe(-1);
    writing.open();
    await running;
    expect((await on).kind).toBe("streams");
    // The write that started first is on disk by the time On is answered.
    expect(rowsWhenAnswered).toBe(1);
  });
});

describe("downloadScopes when legacy storage is closed", () => {
  it("hands the refusal to the caller instead of quarantining the record", async () => {
    const seal: LegacyWriteSeal = fixedLegacyWriteSeal("switched");
    const storage = createMemoryDataStorage({ legacyWriteSeal: seal });
    const f = build(storage, [point(1)]);
    // The early verdict is bypassed, as when the account switches mid-fetch.
    const racing: LegacyWriteSeal = { ...seal, verdict: () => "allow" };
    const racingStorage = createMemoryDataStorage({ legacyWriteSeal: racing });
    const g = build(racingStorage, [point(1)]);
    const retryMemory = createDownloadRetryMemory();
    const recordFailure = vi.spyOn(retryMemory, "recordFailure");

    await expect(
      downloadScopes(g.deps, ["notes.entries1"], { retryMemory }),
    ).rejects.toBeInstanceOf(LegacyWriteRefusedError);
    expect(recordFailure).not.toHaveBeenCalled();
    expect(racingStorage.entries).toHaveLength(0);

    // With the early verdict honest, the fetch is skipped too.
    await expect(
      downloadScopes(f.deps, ["notes.entries1"], { retryMemory }),
    ).rejects.toBeInstanceOf(LegacyWriteRefusedError);
    expect(f.download).not.toHaveBeenCalled();
  });
});
