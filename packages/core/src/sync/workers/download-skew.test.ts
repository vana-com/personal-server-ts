import { beforeEach, describe, expect, it, vi } from "vitest";
import type {
  DataFileEnvelope,
  DataPointRecord,
  GatewayClient,
} from "@opendatalabs/vana-sdk/browser";
import type { DataStoragePort } from "../../ports/index.js";
import type { IndexEntry } from "../../storage/index/types.js";
import type { StorageAdapter } from "../../storage/adapters/interface.js";
import type { Logger } from "../../logger/index.js";
import type { SyncCursor } from "../cursor.js";
import { downloadAll, type DownloadWorkerDeps } from "./download.js";
import { createDownloadRetryMemory } from "../retry-memory.js";

vi.mock("@opendatalabs/vana-sdk/browser", async (importOriginal) => ({
  ...(await importOriginal()),
  deriveScopeKey: vi.fn(),
  decryptWithPassword: vi.fn(),
}));

import {
  decryptWithPassword,
  deriveScopeKey,
} from "@opendatalabs/vana-sdk/browser";

const OWNER = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12";
const COLLECTED_AT = "2026-11-08T10:00:00.000Z";
const PAGE_END = "after-mixed-page";
const LATER_END = "after-later-legacy";
// DESIGN-V4.1 physical/control grammar; independently checked against
// stream-sync/names.ts at 80087a4d. Main under test remains f102ce9f.
const PHYSICAL_SCOPE = "pdpp.oura~0123456789abcdef.sleep";
const CONTROL_SCOPE = "pdpp.oura~0123456789abcdef";

function row(scope: string, id: number): DataPointRecord {
  return {
    id: `0x${id.toString(16).padStart(64, "0")}`,
    ownerAddress: OWNER,
    scope,
    dataHash: "0x" + "11".repeat(32),
    metadataHash: "0x" + "22".repeat(32),
    expectedVersion: "1",
    addedAt: COLLECTED_AT,
  };
}

type SkewCase = {
  name: string;
  scope: string;
  plaintext?: string;
  decryptError?: string;
  missing?: boolean;
  deleted?: boolean;
};

const cases: SkewCase[] = [
  {
    name: "physical head whose decrypted JSON is not a DataFileEnvelope",
    scope: PHYSICAL_SCOPE,
    plaintext: JSON.stringify({ kind: "head", parts: ["part-1"] }),
  },
  {
    name: "physical part whose decrypted bytes are not JSON",
    scope: PHYSICAL_SCOPE,
    plaintext: "stream-part\u0000\u0001",
  },
  {
    name: "physical blob encrypted under a different key",
    scope: PHYSICAL_SCOPE,
    decryptError: "Session key decryption failed.",
  },
  {
    name: "metadata-only live control row whose legacy blob lookup returns 404",
    scope: CONTROL_SCOPE,
    // The stream writer registers control metadata without uploading a blob.
    // A 404 here is the storage-double fixture, not a live endpoint observation.
    missing: true,
  },
  {
    name: "live control row with a non-envelope blob",
    scope: CONTROL_SCOPE,
    // Adverse readable-blob fixture, not a claim about the wire control body.
    plaintext: JSON.stringify({ kind: "control", generation: 1 }),
  },
  {
    name: "tombstoned control-scope row",
    scope: CONTROL_SCOPE,
    deleted: true,
  },
  {
    name: "physical row whose version-keyed blob returns 404",
    scope: PHYSICAL_SCOPE,
    missing: true,
  },
];

async function runMixedPage(special: SkewCase, sessionMemory: boolean) {
  const before = row("pdpp.oura.sleep", 1);
  const after = row("github.repositories", 2);
  const later = row("pdpp.oura.activity", 3);
  const stream = {
    ...row(special.scope, 4),
    ...(special.deleted ? { deletedAt: COLLECTED_AT } : {}),
  };
  const envelopes = new Map<string, DataFileEnvelope>();
  const entries = new Map<string, IndexEntry>();
  const plaintextByMarker = new Map<number, string>();
  const markerByUrl = new Map<string, number>();
  const urlFor = (record: DataPointRecord) =>
    `https://storage.vana.com/v1/blobs/${OWNER}/${record.scope}/${record.expectedVersion}`;
  for (const [index, record] of [before, after, later].entries()) {
    markerByUrl.set(urlFor(record), index + 1);
    plaintextByMarker.set(
      index + 1,
      JSON.stringify({
        version: "1.0",
        scope: record.scope,
        collectedAt: COLLECTED_AT,
        data: { legacy: record.scope },
      }),
    );
  }
  markerByUrl.set(urlFor(stream), 4);

  let cursorValue: string | null = null;
  const cursor: SyncCursor = {
    read: vi.fn(async () => cursorValue),
    write: vi.fn(async (value) => {
      cursorValue = value;
    }),
  };
  const storage: Partial<DataStoragePort> = {
    findByDataPointId: vi.fn((id: string) => entries.get(id)),
    findEntry: vi.fn(({ scope, at }) =>
      [...entries.values()].find(
        (entry) =>
          entry.scope === scope &&
          (at === undefined || entry.collectedAt === at),
      ),
    ),
    writeEnvelope: vi.fn(async (envelope: DataFileEnvelope) => {
      envelopes.set(envelope.scope, envelope);
      return {
        path: `/tmp/data/${envelope.scope}/${envelope.collectedAt}.json`,
        relativePath: `${envelope.scope}/${envelope.collectedAt}.json`,
        sizeBytes: 128,
      };
    }),
    insertEntry: vi.fn((entry) => {
      const stored = {
        id: entries.size + 1,
        createdAt: COLLECTED_AT,
        ...entry,
      } as IndexEntry;
      entries.set(stored.dataPointId!, stored);
      return stored;
    }),
    updateDataPointId: vi.fn(async () => true),
    listVersions: vi.fn(() => []),
    deleteVersion: vi.fn(async () => true),
  };
  const adapter: Partial<StorageAdapter> = {
    urlForKey: vi.fn(
      (key: string) => `https://storage.vana.com/v1/blobs/${OWNER}/${key}`,
    ),
    download: vi.fn(async (url: string) => {
      const marker = markerByUrl.get(url);
      if (marker === undefined)
        throw new Error(`Unexpected fixture URL: ${url}`);
      if (marker === 4 && special.missing) {
        throw Object.assign(
          new Error("vana-storage download failed: 404 Not Found"),
          {
            name: "StorageError",
          },
        );
      }
      // Independent bytes each time: downloadOne clears its ciphertext buffer.
      return new Uint8Array([0xc3, marker]);
    }),
  };
  vi.mocked(decryptWithPassword).mockImplementation(async (ciphertext) => {
    const marker = ciphertext[1];
    if (marker === 4 && special.decryptError)
      throw new Error(special.decryptError);
    const plaintext =
      marker === 4 ? special.plaintext : plaintextByMarker.get(marker!);
    if (plaintext === undefined) throw new Error("Unexpected fixture decrypt");
    return new TextEncoder().encode(plaintext);
  });
  const listing = vi.fn(async (_owner: string, cursor: string | null) => {
    if (cursor === null)
      return { dataPoints: [before, stream, after], cursor: PAGE_END };
    if (cursor === PAGE_END) return { dataPoints: [later], cursor: LATER_END };
    if (cursor === LATER_END) return { dataPoints: [], cursor: null };
    throw new Error(`Unexpected fixture cursor: ${cursor}`);
  });
  const logger = {
    info: vi.fn(),
    error: vi.fn(),
    warn: vi.fn(),
    debug: vi.fn(),
  };
  const deps: DownloadWorkerDeps = {
    storage: storage as DataStoragePort,
    storageAdapter: adapter as StorageAdapter,
    gateway: { listDataPointsByOwner: listing } as unknown as GatewayClient,
    cursor,
    masterKey: new Uint8Array(65).fill(0xaa),
    serverOwner: OWNER,
    logger: logger as unknown as Logger,
  };

  // Match sync-manager: one retry memory per boot, not one per cycle.
  let nowMs = 0;
  const retryMemory = sessionMemory
    ? createDownloadRetryMemory({ now: () => nowMs })
    : undefined;
  const cycle = () => downloadAll(deps, { retryMemory });
  const first = await cycle();
  const firstCursor = cursorValue;
  const firstStored = [...envelopes.keys()];
  const specialAttemptsAfterFirst = vi
    .mocked(adapter.download!)
    .mock.calls.filter(([url]) => url === urlFor(stream)).length;
  nowMs += 60_000;
  await cycle();
  nowMs += 60_000;
  await cycle();

  return {
    before,
    after,
    later,
    stream,
    first,
    firstCursor,
    firstStored,
    cursorValue,
    envelopes,
    entries,
    listing,
    cursor,
    storage,
    adapter,
    logger,
    specialAttemptsAfterFirst,
    specialAttempts: vi
      .mocked(adapter.download!)
      .mock.calls.filter(([url]) => url === urlFor(stream)).length,
  };
}

describe("skew gate R: legacy download with stream-sync rows on the same page", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.mocked(deriveScopeKey).mockReturnValue(new Uint8Array(32).fill(0xbb));
  });

  // All 14 pass on main f102ce9f, so each is a plain test that guards the
  // legacy path. Mutants killed (see download.ts classify and tombstone paths):
  // - json_parse/envelope_validate withhold cursor: cases 1, 2, 5
  // - decrypt/openpgp_parse withhold cursor: case 3
  // - 404 loses its download stage stamp: cases 4, 7
  // - tombstoned row is downloaded: case 6
  for (const special of cases) {
    for (const sessionMemory of [false, true]) {
      it(`${special.name}; session memory=${sessionMemory}`, async () => {
        const result = await runMixedPage(special, sessionMemory);
        expect
          .soft(result.firstStored)
          .toEqual([result.before.scope, result.after.scope]);
        expect
          .soft(result.first.map((entry) => entry.dataPointId))
          .toEqual([result.before.id, result.after.id]);
        expect.soft(result.firstCursor).toBe(PAGE_END);
        if (special.deleted) {
          expect.soft(result.specialAttemptsAfterFirst).toBe(0);
        }
        expect.soft(result.entries.has(result.stream.id)).toBe(false);
        expect.soft(result.envelopes.has(result.stream.scope)).toBe(false);
        expect.soft(result.cursorValue).toBe(LATER_END);
        expect.soft(result.envelopes.has(result.later.scope)).toBe(true);
        expect
          .soft(result.specialAttempts)
          .toBe(result.specialAttemptsAfterFirst);
        expect
          .soft(result.listing.mock.calls.map(([, cursor]) => cursor))
          .toEqual([null, PAGE_END, LATER_END]);
      });
    }
  }
});
