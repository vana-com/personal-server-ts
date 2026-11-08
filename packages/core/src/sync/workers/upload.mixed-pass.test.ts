import { describe, it, expect, vi, beforeEach } from "vitest";

import type { UploadWorkerDeps } from "./upload.js";
import { uploadAll } from "./upload.js";
import {
  createUploadStateTracker,
  estimateUploadBodyBytes,
  MAX_UPLOAD_BODY_BYTES,
} from "../upload-state.js";
import type { IndexEntry } from "../../storage/index/types.js";
import type { StorageAdapter } from "../../storage/adapters/interface.js";
import type {
  DataFileEnvelope,
  GatewayClient,
  Schema,
} from "@opendatalabs/vana-sdk/browser";
import type { ServerSigner } from "../../signing/signer.js";
import type { Logger } from "../../logger/index.js";
import type { DataStoragePort } from "../../ports/index.js";

vi.mock("@opendatalabs/vana-sdk/browser", () => ({
  deriveScopeKey: vi.fn(),
  encryptWithPassword: vi.fn(),
}));

import {
  deriveScopeKey,
  encryptWithPassword,
} from "@opendatalabs/vana-sdk/browser";

const OWNER = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12";
const SCHEMA_ID =
  "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
const T0 = Date.parse("2026-11-07T12:00:00Z");
const SECOND = 1000;
const MIB = 1024 * 1024;
const COLLECTED_AT = "2026-11-07T10:00:00Z";

/** Each scope is ordinary and distinct, so none is coalesced with another. */
const SCOPES = {
  huge: "mixed.huge",
  fail: "mixed.fail",
  ok1: "mixed.ok1",
  ok2: "mixed.ok2",
  ok3: "mixed.ok3",
} as const;

function row(id: number, scope: string, sizeBytes: number): IndexEntry {
  return {
    id,
    fileId: null,
    schemaId: null,
    path: `${scope}/${COLLECTED_AT}.json`,
    scope,
    collectedAt: COLLECTED_AT,
    createdAt: COLLECTED_AT,
    sizeBytes,
    version: 1,
    dataPointId: null,
  };
}

/** Ordered fake store plus fakes that record every call in one event log. */
function makeHarness(rows: IndexEntry[]) {
  const store = [...rows];
  const events: string[] = [];
  const failing = new Set<string>([SCOPES.fail]);

  const storage: Partial<DataStoragePort> = {
    findUnsynced: vi.fn(() => store.filter((e) => e.dataPointId === null)),
    readEnvelope: vi.fn(async (scope: string) => {
      events.push(`read:${scope}`);
      return {
        version: "1.0",
        scope,
        collectedAt: COLLECTED_AT,
        data: { username: "testuser" },
      } as DataFileEnvelope;
    }),
    updateEntryVersion: vi.fn().mockReturnValue(true),
    updateDataPointId: vi.fn((path: string, id: string) => {
      const found = store.find((e) => e.path === path);
      if (found) found.dataPointId = id;
      events.push(`synced:${found?.scope}`);
      return true;
    }),
  };

  const storageAdapter: Partial<StorageAdapter> = {
    upload: vi.fn(async (key: string) => {
      const scope = key.split("/")[0];
      events.push(`put:${scope}`);
      if (failing.has(scope)) {
        await Promise.resolve();
        events.push(`reject:${scope}`);
        throw new Error("Failed to fetch");
      }
      return `https://storage.example/v1/blobs/${OWNER}/${key}`;
    }),
    urlForKey: vi.fn((key: string) => `https://storage.example/${key}`),
    exists: vi.fn().mockResolvedValue(true),
  };

  const gateway: Partial<GatewayClient> = {
    getSchemaForScope: vi.fn().mockResolvedValue({
      id: SCHEMA_ID,
      ownerAddress: OWNER,
      name: "mixed",
      definitionUrl: "https://schemas.example/mixed.json",
      scope: "mixed",
      addedAt: "2026-01-01T00:00:00Z",
    } satisfies Schema),
    getDataPoint: vi.fn().mockResolvedValue(null),
    registerDataPoint: vi.fn(async () => {
      events.push("register");
      return { dataPointId: `0x${"ab".repeat(32)}`, expectedVersion: "1" };
    }),
  };

  const signer: Partial<ServerSigner> = {
    signAddData: vi.fn().mockResolvedValue("0xadddatasignature"),
    signLineageAttestation: vi.fn().mockResolvedValue("0xlineagesignature"),
  };

  const logger: Partial<Logger> = {
    info: vi.fn(),
    error: vi.fn(),
    warn: vi.fn(),
    debug: vi.fn(),
  };

  const uploadState = createUploadStateTracker();
  const deps: UploadWorkerDeps = {
    storage: storage as DataStoragePort,
    storageAdapter: storageAdapter as StorageAdapter,
    gateway: gateway as GatewayClient,
    signer: signer as ServerSigner,
    masterKey: new Uint8Array(65).fill(0xaa),
    serverOwner: OWNER,
    logger: logger as Logger,
    uploadState,
  };

  const pass = (offsetMs: number) =>
    uploadAll(deps, { now: () => new Date(T0 + offsetMs) });
  const eventsFor = (scope: string) => events.filter((e) => e.endsWith(scope));

  return { deps, store, events, uploadState, pass, eventsFor };
}

describe("uploadAll — one pass over oversize, failing and healthy entries", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (deriveScopeKey as ReturnType<typeof vi.fn>).mockReturnValue(
      new Uint8Array(32).fill(0xbb),
    );
    (encryptWithPassword as ReturnType<typeof vi.fn>).mockResolvedValue(
      new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
    );
  });

  // 319 MiB of stored metadata; no payload of that size is ever allocated.
  const HUGE_BYTES = 319 * MIB;

  it("sits H above the cap by its estimate, and F, S1, S2 far below it", () => {
    expect(MAX_UPLOAD_BODY_BYTES).toBe(95_000_000);
    expect(estimateUploadBodyBytes(HUGE_BYTES)).toBe(
      Math.ceil(HUGE_BYTES * 1.02) + 65_536,
    );
    expect(estimateUploadBodyBytes(HUGE_BYTES)).toBeGreaterThan(
      MAX_UPLOAD_BODY_BYTES,
    );
    expect(estimateUploadBodyBytes(256)).toBeLessThan(MAX_UPLOAD_BODY_BYTES);
  });

  it("skips the oversize entry without reading it, attempts the others in order, and syncs the healthy ones in the same pass", async () => {
    const h = makeHarness([
      row(1, SCOPES.huge, HUGE_BYTES),
      row(2, SCOPES.fail, 256),
      row(3, SCOPES.ok1, 256),
      row(4, SCOPES.ok2, 256),
    ]);

    const results = await h.pass(0);

    // H: metadata only. No read, key derivation, encryption, PUT or registration.
    expect(h.eventsFor(SCOPES.huge)).toEqual([]);
    const derivedFor = (deriveScopeKey as ReturnType<typeof vi.fn>).mock.calls;
    expect(derivedFor.map((c) => c[1])).toContain(SCOPES.ok1);
    expect(derivedFor.map((c) => c[1])).not.toContain(SCOPES.huge);
    expect(h.deps.gateway.registerDataPoint).toHaveBeenCalledTimes(2);
    expect(h.uploadState.snapshot().tooLarge).toEqual([
      expect.objectContaining({ scope: SCOPES.huge, sizeBytes: HUGE_BYTES }),
    ]);
    expect(
      h.store.find((e) => e.scope === SCOPES.huge)?.dataPointId,
    ).toBeNull();

    // Attempts run F, S1, S2, and S1 starts only after F's rejection.
    expect(h.events.filter((e) => e.startsWith("put:"))).toEqual([
      `put:${SCOPES.fail}`,
      `put:${SCOPES.ok1}`,
      `put:${SCOPES.ok2}`,
    ]);
    expect(h.events.indexOf(`reject:${SCOPES.fail}`)).toBeLessThan(
      h.events.indexOf(`put:${SCOPES.ok1}`),
    );

    // S1 and S2 are synced by the time this call resolves.
    expect(results.map((r) => r.path)).toEqual([
      row(3, SCOPES.ok1, 256).path,
      row(4, SCOPES.ok2, 256).path,
    ]);
    expect(h.eventsFor(SCOPES.ok1)).toContain(`synced:${SCOPES.ok1}`);
    expect(h.eventsFor(SCOPES.ok2)).toContain(`synced:${SCOPES.ok2}`);

    // F alone is backing off; the failure did not touch S1, S2 or H.
    expect(h.uploadState.snapshot().retrying).toEqual([
      expect.objectContaining({
        scope: SCOPES.fail,
        failures: 1,
        nextAttemptAt: new Date(T0 + 60 * SECOND).toISOString(),
      }),
    ]);
    expect(h.uploadState.snapshot().stopped).toEqual([]);
    expect(h.eventsFor(SCOPES.fail)).not.toContain(`synced:${SCOPES.fail}`);
  });

  it("skips F inside its backoff while a new entry uploads, then runs only F's due retry", async () => {
    const h = makeHarness([
      row(1, SCOPES.huge, HUGE_BYTES),
      row(2, SCOPES.fail, 256),
      row(3, SCOPES.ok1, 256),
      row(4, SCOPES.ok2, 256),
    ]);
    await h.pass(0);
    h.events.length = 0;

    // +30 s: S3 arrives. F is still backing off and is skipped.
    h.store.push(row(5, SCOPES.ok3, 256));
    const early = await h.pass(30 * SECOND);

    expect(early.map((r) => r.path)).toEqual([row(5, SCOPES.ok3, 256).path]);
    expect(h.events.filter((e) => e.startsWith("put:"))).toEqual([
      `put:${SCOPES.ok3}`,
    ]);
    expect(h.eventsFor(SCOPES.huge)).toEqual([]);

    // +60 s: F is due. Only F is attempted; it fails again with a longer wait.
    h.events.length = 0;
    const due = await h.pass(60 * SECOND);

    expect(due).toEqual([]);
    expect(h.events.filter((e) => e.startsWith("put:"))).toEqual([
      `put:${SCOPES.fail}`,
    ]);
    expect(h.eventsFor(SCOPES.huge)).toEqual([]);
    expect(h.uploadState.snapshot().retrying).toEqual([
      expect.objectContaining({
        scope: SCOPES.fail,
        failures: 2,
        nextAttemptAt: new Date(T0 + 60 * SECOND + 120 * SECOND).toISOString(),
      }),
    ]);
    expect(h.uploadState.snapshot().tooLarge).toHaveLength(1);
  });
});
