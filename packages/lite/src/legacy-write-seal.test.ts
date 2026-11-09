/**
 * The legacy-write seal in persistent Lite storage. Every test here uses
 * `createPersistentPsLiteStorage` over a persistence adapter and a file store
 * (not the memory test double), and reloads from the adapter to see what was
 * really made durable.
 */

import { describe, expect, it } from "vitest";
import { createDataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import {
  createAccountStorageMode,
  LegacyWriteRefusedError,
} from "@opendatalabs/personal-server-ts-core/api";
import {
  createMemoryPsLiteAccessLogStore,
  createMemoryPsLiteDataFileStore,
  createMemoryPsLitePersistence,
  createMemoryPsLiteTokenStore,
} from "./test-support/memory.js";
import { createPersistentPsLiteStorage } from "./storage.js";
import type { PsLiteDataFileStore } from "./storage.js";
import {
  createBearerTokenPsLiteAuth,
  createPsLiteRuntime,
  importOuraBrowserRecords,
  type OuraBrowserImportInput,
} from "./index.js";

const owner = "0x1111111111111111111111111111111111111111" as const;
const auth = { authorization: "Bearer owner" };
const scope = "instagram.profile";

/** A file store whose envelope writes can be parked, recording each path. */
function gatedFiles() {
  const base = createMemoryPsLiteDataFileStore("custom");
  const written: string[] = [];
  const state: { gate: Promise<void> | null } = { gate: null };
  const files: PsLiteDataFileStore = {
    ...base,
    async writeEnvelope(path, envelope) {
      written.push(path);
      if (state.gate) await state.gate;
      return base.writeEnvelope(path, envelope);
    },
  };
  return { files, written, state };
}

async function setup(modeState: { switched: boolean }) {
  const persistence = createMemoryPsLitePersistence();
  const { files, written, state } = gatedFiles();
  const storage = await createPersistentPsLiteStorage(
    { kind: "custom" },
    persistence,
    files,
  );
  const mode = createAccountStorageMode({
    owner,
    source: () => modeState.switched,
  });
  const accessLogs = createMemoryPsLiteAccessLogStore();
  const runtime = createPsLiteRuntime({
    storage,
    active: true,
    accountStorageMode: mode,
    serverOwner: owner,
    accessLogReader: accessLogs,
    accessLogWriter: accessLogs,
    tokenStore: createMemoryPsLiteTokenStore(),
    saveConfig: async () => {},
    auth: createBearerTokenPsLiteAuth({
      ownerToken: "owner",
      builderToken: "builder",
    }),
  });
  const reload = () =>
    createPersistentPsLiteStorage({ kind: "custom" }, persistence, files);
  return { storage, runtime, files, written, state, reload, mode };
}

const post = (runtime: { fetch(r: Request): Promise<Response> }) =>
  runtime.fetch(
    new Request(`https://ps.test/v1/data/${scope}`, {
      method: "POST",
      headers: { ...auth, "content-type": "application/json" },
      body: JSON.stringify({ username: "lite_user" }),
    }),
  );

describe("persistent Lite storage seals the index install", () => {
  // LITE_INDEX_AFTER_FENCE: the route fence already passed; the account
  // switches while the blob is being written, before the index row installs.
  it("refuses a write whose switch lands between the route fence and the index install", async () => {
    const modeState = { switched: false };
    const { runtime, written, state, files, reload } = await setup(modeState);
    let release!: () => void;
    state.gate = new Promise<void>((resolve) => (release = resolve));
    const responding = post(runtime);
    // Wait until the write reached the file store: the fence has passed.
    while (written.length === 0) await new Promise((r) => setTimeout(r, 1));
    modeState.switched = true;
    release();
    const response = await responding;
    expect(response.status).toBe(426);
    expect((await response.json()).errorCode).toBe("update_required");
    // Nothing visible after a restart, and the blob is gone.
    const reloaded = await reload();
    expect(reloaded.countVersions(scope)).toBe(0);
    expect(reloaded.findEntry({ scope })).toBeUndefined();
    for (const path of written)
      expect(await files.readEnvelope(path)).toBeNull();
  });

  it("stores the same write when the account stays unswitched", async () => {
    const { runtime, reload } = await setup({ switched: false });
    expect((await post(runtime)).status).toBe(201);
    expect((await reload()).countVersions(scope)).toBe(1);
  });

  // SEAL_BYPASSED (Lite): a direct storage-level commit on a switched owner.
  it("refuses a direct storage commit on a switched owner and leaves nothing", async () => {
    const modeState = { switched: true };
    const { storage, written, files, reload } = await setup(modeState);
    const envelope = createDataFileEnvelope(scope, "2026-11-09T00:00:00.000Z", {
      username: "direct",
    });
    await expect(
      storage.writeEnvelopeAndIndex!(envelope, {
        fileId: null,
        scope,
        collectedAt: envelope.collectedAt,
      }),
    ).rejects.toBeInstanceOf(LegacyWriteRefusedError);
    await expect(
      storage.insertEntry({
        fileId: null,
        scope,
        collectedAt: envelope.collectedAt,
        path: "x/y.json",
        sizeBytes: 1,
      }),
    ).rejects.toBeInstanceOf(LegacyWriteRefusedError);
    await expect(storage.writeEnvelope(envelope)).rejects.toBeInstanceOf(
      LegacyWriteRefusedError,
    );
    const reloaded = await reload();
    expect(reloaded.countVersions(scope)).toBe(0);
    for (const path of written)
      expect(await files.readEnvelope(path)).toBeNull();
  });

  it("refuses everything while no mode is bound (unwired is unknown)", async () => {
    const storage = await createPersistentPsLiteStorage(
      { kind: "custom" },
      createMemoryPsLitePersistence(),
      createMemoryPsLiteDataFileStore("custom"),
    );
    const envelope = createDataFileEnvelope(scope, "2026-11-09T00:00:00.000Z", {
      username: "unbound",
    });
    try {
      await storage.writeEnvelopeAndIndex!(envelope, {
        fileId: null,
        scope,
        collectedAt: envelope.collectedAt,
      });
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(LegacyWriteRefusedError);
      expect((error as LegacyWriteRefusedError).verdict).toBe("unknown");
      expect((error as LegacyWriteRefusedError).response.status).toBe(503);
    }
    expect(storage.countVersions(scope)).toBe(0);
  });

  it("still lets a switched account erase legacy data", async () => {
    const modeState = { switched: false };
    const { runtime, storage } = await setup(modeState);
    expect((await post(runtime)).status).toBe(201);
    modeState.switched = true;
    await storage.deleteScope(scope);
    expect(storage.countVersions(scope)).toBe(0);
  });

  it("waits for a commit that started before the switch (drain)", async () => {
    const modeState = { switched: false };
    const { storage, written, state } = await setup(modeState);
    let release!: () => void;
    state.gate = new Promise<void>((resolve) => (release = resolve));
    const envelope = createDataFileEnvelope(scope, "2026-11-09T00:00:00.000Z", {
      username: "drain",
    });
    const writing = storage.writeEnvelopeAndIndex!(envelope, {
      fileId: null,
      scope,
      collectedAt: envelope.collectedAt,
    });
    while (written.length === 0) await new Promise((r) => setTimeout(r, 1));
    // The blob is parked, so the row has not been asked about yet. Let it
    // through to the index install, which is the tracked commit.
    release();
    await writing;
    modeState.switched = true;
    await expect(storage.legacyWriteSeal.drain()).resolves.toBeUndefined();
    expect(storage.countVersions(scope)).toBe(1);
  });
});

// OURA_SWITCH_MID_BATCH
describe("an Oura batch that straddles the switch", () => {
  const streams = ["sleep", "readiness", "activity"] as const;
  const input = (): OuraBrowserImportInput =>
    ({
      selection: { streams: streams.map((name) => ({ name })) },
      collectedAt: "2026-10-15T00:00:00.000Z",
      records: streams.map((stream) => ({
        stream,
        data: {
          id: `${stream}-1`,
          day: "2026-10-13",
          score: 80,
          ...(stream === "sleep"
            ? { record_type: "daily_score", sleep_score: 80 }
            : {}),
        },
      })),
      completion: {
        streams: streams.map((name) => ({
          stream: name,
          status: "complete",
          recordCount: 1,
        })),
      },
    }) as unknown as OuraBrowserImportInput;

  it("keeps no stream written after the switch, and says so by refusing", async () => {
    const modeState = { switched: false };
    const persistence = createMemoryPsLitePersistence();
    const files = createMemoryPsLiteDataFileStore("custom");
    const storage = await createPersistentPsLiteStorage(
      { kind: "custom" },
      persistence,
      files,
    );
    const sealMode = createAccountStorageMode({
      owner,
      source: () => modeState.switched,
    });
    storage.legacyWriteSeal.bind({ mode: sealMode, owner });
    // The route-level checks see a stale unswitched account; only the storage
    // seal knows. The batch must still stop at the switch.
    const staleRouteMode = createAccountStorageMode({
      owner,
      source: () => false,
    });
    let installs = 0;
    const flipping = new Proxy(storage, {
      get(target, property, receiver) {
        const value = Reflect.get(target, property, receiver);
        if (
          typeof value === "function" &&
          (property === "writeEnvelopeAndIndex" ||
            property === "commitEnvelope")
        ) {
          return async (...args: unknown[]) => {
            const result = await (value as (...a: unknown[]) => unknown).apply(
              target,
              args,
            );
            if (++installs === 1) modeState.switched = true;
            return result;
          };
        }
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
    await expect(
      importOuraBrowserRecords(flipping, input(), {
        accountStorageMode: staleRouteMode,
      }),
    ).rejects.toBeInstanceOf(LegacyWriteRefusedError);
    // Not atomic: the stream committed before the switch stays, nothing after.
    const reloaded = await createPersistentPsLiteStorage(
      { kind: "custom" },
      persistence,
      files,
    );
    const stored = streams.filter(
      (stream) => reloaded.countVersions(`oura.${stream}`) > 0,
    );
    expect(stored).toHaveLength(1);
  });
});
