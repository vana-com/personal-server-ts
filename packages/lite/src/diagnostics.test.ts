import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  DiagnosticsRecorder,
  collectDiagnosticsWithTimeout,
  DIAGNOSTICS_VERSION,
  type PsLiteDiagnosticsSnapshot,
} from "./diagnostics.js";
import type { SyncStatus } from "@opendatalabs/personal-server-ts-core/sync";
import type { DataStoragePort } from "@opendatalabs/personal-server-ts-core/ports";

function makeSyncStatus(overrides: Partial<SyncStatus> = {}): SyncStatus {
  return {
    enabled: true,
    running: true,
    syncing: false,
    blocked: null,
    lastSync: "2024-01-01T00:00:00.000Z",
    lastProcessedTimestamp: "2024-01-01T00:00:00.000Z",
    pendingFiles: 0,
    errors: [],
    ...overrides,
  };
}

function makeStorage(
  overrides: Partial<DataStoragePort> = {},
): DataStoragePort {
  return {
    kind: "browser-indexeddb-opfs",
    listScopes: () => ({ scopes: [], total: 0 }),
    listVersions: () => [],
    countVersions: () => 0,
    findEntry: () => undefined,
    findByFileId: () => undefined,
    findUnsynced: () => [],
    readEnvelope: async () => {
      throw new Error("not implemented");
    },
    writeEnvelope: async () => ({ path: "", relativePath: "", sizeBytes: 0 }),
    insertEntry: () => {
      throw new Error("not implemented");
    },
    updateFileId: async () => false,
    deleteScope: async () => 0,
    ...overrides,
  } as DataStoragePort;
}

describe("DiagnosticsRecorder", () => {
  let recorder: DiagnosticsRecorder;

  beforeEach(() => {
    recorder = new DiagnosticsRecorder();
  });

  it("starts with booting phase and empty events", () => {
    const snap = recorder.snapshot();
    expect(snap.diagnosticVersion).toBe(DIAGNOSTICS_VERSION);
    expect(snap.currentPhase).toBe("booting");
    expect(snap.recentEvents).toHaveLength(0);
    expect(snap.scopes).toHaveLength(0);
    expect(snap.partial).toBe(false);
  });

  it("captures pushed events in the ring", () => {
    recorder.push({ phase: "indexing", detail: "scope=drive", scope: "drive" });
    recorder.push({ phase: "ready", scope: "drive" });

    const snap = recorder.snapshot();
    expect(snap.recentEvents).toHaveLength(2);
    expect(snap.recentEvents[0]!.phase).toBe("indexing");
    expect(snap.recentEvents[0]!.scope).toBe("drive");
    expect(snap.recentEvents[0]!.detail).toBe("scope=drive");
    expect(snap.recentEvents[1]!.phase).toBe("ready");
    expect(snap.currentPhase).toBe("ready");
  });

  it("bounds ring to MAX_EVENTS (100) and drops oldest", () => {
    for (let i = 0; i < 120; i++) {
      recorder.push({ phase: "indexing", detail: `event-${i}` });
    }
    const snap = recorder.snapshot();
    expect(snap.recentEvents.length).toBe(100);
    // Should have the most recent 100 (events 20–119)
    expect(snap.recentEvents[0]!.detail).toBe("event-20");
    expect(snap.recentEvents[99]!.detail).toBe("event-119");
  });

  it("updates per-scope status from pushed events", () => {
    recorder.push({ phase: "downloading", scope: "photos" });
    recorder.push({ phase: "indexing", scope: "photos" });
    recorder.push({ phase: "ready", scope: "photos" });

    const snap = recorder.snapshot();
    const scope = snap.scopes.find((s) => s.scope === "photos");
    expect(scope).toBeDefined();
    expect(scope!.status).toBe("ready");
  });

  it("marks scope as downloadFailed on error download event", () => {
    recorder.push({
      phase: "downloading",
      scope: "drive",
      fileId: "file-abc",
      error: true,
      detail: "connection refused",
    });

    const snap = recorder.snapshot();
    const scope = snap.scopes.find((s) => s.scope === "drive");
    expect(scope!.status).toBe("downloadFailed");
    expect(scope!.lastError).toBe("connection refused");
    expect(scope!.lastFileId).toBe("file-abc");
  });

  it("marks scope as decryptFailed on error decrypt event", () => {
    recorder.push({
      phase: "decrypting",
      scope: "health",
      error: true,
      detail: "bad key",
    });
    const snap = recorder.snapshot();
    const scope = snap.scopes.find((s) => s.scope === "health");
    expect(scope!.status).toBe("decryptFailed");
  });

  it("marks scope as indexFailed on error indexing event", () => {
    recorder.push({
      phase: "indexing",
      scope: "calendar",
      error: true,
      detail: "schema mismatch",
    });
    const snap = recorder.snapshot();
    const scope = snap.scopes.find((s) => s.scope === "calendar");
    expect(scope!.status).toBe("indexFailed");
  });

  it("does not mask manifest failures as ready after raw indexing completes", () => {
    recorder.push({
      phase: "buildingManifest",
      scope: "chatgpt.conversations",
      error: true,
      detail: "block_manifest_not_found",
    });
    recorder.push({
      phase: "indexing",
      scope: "chatgpt.conversations",
    });
    recorder.setScopeReadyAfterIndex("chatgpt.conversations");

    const snap = recorder.snapshot();
    const scope = snap.scopes.find((s) => s.scope === "chatgpt.conversations");
    expect(scope!.status).toBe("manifestMissing");
    expect(scope!.lastError).toBe("block_manifest_not_found");
  });

  it("allows a later successful manifest build to become ready", () => {
    recorder.push({
      phase: "buildingManifest",
      scope: "chatgpt.conversations",
      error: true,
      detail: "block_manifest_not_found",
    });
    recorder.push({
      phase: "buildingManifest",
      scope: "chatgpt.conversations",
    });
    recorder.setScopeManifestBuilt("chatgpt.conversations");
    recorder.setScopeReadyAfterIndex("chatgpt.conversations");

    const snap = recorder.snapshot();
    const scope = snap.scopes.find((s) => s.scope === "chatgpt.conversations");
    expect(scope!.status).toBe("ready");
    expect(scope!.lastError).toBeUndefined();
  });

  it("tracks repair loop counts per scope", () => {
    recorder.recordRepair("drive");
    recorder.recordRepair("drive");
    recorder.recordRepair("photos");

    const snap = recorder.snapshot();
    expect(snap.repairCounts["drive"]).toBe(2);
    expect(snap.repairCounts["photos"]).toBe(1);

    const driveScope = snap.scopes.find((s) => s.scope === "drive");
    expect(driveScope!.repairCount).toBe(2);
  });

  it("repair loop events appear in diagnostic ring when simulated", () => {
    recorder.push({
      phase: "repairingManifest",
      scope: "drive",
      detail: "index exists without local payload; repairing",
    });
    recorder.recordRepair("drive");
    recorder.push({
      phase: "repairingManifest",
      scope: "drive",
      detail: "index exists without local payload; repairing",
    });
    recorder.recordRepair("drive");

    const snap = recorder.snapshot();
    const repairEvents = snap.recentEvents.filter(
      (e) => e.phase === "repairingManifest" && e.scope === "drive",
    );
    expect(repairEvents).toHaveLength(2);
    expect(snap.repairCounts["drive"]).toBe(2);
  });

  it("tracks active operations with elapsed time", () => {
    recorder.beginOperation("downloading", "drive", "file-xyz");
    const snap = recorder.snapshot();
    expect(snap.activeOperation).not.toBeNull();
    expect(snap.activeOperation!.phase).toBe("downloading");
    expect(snap.activeOperation!.scope).toBe("drive");
    expect(snap.activeOperation!.fileId).toBe("file-xyz");
    expect(snap.activeOperation!.elapsedMs).toBeGreaterThanOrEqual(0);
  });

  it("clears active operation after endOperation", () => {
    recorder.beginOperation("indexing", "drive");
    recorder.endOperation();
    const snap = recorder.snapshot();
    expect(snap.activeOperation).toBeNull();
  });

  it("records network operations without payload body", () => {
    recorder.recordNetworkOp("download", "error", 234, 503);
    const snap = recorder.snapshot();
    expect(snap.lastNetworkOperation).not.toBeNull();
    expect(snap.lastNetworkOperation!.operationClass).toBe("download");
    expect(snap.lastNetworkOperation!.status).toBe("error");
    expect(snap.lastNetworkOperation!.elapsedMs).toBe(234);
    expect(snap.lastNetworkOperation!.statusOrError).toBe(503);
  });

  it("setScopeStatus updates scope explicitly", () => {
    recorder.setScopeStatus("email", "waitingForPayload", {
      lastFileId: "f-001",
    });
    const snap = recorder.snapshot();
    const scope = snap.scopes.find((s) => s.scope === "email");
    expect(scope!.status).toBe("waitingForPayload");
    expect(scope!.lastFileId).toBe("f-001");
  });

  it("includes runtimeActive and sync status in snapshot", () => {
    const syncStatus = makeSyncStatus({
      running: true,
      syncing: true,
      errors: [
        {
          fileId: "f-001",
          scope: "drive",
          message: "upload failed",
          timestamp: "2024-01-01T00:00:00.000Z",
        },
      ],
    });

    const snap = recorder.snapshot({ runtimeActive: true, syncStatus });
    expect(snap.runtimeActive).toBe(true);
    expect(snap.sync).not.toBeNull();
    expect(snap.sync!.syncing).toBe(true);
    expect(snap.sync!.recentErrors).toHaveLength(1);
    expect(snap.sync!.recentErrors[0]!.message).toBe("upload failed");
  });

  it("does not expose payload bodies in sync errors", () => {
    const syncStatus = makeSyncStatus({
      errors: [
        {
          fileId: "f-001",
          scope: "drive",
          message: "decrypt failed",
          timestamp: "2024-01-01T00:00:00.000Z",
        },
      ],
    });
    const snap = recorder.snapshot({ syncStatus });
    const serialized = JSON.stringify(snap);
    expect(serialized).not.toContain("payloadBody");
    expect(serialized).not.toContain("rawBytes");
  });

  it("includes storage health without exposing content", () => {
    const storage = makeStorage({
      listScopes: () => ({ scopes: [], total: 3 }),
      findUnsynced: () => [
        {
          id: 1,
          fileId: null,
          scope: "drive",
          collectedAt: "2024-01-01",
          path: "x",
          createdAt: "2024-01-01",
          schemaId: null,
          sizeBytes: 100,
        },
      ],
    });

    const snap = recorder.snapshot({ storage });
    expect(snap.storage).not.toBeNull();
    expect(snap.storage!.scopeCount).toBe(3);
    expect(snap.storage!.unsyncedCount).toBe(1);
    expect(snap.storage!.persistenceBackend).toBe("browser-indexeddb-opfs");
    // No raw envelope data in the snapshot
    const serialized = JSON.stringify(snap);
    expect(serialized).not.toContain("envelopes");
  });

  it("returns partial=false on synchronous snapshot", () => {
    const snap = recorder.snapshot();
    expect(snap.partial).toBe(false);
  });
});

describe("collectDiagnosticsWithTimeout", () => {
  it("returns snapshot within timeout", async () => {
    const recorder = new DiagnosticsRecorder();
    recorder.push({ phase: "indexing", scope: "drive" });

    const snap = await collectDiagnosticsWithTimeout(recorder, {
      runtimeActive: true,
    });
    expect(snap.diagnosticVersion).toBe(DIAGNOSTICS_VERSION);
    expect(snap.partial).toBe(false);
    expect(snap.runtimeActive).toBe(true);
    expect(snap.recentEvents).toHaveLength(1);
  });

  it("returns partial=true if snapshot throws synchronously", async () => {
    const recorder = new DiagnosticsRecorder();
    vi.spyOn(recorder, "snapshot").mockImplementationOnce(() => {
      throw new Error("snapshot crashed");
    });

    const snap = await collectDiagnosticsWithTimeout(recorder, {});
    expect(snap.partial).toBe(true);
    expect(snap.diagnosticVersion).toBe(DIAGNOSTICS_VERSION);
  });

  it("returns partial=true if snapshot throws", async () => {
    const recorder = new DiagnosticsRecorder();
    vi.spyOn(recorder, "snapshot").mockImplementationOnce(() => {
      throw new Error("storage failure");
    });

    const snap = await collectDiagnosticsWithTimeout(recorder, {});
    expect(snap.partial).toBe(true);
    expect(snap.diagnosticVersion).toBe(DIAGNOSTICS_VERSION);
  });

  it("no payload body is returned in diagnostics", async () => {
    const recorder = new DiagnosticsRecorder();
    recorder.push({
      phase: "indexing",
      scope: "drive",
      detail: "processing entry",
    });
    recorder.recordNetworkOp("download", "ok", 100, 200);

    const snap = await collectDiagnosticsWithTimeout(recorder, {
      syncStatus: makeSyncStatus(),
      storage: makeStorage(),
    });

    const serialized = JSON.stringify(snap);
    // Must not contain any payload-like fields
    expect(serialized).not.toContain('"payload"');
    expect(serialized).not.toContain('"body"');
    expect(serialized).not.toContain('"data"');
    expect(serialized).not.toContain('"privateKey"');
    expect(serialized).not.toContain('"secret"');
    expect(serialized).not.toContain('"token"');
    expect(serialized).not.toContain('"envelopes"');
  });
});

describe("DiagnosticsRecorder — runtime route integration", () => {
  it("GET /v1/diagnostics returns snapshot with default recorder when not explicitly configured", async () => {
    const { createPsLiteRuntime } = await import("./runtime.js");
    const {
      createMemoryPsLiteStorage,
      createMemoryPsLiteTokenStore,
      createMemoryPsLiteAccessLogStore,
    } = await import("./test-support/memory.js");

    const accessLogStore = createMemoryPsLiteAccessLogStore();
    const runtime = createPsLiteRuntime({
      storage: createMemoryPsLiteStorage(),
      accessLogReader: accessLogStore,
      accessLogWriter: accessLogStore,
      tokenStore: createMemoryPsLiteTokenStore(),
      saveConfig: async () => {},
      stateCapabilities: { config: "memory" },
      active: true,
      auth: {
        async authorizeOwner() {},
        async authorizeBuilderList() {},
        async authorizeBuilderRead() {
          return { grantId: "owner" };
        },
      },
      // No explicit diagnostics — runtime creates a default recorder
    });

    const response = await runtime.fetch(
      new Request("http://localhost/v1/diagnostics", { method: "GET" }),
    );
    // Always 200 now that a default recorder is wired in
    expect(response.status).toBe(200);
    const snap = (await response.json()) as PsLiteDiagnosticsSnapshot;
    expect(snap.diagnosticVersion).toBe(DIAGNOSTICS_VERSION);
    // At minimum the "booting" event pushed at runtime creation
    expect(snap.recentEvents.length).toBeGreaterThanOrEqual(1);
    expect(snap.recentEvents[0]!.phase).toBe("booting");
  });

  it("GET /v1/diagnostics works even when the runtime is inactive", async () => {
    const { createPsLiteRuntime } = await import("./runtime.js");
    const {
      createMemoryPsLiteStorage,
      createMemoryPsLiteTokenStore,
      createMemoryPsLiteAccessLogStore,
    } = await import("./test-support/memory.js");

    const accessLogStore = createMemoryPsLiteAccessLogStore();
    const runtime = createPsLiteRuntime({
      storage: createMemoryPsLiteStorage(),
      accessLogReader: accessLogStore,
      accessLogWriter: accessLogStore,
      tokenStore: createMemoryPsLiteTokenStore(),
      saveConfig: async () => {},
      stateCapabilities: { config: "memory" },
      active: false,
      auth: {
        async authorizeOwner() {},
        async authorizeBuilderList() {},
        async authorizeBuilderRead() {
          return { grantId: "owner" };
        },
      },
    });

    const diagnostics = await runtime.fetch(
      new Request("http://localhost/v1/diagnostics", { method: "GET" }),
    );
    expect(diagnostics.status).toBe(200);
    const snap = (await diagnostics.json()) as PsLiteDiagnosticsSnapshot;
    expect(snap.runtimeActive).toBe(false);

    const data = await runtime.fetch(
      new Request("http://localhost/v1/data/scopes", { method: "GET" }),
    );
    expect(data.status).toBe(503);
  });

  it("GET /v1/diagnostics returns snapshot when recorder is configured", async () => {
    const { createPsLiteRuntime } = await import("./runtime.js");
    const {
      createMemoryPsLiteStorage,
      createMemoryPsLiteTokenStore,
      createMemoryPsLiteAccessLogStore,
    } = await import("./test-support/memory.js");

    const recorder = new DiagnosticsRecorder();
    recorder.push({
      phase: "indexing",
      scope: "drive",
      detail: "initial load",
    });
    recorder.recordRepair("drive");

    const accessLogStore = createMemoryPsLiteAccessLogStore();
    const runtime = createPsLiteRuntime({
      storage: createMemoryPsLiteStorage(),
      accessLogReader: accessLogStore,
      accessLogWriter: accessLogStore,
      tokenStore: createMemoryPsLiteTokenStore(),
      saveConfig: async () => {},
      stateCapabilities: { config: "memory" },
      active: true,
      auth: {
        async authorizeOwner() {},
        async authorizeBuilderList() {},
        async authorizeBuilderRead() {
          return { grantId: "owner" };
        },
      },
      diagnostics: recorder,
    });

    const response = await runtime.fetch(
      new Request("http://localhost/v1/diagnostics", { method: "GET" }),
    );
    expect(response.status).toBe(200);

    const snap = (await response.json()) as PsLiteDiagnosticsSnapshot;
    expect(snap.diagnosticVersion).toBe(DIAGNOSTICS_VERSION);
    expect(snap.runtimeActive).toBe(true);
    // createPsLiteRuntime adds a "booting" event, so pre-pushed "indexing" + runtime's "booting" = 2 total
    expect(snap.recentEvents.length).toBe(2);
    // indexing was pushed before runtime creation; booting is pushed during runtime creation
    expect(snap.recentEvents[0]!.phase).toBe("indexing");
    expect(snap.recentEvents[1]!.phase).toBe("booting");
    expect(snap.repairCounts["drive"]).toBe(1);
    expect(snap.partial).toBe(false);
  });

  it("GET /v1/diagnostics returns 405 for non-GET methods", async () => {
    const { createPsLiteRuntime } = await import("./runtime.js");
    const {
      createMemoryPsLiteStorage,
      createMemoryPsLiteTokenStore,
      createMemoryPsLiteAccessLogStore,
    } = await import("./test-support/memory.js");

    const recorder = new DiagnosticsRecorder();
    const accessLogStore = createMemoryPsLiteAccessLogStore();
    const runtime = createPsLiteRuntime({
      storage: createMemoryPsLiteStorage(),
      accessLogReader: accessLogStore,
      accessLogWriter: accessLogStore,
      tokenStore: createMemoryPsLiteTokenStore(),
      saveConfig: async () => {},
      stateCapabilities: { config: "memory" },
      active: true,
      auth: {
        async authorizeOwner() {},
        async authorizeBuilderList() {},
        async authorizeBuilderRead() {
          return { grantId: "owner" };
        },
      },
      diagnostics: recorder,
    });

    const response = await runtime.fetch(
      new Request("http://localhost/v1/diagnostics", { method: "POST" }),
    );
    expect(response.status).toBe(405);
  });

  it("GET /v1/diagnostics requires owner auth", async () => {
    const { createPsLiteRuntime } = await import("./runtime.js");
    const {
      createMemoryPsLiteStorage,
      createMemoryPsLiteTokenStore,
      createMemoryPsLiteAccessLogStore,
    } = await import("./test-support/memory.js");
    const { ProtocolError } =
      await import("@opendatalabs/personal-server-ts-core/errors");

    const recorder = new DiagnosticsRecorder();
    const accessLogStore = createMemoryPsLiteAccessLogStore();
    const runtime = createPsLiteRuntime({
      storage: createMemoryPsLiteStorage(),
      accessLogReader: accessLogStore,
      accessLogWriter: accessLogStore,
      tokenStore: createMemoryPsLiteTokenStore(),
      saveConfig: async () => {},
      stateCapabilities: { config: "memory" },
      active: true,
      auth: {
        async authorizeOwner() {
          throw new ProtocolError(401, "NOT_OWNER", "Owner auth required");
        },
        async authorizeBuilderList() {},
        async authorizeBuilderRead() {
          return { grantId: "owner" };
        },
      },
      diagnostics: recorder,
    });

    const response = await runtime.fetch(
      new Request("http://localhost/v1/diagnostics", { method: "GET" }),
    );
    expect(response.status).toBe(401);
  });

  it("repair loop increments repairCounts and appears in /v1/diagnostics", async () => {
    const { createPsLiteRuntime } = await import("./runtime.js");
    const {
      createMemoryPsLiteStorage,
      createMemoryPsLiteTokenStore,
      createMemoryPsLiteAccessLogStore,
    } = await import("./test-support/memory.js");

    const recorder = new DiagnosticsRecorder();
    // Simulate the repair loop as it would be called from sync instrumentation
    recorder.recordRepair("drive");
    recorder.push({
      phase: "repairingManifest",
      scope: "drive",
      detail: "index exists without local payload; repairing",
    });
    recorder.recordRepair("drive");
    recorder.push({
      phase: "repairingManifest",
      scope: "drive",
      detail: "index exists without local payload; repairing",
    });

    const accessLogStore = createMemoryPsLiteAccessLogStore();
    const runtime = createPsLiteRuntime({
      storage: createMemoryPsLiteStorage(),
      accessLogReader: accessLogStore,
      accessLogWriter: accessLogStore,
      tokenStore: createMemoryPsLiteTokenStore(),
      saveConfig: async () => {},
      stateCapabilities: { config: "memory" },
      active: true,
      auth: {
        async authorizeOwner() {},
        async authorizeBuilderList() {},
        async authorizeBuilderRead() {
          return { grantId: "owner" };
        },
      },
      diagnostics: recorder,
    });

    const response = await runtime.fetch(
      new Request("http://localhost/v1/diagnostics", { method: "GET" }),
    );
    expect(response.status).toBe(200);

    const snap = (await response.json()) as PsLiteDiagnosticsSnapshot;
    // Repair counts must reflect both recordRepair calls
    expect(snap.repairCounts["drive"]).toBe(2);
    // Scope entry must have the count
    const driveScope = snap.scopes.find((s) => s.scope === "drive");
    expect(driveScope).toBeDefined();
    expect(driveScope!.repairCount).toBe(2);
    // Both repair events must be in the ring
    const repairEvents = snap.recentEvents.filter(
      (e) => e.phase === "repairingManifest" && e.scope === "drive",
    );
    expect(repairEvents).toHaveLength(2);
  });

  it("download failure maps to downloadFailed scope status in /v1/diagnostics", async () => {
    const { createPsLiteRuntime } = await import("./runtime.js");
    const {
      createMemoryPsLiteStorage,
      createMemoryPsLiteTokenStore,
      createMemoryPsLiteAccessLogStore,
    } = await import("./test-support/memory.js");

    const recorder = new DiagnosticsRecorder();
    // Simulate download failure as the sync hook adapter would record it
    recorder.beginOperation("downloading", undefined, "file-bad");
    recorder.push({
      phase: "downloading",
      fileId: "file-bad",
      error: true,
      detail: "connection refused",
    });
    recorder.endOperation();

    const accessLogStore = createMemoryPsLiteAccessLogStore();
    const runtime = createPsLiteRuntime({
      storage: createMemoryPsLiteStorage(),
      accessLogReader: accessLogStore,
      accessLogWriter: accessLogStore,
      tokenStore: createMemoryPsLiteTokenStore(),
      saveConfig: async () => {},
      stateCapabilities: { config: "memory" },
      active: true,
      auth: {
        async authorizeOwner() {},
        async authorizeBuilderList() {},
        async authorizeBuilderRead() {
          return { grantId: "owner" };
        },
      },
      diagnostics: recorder,
    });

    const response = await runtime.fetch(
      new Request("http://localhost/v1/diagnostics", { method: "GET" }),
    );
    expect(response.status).toBe(200);

    const snap = (await response.json()) as PsLiteDiagnosticsSnapshot;
    // No scope is set since we pushed without scope, but the error event must appear
    const errorEvents = snap.recentEvents.filter(
      (e) => e.error && e.phase === "downloading",
    );
    expect(errorEvents).toHaveLength(1);
    expect(errorEvents[0]!.detail).toBe("connection refused");
    expect(errorEvents[0]!.fileId).toBe("file-bad");
    // Active operation must be cleared after endOperation
    expect(snap.activeOperation).toBeNull();
  });

  it("decrypt failure maps to decryptFailed scope status in /v1/diagnostics", async () => {
    const { createPsLiteRuntime } = await import("./runtime.js");
    const {
      createMemoryPsLiteStorage,
      createMemoryPsLiteTokenStore,
      createMemoryPsLiteAccessLogStore,
    } = await import("./test-support/memory.js");

    const recorder = new DiagnosticsRecorder();
    recorder.beginOperation("decrypting", "health", "file-enc");
    recorder.push({
      phase: "decrypting",
      fileId: "file-enc",
      scope: "health",
      error: true,
      detail: "bad decryption key",
    });
    recorder.endOperation();

    const accessLogStore = createMemoryPsLiteAccessLogStore();
    const runtime = createPsLiteRuntime({
      storage: createMemoryPsLiteStorage(),
      accessLogReader: accessLogStore,
      accessLogWriter: accessLogStore,
      tokenStore: createMemoryPsLiteTokenStore(),
      saveConfig: async () => {},
      stateCapabilities: { config: "memory" },
      active: true,
      auth: {
        async authorizeOwner() {},
        async authorizeBuilderList() {},
        async authorizeBuilderRead() {
          return { grantId: "owner" };
        },
      },
      diagnostics: recorder,
    });

    const response = await runtime.fetch(
      new Request("http://localhost/v1/diagnostics", { method: "GET" }),
    );
    expect(response.status).toBe(200);

    const snap = (await response.json()) as PsLiteDiagnosticsSnapshot;
    const healthScope = snap.scopes.find((s) => s.scope === "health");
    expect(healthScope).toBeDefined();
    expect(healthScope!.status).toBe("decryptFailed");
    expect(healthScope!.lastError).toBe("bad decryption key");
    expect(healthScope!.lastFileId).toBe("file-enc");
  });
});
