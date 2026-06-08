/**
 * PS Lite one-shot diagnostics — v1
 *
 * Produces a bounded, plain-JSON diagnostic snapshot that the web MCP approval
 * page can copy verbatim when it is stuck waiting for scopes. No payload bodies
 * or secrets are ever included.
 *
 * Usage:
 *   const recorder = new DiagnosticsRecorder();
 *   recorder.push({ phase: "indexing", detail: "scope=drive" });
 *   // … pass recorder into createPsLiteRuntime({ diagnostics: recorder, … })
 *   // GET /v1/diagnostics returns recorder.snapshot(syncStatus, storage)
 */

import type { SyncStatus } from "@opendatalabs/personal-server-ts-core/sync";
import type { DataStoragePort } from "@opendatalabs/personal-server-ts-core/ports";

export const DIAGNOSTICS_VERSION = 1;

/** Phases that the PS / PS Lite can be in during its lifecycle. */
export type DiagnosticsPhase =
  | "booting"
  | "registering"
  | "routing"
  | "syncing"
  | "downloading"
  | "decrypting"
  | "indexing"
  | "buildingManifest"
  | "repairingManifest"
  | "generatingScopes"
  | "storageFailing"
  | "networkFailing"
  | "ready"
  | "unknown";

/** Per-scope readiness states visible to the approval page. */
export type ScopeReadinessStatus =
  | "ready"
  | "indexing"
  | "waitingForPayload"
  | "manifestMissing"
  | "downloadFailed"
  | "decryptFailed"
  | "indexFailed"
  | "unknown";

export interface DiagnosticsEvent {
  /** ISO 8601 timestamp */
  at: string;
  phase: DiagnosticsPhase;
  /** Free-form detail — no payload bodies or secrets */
  detail?: string;
  /** Associated scope identifier, if known */
  scope?: string;
  /** Associated file id, if known */
  fileId?: string;
  /** Whether this event represents an error condition */
  error?: boolean;
}

export interface ScopeDiagnostics {
  scope: string;
  status: ScopeReadinessStatus;
  /** ISO 8601 */
  lastActivityAt?: string;
  lastError?: string;
  lastFileId?: string;
  /** Bytes of the last payload, if known */
  sizeBytes?: number;
  /** How many times a repair loop has fired for this scope */
  repairCount?: number;
}

export interface ActiveOperation {
  phase: DiagnosticsPhase;
  startedAt: string;
  elapsedMs: number;
  scope?: string;
  fileId?: string;
}

export interface LastNetworkOperation {
  /** e.g. "download", "upload", "gatewayGetServer" */
  operationClass: string;
  status: "ok" | "error";
  elapsedMs: number;
  /** HTTP status code or error class, no body */
  statusOrError?: string | number;
  at: string;
}

export interface StorageHealthSummary {
  indexedDbAvailable: boolean;
  persistenceBackend?: string;
  opfsAvailable?: boolean;
  entryCount?: number;
  unsyncedCount?: number;
  scopeCount?: number;
}

export interface PsLiteDiagnosticsSnapshot {
  diagnosticVersion: 1;
  capturedAt: string;
  /** Current runtime active state */
  runtimeActive: boolean | "unknown";
  /** Current or last readiness phase */
  currentPhase: DiagnosticsPhase;
  /** Active operation with elapsed time, if any */
  activeOperation: ActiveOperation | null;
  /** Recent event ring, newest-last, bounded to MAX_EVENTS */
  recentEvents: DiagnosticsEvent[];
  /** Per-scope readiness where known */
  scopes: ScopeDiagnostics[];
  /** Sync manager status, if available */
  sync: SyncDiagnostics | null;
  /** Storage health, if available */
  storage: StorageHealthSummary | null;
  /** Most recent network/storage operation, no body */
  lastNetworkOperation: LastNetworkOperation | null;
  /** Repair loop counts keyed by scope */
  repairCounts: Record<string, number>;
  /** Whether diagnostics collection itself timed out */
  partial: boolean;
}

export interface SyncDiagnostics {
  enabled: boolean;
  running: boolean;
  syncing: boolean;
  blocked: { reason: string; message: string } | null;
  lastSync: string | null;
  lastProcessedTimestamp: string | null;
  pendingFiles: number;
  recentErrors: Array<{
    fileId: string | null;
    scope: string | null;
    message: string;
    timestamp: string;
  }>;
}

const MAX_EVENTS = 100;
const DIAG_TIMEOUT_MS = 3_000;

/** Options passed when recording an event. */
export interface RecordEventOptions {
  phase: DiagnosticsPhase;
  detail?: string;
  scope?: string;
  fileId?: string;
  error?: boolean;
}

/**
 * Lightweight thread-safe (single-threaded JS) recorder.
 *
 * Instantiate once per PS Lite runtime; pass it into createPsLiteRuntime and
 * call recorder.push() from sync, storage, and indexing code paths.
 */
export class DiagnosticsRecorder {
  private readonly events: DiagnosticsEvent[] = [];
  private currentPhase: DiagnosticsPhase = "booting";
  private activeOp: {
    phase: DiagnosticsPhase;
    startedAt: number;
    scope?: string;
    fileId?: string;
  } | null = null;
  private lastNetwork: LastNetworkOperation | null = null;
  private readonly scopeMap = new Map<string, ScopeDiagnostics>();
  private readonly repairCounts: Record<string, number> = {};

  push(options: RecordEventOptions): void {
    const event: DiagnosticsEvent = {
      at: new Date().toISOString(),
      phase: options.phase,
      ...(options.detail !== undefined ? { detail: options.detail } : {}),
      ...(options.scope !== undefined ? { scope: options.scope } : {}),
      ...(options.fileId !== undefined ? { fileId: options.fileId } : {}),
      ...(options.error ? { error: true } : {}),
    };
    this.events.push(event);
    if (this.events.length > MAX_EVENTS) {
      this.events.splice(0, this.events.length - MAX_EVENTS);
    }
    this.currentPhase = options.phase;

    if (options.scope) {
      const existing = this.scopeMap.get(options.scope) ?? {
        scope: options.scope,
        status: "unknown" as ScopeReadinessStatus,
      };
      const next: ScopeDiagnostics = {
        ...existing,
        scope: options.scope,
        lastActivityAt: event.at,
        ...(options.fileId ? { lastFileId: options.fileId } : {}),
        ...(options.error && options.detail
          ? { lastError: options.detail }
          : {}),
        status: phaseToScopeStatus(options.phase, options.error),
      };
      this.scopeMap.set(options.scope, next);
    }
  }

  /** Call when an async operation starts (e.g. a download or index run). */
  beginOperation(
    phase: DiagnosticsPhase,
    scope?: string,
    fileId?: string,
  ): void {
    this.activeOp = { phase, startedAt: Date.now(), scope, fileId };
    this.currentPhase = phase;
  }

  /** Call when the async operation completes or fails. */
  endOperation(): void {
    this.activeOp = null;
  }

  /** Record a network or storage operation result without payload. */
  recordNetworkOp(
    operationClass: string,
    status: "ok" | "error",
    elapsedMs: number,
    statusOrError?: string | number,
  ): void {
    this.lastNetwork = {
      operationClass,
      status,
      elapsedMs,
      ...(statusOrError !== undefined ? { statusOrError } : {}),
      at: new Date().toISOString(),
    };
  }

  /** Increment the repair loop counter for a scope. */
  recordRepair(scope: string): void {
    this.repairCounts[scope] = (this.repairCounts[scope] ?? 0) + 1;
    const existing = this.scopeMap.get(scope) ?? {
      scope,
      status: "unknown" as ScopeReadinessStatus,
    };
    this.scopeMap.set(scope, {
      ...existing,
      repairCount: this.repairCounts[scope],
    });
  }

  /** Update per-scope readiness explicitly. */
  setScopeStatus(
    scope: string,
    status: ScopeReadinessStatus,
    extra?: Partial<Omit<ScopeDiagnostics, "scope" | "status">>,
  ): void {
    const existing = this.scopeMap.get(scope) ?? { scope, status };
    this.scopeMap.set(scope, { ...existing, ...extra, scope, status });
  }

  /**
   * Assemble a snapshot. Optionally accepts sync status and storage port to
   * enrich the result. Runs with a hard timeout so it can never block.
   */
  snapshot(options?: {
    runtimeActive?: boolean;
    syncStatus?: SyncStatus | null;
    storage?: DataStoragePort | null;
  }): PsLiteDiagnosticsSnapshot {
    const now = new Date().toISOString();

    const activeOperation: ActiveOperation | null = this.activeOp
      ? {
          phase: this.activeOp.phase,
          startedAt: new Date(this.activeOp.startedAt).toISOString(),
          elapsedMs: Date.now() - this.activeOp.startedAt,
          ...(this.activeOp.scope ? { scope: this.activeOp.scope } : {}),
          ...(this.activeOp.fileId ? { fileId: this.activeOp.fileId } : {}),
        }
      : null;

    const sync = buildSyncDiagnostics(options?.syncStatus);
    const storage = buildStorageDiagnostics(options?.storage);
    const scopes = Array.from(this.scopeMap.values());

    return {
      diagnosticVersion: DIAGNOSTICS_VERSION,
      capturedAt: now,
      runtimeActive: options?.runtimeActive ?? "unknown",
      currentPhase: this.currentPhase,
      activeOperation,
      recentEvents: [...this.events],
      scopes,
      sync,
      storage,
      lastNetworkOperation: this.lastNetwork,
      repairCounts: { ...this.repairCounts },
      partial: false,
    };
  }
}

function phaseToScopeStatus(
  phase: DiagnosticsPhase,
  error?: boolean,
): ScopeReadinessStatus {
  if (error) {
    if (phase === "downloading") return "downloadFailed";
    if (phase === "decrypting") return "decryptFailed";
    if (phase === "indexing") return "indexFailed";
    if (phase === "buildingManifest" || phase === "repairingManifest")
      return "manifestMissing";
    return "unknown";
  }
  switch (phase) {
    case "ready":
      return "ready";
    case "indexing":
      return "indexing";
    case "downloading":
      return "waitingForPayload";
    case "buildingManifest":
    case "repairingManifest":
      return "indexing";
    default:
      return "unknown";
  }
}

function buildSyncDiagnostics(
  status?: SyncStatus | null,
): SyncDiagnostics | null {
  if (!status) return null;
  return {
    enabled: status.enabled,
    running: status.running,
    syncing: status.syncing,
    blocked: status.blocked ?? null,
    lastSync: status.lastSync,
    lastProcessedTimestamp: status.lastProcessedTimestamp,
    pendingFiles: status.pendingFiles,
    recentErrors: status.errors.map((e) => ({
      fileId: e.fileId,
      scope: e.scope,
      message: e.message,
      timestamp: e.timestamp,
    })),
  };
}

function buildStorageDiagnostics(
  storage?: DataStoragePort | null,
): StorageHealthSummary | null {
  if (!storage) return null;
  try {
    const scopeResult = storage.listScopes({ limit: 1000 });
    const unsynced = storage.findUnsynced({ limit: 1000 });
    return {
      indexedDbAvailable: typeof indexedDB !== "undefined",
      persistenceBackend: storage.kind,
      scopeCount: scopeResult.total,
      unsyncedCount: unsynced.length,
    };
  } catch {
    return {
      indexedDbAvailable: typeof indexedDB !== "undefined",
    };
  }
}

/**
 * Collect a diagnostic snapshot with a hard timeout so it can never block the
 * approval page. Returns a partial snapshot if the timeout fires.
 */
export async function collectDiagnosticsWithTimeout(
  recorder: DiagnosticsRecorder,
  options?: Parameters<DiagnosticsRecorder["snapshot"]>[0],
  timeoutMs = DIAG_TIMEOUT_MS,
): Promise<PsLiteDiagnosticsSnapshot> {
  return new Promise<PsLiteDiagnosticsSnapshot>((resolve) => {
    const tid = setTimeout(() => {
      resolve({ ...recorder.snapshot(options), partial: true });
    }, timeoutMs);

    try {
      const snap = recorder.snapshot(options);
      clearTimeout(tid);
      resolve(snap);
    } catch {
      clearTimeout(tid);
      resolve({
        diagnosticVersion: DIAGNOSTICS_VERSION,
        capturedAt: new Date().toISOString(),
        runtimeActive: options?.runtimeActive ?? "unknown",
        currentPhase: "unknown",
        activeOperation: null,
        recentEvents: [],
        scopes: [],
        sync: null,
        storage: null,
        lastNetworkOperation: null,
        repairCounts: {},
        partial: true,
      });
    }
  });
}
