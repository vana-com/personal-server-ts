import { trackLegacyScopeMutations } from "./legacy-scope-revalidation-state.js";
import { readlinkSync } from "node:fs";
import { setPriority } from "node:os";
import { isDeepStrictEqual } from "node:util";
import Database from "better-sqlite3";
import { configureDatabaseConnection } from "./index-schema.js";
import {
  Worker,
  isMainThread,
  parentPort,
  workerData,
} from "node:worker_threads";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import {
  createLegacyScopeView,
  type LegacyScopeAuthority,
  type CreateLegacyScopeViewInput,
} from "@opendatalabs/personal-server-ts-core/storage/legacy-scope-view";
import { createSourceStreamDeclarationRegistry } from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import type { DeclarationSnapshot } from "@opendatalabs/personal-server-ts-core/pdpp";
import { replicaDeclarationContext } from "@opendatalabs/personal-server-ts-core/replication/host-config";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import { createReplicaRecordStore } from "./pdpp-replica-canonical-port.js";
import { createReplicaReceiver } from "./pdpp-replication-receiver.js";
import { createLegacyScopeAuthority } from "./legacy-scope-authority.js";
import {
  legacyScopeRecords,
  toStreamDeclarations,
} from "../pdpp/records-bootstrap.js";

export interface LegacyEvaluationConfig {
  database: string;
  ceilingMs?: number;
  dataDir: string;
  owner: string;
  replication: boolean;
  declarations: readonly DeclarationSnapshot[];
  configuredMethods: [string, string[]][];
  optInMethods: string[];
  coverageThresholds: CreateLegacyScopeViewInput["coverageThresholds"];
}
export interface LegacyEvaluationJob extends LegacyEvaluationConfig {
  instance: string;
  scopes: readonly string[];
  epoch: number;
}
export const isLegacyEvaluationWorker =
  !isMainThread && workerData?.legacyScopeEvaluation === true;

/** Separate event loop and SQLite handle: projection CPU never runs in ingest. */
export function createLegacyEvaluationWorker(
  options: { timeoutMs?: number } = {},
) {
  const epoch = new Int32Array(new SharedArrayBuffer(4));
  let worker: Worker | undefined;
  let closed = false;
  let timeout: ReturnType<typeof setTimeout> | undefined;
  type Result = { wallMs: number; peakRssKiB: number; refused: string[] };
  let active:
    { resolve(value: Result): void; reject(error: Error): void } | undefined;
  function fail(current: Worker, error: Error) {
    if (worker !== current) return;
    worker = undefined;
    clearTimeout(timeout);
    const interrupted = active;
    // Do not release the single-flight slot until the old projection thread
    // has stopped, even when its deadline or an uncaught error ends the job.
    void current.terminate().finally(() => {
      if (active === interrupted) active = undefined;
      interrupted?.reject(error);
    });
  }
  return {
    invalidate() {
      Atomics.add(epoch, 0, 1);
    },
    evaluate(input: Omit<LegacyEvaluationJob, "epoch">) {
      if (closed) throw Error("Legacy evaluator is closed");
      if (active) throw Error("Legacy evaluator is already running");
      if (!worker) {
        const url = import.meta.url.endsWith(".ts")
          ? new URL(
              "../../dist/storage/legacy-scope-evaluation.js",
              import.meta.url,
            )
          : new URL(import.meta.url);
        const current = new Worker(url, {
          workerData: { legacyScopeEvaluation: true, epoch: epoch.buffer },
          resourceLimits: { maxOldGenerationSizeMb: 1024 },
        });
        worker = current;
        current.on("message", (message) => {
          if (worker !== current) return;
          clearTimeout(timeout);
          if (message.error) active?.reject(Error(message.error));
          else active?.resolve(message);
          active = undefined;
        });
        current.on("error", (error) =>
          fail(
            current,
            error instanceof Error ? error : Error("Legacy evaluator failed"),
          ),
        );
        current.on("exit", () =>
          fail(current, Error("Legacy evaluator stopped")),
        );
      }
      const current = worker;
      return new Promise<Result>((resolve, reject) => {
        active = { resolve, reject };
        timeout = setTimeout(
          () =>
            fail(current, Error("Legacy evaluator exceeded its time budget")),
          options.timeoutMs ?? 60_000,
        );
        timeout.unref();
        current.postMessage({ ...input, epoch: Atomics.load(epoch, 0) });
      });
    },
    async stop() {
      closed = true;
      const current = worker;
      worker = undefined;
      clearTimeout(timeout);
      active?.reject(Error("Legacy evaluator stopped"));
      active = undefined;
      if (current) await current.terminate();
    },
  };
}

/** Background comparisons bypass cached evidence and fence all external commits. */
export function freshCoverageAuthority(
  authority: LegacyScopeAuthority,
  isCurrent: () => boolean,
): LegacyScopeAuthority {
  return {
    ...authority,
    cachedVerdict: () => null,
    confirmRead(scope, head, current, method, verdict) {
      const same =
        verdict && !verdict.completion && head
          ? authority.cachedVerdict(
              scope,
              verdict.instance,
              verdict.generation,
              head.id,
              verdict.canonicalCursor,
            )
          : null;
      const reuse =
        verdict &&
        !verdict.completion &&
        same &&
        isDeepStrictEqual(same, verdict.coverage);
      return authority.confirmRead(
        scope,
        head,
        () => current() && isCurrent(),
        method,
        reuse
          ? {
              ...verdict,
              coverage: verdict.coverage!,
              cached: true,
              completion: undefined,
            }
          : verdict,
      );
    },
  };
}

if (isLegacyEvaluationWorker) {
  // Linux schedules individual threads by TID. Lower only this projection
  // thread's priority; never lower the ingest/event-loop thread's priority.
  if (process.platform === "linux") {
    try {
      setPriority(
        Number(readlinkSync("/proc/thread-self").split("/").at(-1)),
        10,
      );
    } catch {
      /* Scheduling correctness does not depend on priority support. */
    }
  }
  const epoch = new Int32Array(workerData.epoch);
  let db: Database.Database | undefined;
  let state: ReturnType<typeof trackLegacyScopeMutations> | undefined;
  let store: ReturnType<typeof createSqliteRecordStore> | undefined;
  let replica: ReturnType<typeof createReplicaRecordStore> | undefined;
  let receiver: ReturnType<typeof createReplicaReceiver> | undefined;
  let context: ReturnType<typeof replicaDeclarationContext> | undefined;
  let declarationsKey = "";
  parentPort!.on("message", async (job: LegacyEvaluationJob) => {
    const started = performance.now();
    try {
      if (!db) {
        const raw = new Database(job.database);
        configureDatabaseConnection(raw);
        state = trackLegacyScopeMutations(raw, {
          ceilingMs: job.ceilingMs ?? 1800000,
          // The main process already invalidated surviving proofs at boot.
          processBoot: false,
        });
        db = state.db;
        if (job.replication) {
          replica = createReplicaRecordStore(db);
          store = replica;
        } else store = createSqliteRecordStore(db);
      }
      const key = JSON.stringify(job.declarations);
      if (job.replication && (key !== declarationsKey || !receiver)) {
        context = replicaDeclarationContext(
          job.owner,
          job.declarations,
          replica!.replication.declarationHistory(),
        );
        if (!receiver)
          receiver = createReplicaReceiver({
            db,
            store: replica!,
            owner: job.owner,
            authenticate: (credential) =>
              credential === true ? job.owner : undefined,
            declarations: () => context!.declarations,
          });
        else receiver.reconcileDeclarations({ credential: true });
      }
      declarationsKey = key;
      const registry = createSourceStreamDeclarationRegistry(
        job.declarations.map((snapshot) => ({
          sourceId: snapshot.source_id,
          streams: toStreamDeclarations(snapshot),
        })),
      );
      const baseAuthority = createLegacyScopeAuthority(db, state);
      const authority = {
        ...baseAuthority,
        confirmRead(...args: Parameters<typeof baseAuthority.confirmRead>) {
          return db!
            .transaction(() => {
              if (state!.revision(job.instance) !== revision) return false;
              const confirmed = baseAuthority.confirmRead(...args);
              if (confirmed && args[4])
                state!.complete(job.instance, args[0], revision);
              return confirmed;
            })
            .immediate();
        },
      };
      const dataVersion = () => db!.pragma("data_version", { simple: true });
      const methods = new Map(job.configuredMethods);
      const view = createLegacyScopeView({
        authority: freshCoverageAuthority(
          authority,
          () =>
            dataVersion() === version && Atomics.load(epoch, 0) === job.epoch,
        ),
        records: receiver
          ? legacyScopeRecords({
              bindingStore: store!,
              reads: () => receiver!.readStore({ reader: "grant" }),
            })
          : store!,
        declarations: {
          forInstance: (instance, stream) => {
            const source = store!.getInstanceBinding(instance).sourceId;
            return source ? registry.get(stream, source) : undefined;
          },
        },
        configuredMethods: (source) => methods.get(source) ?? [],
        optInMethods: new Set(job.optInMethods),
        coverageThresholds: job.coverageThresholds,
        readLegacyHead: async (head) => {
          if (
            head.path.startsWith("/") ||
            head.path.split(/[\\/]/).includes("..")
          )
            throw Error("Unsafe legacy path");
          return JSON.parse(
            await readFile(join(job.dataDir, head.path), "utf8"),
          );
        },
      });
      // This connection's data_version moves on another handle's commit, including
      // a newer negative proof that must defeat this evaluation's older positive.
      let version: unknown;
      let revision: number;
      const refused: string[] = [];
      for (const scope of job.scopes) {
        version = dataVersion();
        revision = state!.revision(job.instance);
        const result = await view.readLatest(scope);
        if (result.kind === "refused") {
          refused.push(`${scope}:${result.refusal.reason}`);
          state!.fail(job.instance, [scope]);
        }
      }
      parentPort!.postMessage({
        wallMs: performance.now() - started,
        peakRssKiB: process.resourceUsage().maxRSS,
        refused,
      });
    } catch {
      if (db?.open) db.close();
      db = undefined;
      store = undefined;
      replica = undefined;
      receiver = undefined;
      parentPort!.postMessage({ error: "Legacy coverage evaluation failed" });
    }
  });
}
