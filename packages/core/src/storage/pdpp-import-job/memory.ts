/**
 * In-memory import job adapter: the reference behaviour for native adapters
 * and the oracle for engine tests. Not a production store. Each method
 * builds its whole effect first and applies it in one synchronous step, so a
 * fault before that step leaves nothing and a fault after it is a lost ack.
 */

import {
  liveSnapshotDigestAsync,
  type LiveSnapshotRow,
} from "../pdpp-records/completion.js";
import { planIngest } from "../pdpp-records/ingest-plan.js";
import type { PdppRecordEnvelopeInput } from "../pdpp-records/types.js";
import {
  ImportJobError,
  PDPP_IMPORT_JOB_CONTRACT_VERSION,
  type ImportBatchReceipt,
  type ImportBindingSnapshot,
  type ImportCommitReceipt,
  type ImportConnectorState,
  type ImportJobRecord,
  type ImportPublishInput,
  type ImportSpoolHandle,
  type ImportStagedOperation,
  type PdppImportJobCapability,
} from "./contract.js";

/** Where a test may make the adapter fail. */
export type MemoryImportFaultPoint =
  | "stage:before-commit"
  | "stage:after-commit"
  | "publish:before-commit"
  | "publish:after-commit"
  | "abort:before-commit";

export interface MemoryImportRow {
  instance: string;
  stream: string;
  recordKey: string;
  data: Record<string, unknown> | null;
  deleted: boolean;
  version: number;
  emittedAt: string;
}

/** One captured replication mutation; present only when replication is enabled. */
export interface MemoryImportOutboxEntry {
  operationId: string;
  instance: string;
  method: string;
  generation: number;
  stream: string;
  recordKey: string;
  operation: "upsert" | "delete";
  value: MemoryImportRow;
}

export interface MemoryImportCompletion {
  instance: string;
  stream: string;
  sourceCollectedAt: string;
  liveCount: number;
  snapshotSha256: string;
  generation: number;
}

export interface MemoryImportJobCapabilityOptions {
  /** Capture an outbox entry for every published write, in the same step. */
  replication?: boolean;
  fault?: (point: MemoryImportFaultPoint) => void;
  /** Spool bytes by handle id, for `readSpool`. */
  spools?: Map<string, Uint8Array>;
  /** Index rows applied per page at publication. */
  pageSize?: number;
  /** Override the reported contract version (version-boundary tests). */
  contractVersion?: number;
}

interface Binding {
  sourceId: string;
  method: string;
  generation: number;
  deleted: boolean;
}

const rowKey = (instance: string, stream: string, recordKey: string) =>
  `${instance}\0${stream}\0${recordKey}`;
const indexKey = (stream: string, recordKey: string) =>
  `${stream}\0${recordKey}`;

export function createMemoryImportJobCapability(
  options: MemoryImportJobCapabilityOptions = {},
) {
  const fault = options.fault ?? (() => {});
  const pageSize = options.pageSize ?? 256;
  const bindings = new Map<string, Binding>();
  let rows = new Map<string, MemoryImportRow>();
  const history: MemoryImportRow[] = [];
  const outbox: MemoryImportOutboxEntry[] = [];
  const completions = new Map<string, MemoryImportCompletion>();
  const jobs = new Map<string, ImportJobRecord>();
  const receipts = new Map<string, ImportBatchReceipt>();
  const indexes = new Map<string, Map<string, ImportStagedOperation>>();
  const connectorStates = new Map<string, ImportConnectorState>();
  const clone = <T>(value: T): T => structuredClone(value);
  // One writer at a time, like a SQLite write lock.
  let queue: Promise<unknown> = Promise.resolve();
  function serial<T>(step: () => Promise<T>): Promise<T> {
    const run = queue.then(step, step);
    queue = run.catch(() => undefined);
    return run;
  }

  async function publish(
    input: ImportPublishInput,
  ): Promise<ImportCommitReceipt> {
    const job = jobs.get(input.job.jobId);
    if (!job) throw new ImportJobError("job_not_found");
    if (job.state === "committed" && job.commit) return clone(job.commit);
    // Checked again at the commit point: reset and abort do not wait for
    // this writer, and publication awaits while it hashes proofs.
    const assertPublishable = () => {
      const stored = jobs.get(job.jobId);
      if (!stored || stored.state !== "open")
        throw new ImportJobError("job_not_open");
      if (stored.nextSeq !== input.job.nextSeq)
        throw new ImportJobError("batch_count_mismatch");
      if (stored.nextSeq < 1 || stored.spoolOffset !== stored.spool.byteLength)
        throw new ImportJobError("spool_incomplete");
      const binding = bindings.get(stored.binding.instance);
      if (
        !binding ||
        binding.deleted ||
        binding.method !== stored.binding.method ||
        binding.generation !== stored.binding.generation
      )
        throw new ImportJobError("binding_mismatch");
    };
    assertPublishable();
    const { instance, method, generation, sourceId } = job.binding;

    const next = new Map(rows);
    const written: MemoryImportRow[] = [];
    const captured: MemoryImportOutboxEntry[] = [];
    const touched = new Set<string>();
    let accepted = 0;
    let unchanged = 0;
    let rejected = 0;
    const staged = [...indexes.get(job.jobId)!.values()].sort(
      (a, b) => a.order - b.order,
    );
    for (let start = 0; start < staged.length; start += pageSize) {
      for (const operation of staged.slice(start, start + pageSize)) {
        const declaration = input.declarations.forInstance(
          instance,
          operation.stream,
        );
        if (!declaration) {
          rejected += 1;
          continue;
        }
        const envelope: PdppRecordEnvelopeInput = {
          instance,
          stream: operation.stream,
          key: JSON.parse(operation.keyJson),
          data:
            operation.dataJson === null ? null : JSON.parse(operation.dataJson),
          emitted_at: operation.emittedAt,
          op: operation.op,
        };
        const key = rowKey(instance, operation.stream, operation.recordKey);
        const plan = planIngest(
          operation.order,
          envelope,
          declaration.semantics,
          declaration.primaryKey,
          () => {
            const row = next.get(key);
            return row && { deleted: row.deleted, data: row.data };
          },
          input.declarations.validateData,
        );
        if (plan.outcome.outcome === "rejected") rejected += 1;
        else if (plan.outcome.outcome === "unchanged") unchanged += 1;
        if (!plan.write) continue;
        accepted += 1;
        const row: MemoryImportRow = {
          instance,
          stream: operation.stream,
          recordKey: plan.write.recordKey,
          data: plan.write.data,
          deleted: plan.write.data === null,
          version: (next.get(key)?.version ?? 0) + 1,
          emittedAt: operation.emittedAt,
        };
        next.set(key, row);
        written.push(row);
        touched.add(operation.stream);
        if (options.replication)
          captured.push({
            operationId: operation.digest,
            instance,
            method,
            generation,
            stream: operation.stream,
            recordKey: row.recordKey,
            operation: row.deleted ? "delete" : "upsert",
            value: row,
          });
      }
    }

    const proven: MemoryImportCompletion[] = [];
    for (const proof of input.completion?.streams ?? []) {
      const declaration = input.declarations.forInstance(
        instance,
        proof.stream,
      );
      if (!declaration) throw new ImportJobError("completion_failed");
      const live: LiveSnapshotRow[] = [];
      for (const row of next.values())
        if (
          row.instance === instance &&
          row.stream === proof.stream &&
          !row.deleted
        )
          live.push({
            recordKey: row.recordKey,
            dataJson: JSON.stringify(row.data),
          });
      const digest = await liveSnapshotDigestAsync(
        { sourceId, instance, method, generation, stream: proof.stream },
        declaration.primaryKey,
        live,
      );
      if (live.length !== proof.liveCount || digest !== proof.snapshotSha256)
        throw new ImportJobError(
          "completion_failed",
          `stream ${proof.stream}: the live set differs from the proof`,
        );
      proven.push({
        instance,
        stream: proof.stream,
        sourceCollectedAt: input.completion!.sourceCollectedAt,
        liveCount: live.length,
        snapshotSha256: digest,
        generation,
      });
    }
    const receipt: ImportCommitReceipt = {
      jobId: job.jobId,
      contractVersion: PDPP_IMPORT_JOB_CONTRACT_VERSION,
      instance,
      generation,
      batches: job.nextSeq,
      records: job.records,
      operations: staged.length,
      accepted,
      unchanged,
      rejected: job.rejected + rejected,
      completedStreams: proven.map((proof) => proof.stream),
      connectorStateSha256: input.connectorStateSha256,
      committedAt: input.committedAt,
    };

    fault("publish:before-commit");
    assertPublishable();
    rows = next;
    history.push(...written);
    outbox.push(...captured);
    for (const stream of touched) completions.delete(`${instance}\0${stream}`);
    for (const proof of proven)
      completions.set(`${instance}\0${proof.stream}`, proof);
    if (input.connectorState !== undefined)
      connectorStates.set(instance, {
        instance,
        generation,
        jobId: job.jobId,
        state: input.connectorState,
        committedAt: input.committedAt,
      });
    jobs.set(job.jobId, {
      ...job,
      state: "committed",
      updatedAt: input.committedAt,
      commit: receipt,
    });
    indexes.delete(job.jobId);
    fault("publish:after-commit");
    return clone(receipt);
  }

  const capability: PdppImportJobCapability = {
    contractVersion:
      options.contractVersion ?? PDPP_IMPORT_JOB_CONTRACT_VERSION,

    async readBinding(instance): Promise<ImportBindingSnapshot> {
      const binding = bindings.get(instance);
      return binding
        ? {
            sourceId: binding.sourceId,
            method: binding.method,
            generation: binding.generation,
            deleted: binding.deleted,
          }
        : { sourceId: null, method: null, generation: 1, deleted: false };
    },

    async createJob(job) {
      const existing = jobs.get(job.jobId);
      if (existing) return clone(existing);
      jobs.set(job.jobId, clone(job));
      indexes.set(job.jobId, new Map());
      return clone(job);
    },

    async readJob(jobId) {
      const job = jobs.get(jobId);
      return job && clone(job);
    },

    async stageBatch({ job, receipt, operations }) {
      const receiptKey = `${receipt.jobId}\0${receipt.seq}`;
      const existing = receipts.get(receiptKey);
      if (existing) return clone(existing);
      const stored = jobs.get(job.jobId);
      if (!stored || stored.state !== "open")
        throw new ImportJobError("job_not_open");
      if (stored.nextSeq !== receipt.seq)
        throw new ImportJobError("batch_out_of_order");
      const index = indexes.get(job.jobId)!;
      const updates = new Map<string, ImportStagedOperation>();
      for (const operation of operations) {
        const key = indexKey(operation.stream, operation.recordKey);
        const prior = updates.get(key) ?? index.get(key);
        if (prior && operation.keep === "first") continue;
        updates.set(key, clone(operation));
      }
      fault("stage:before-commit");
      for (const [key, operation] of updates) index.set(key, operation);
      receipts.set(receiptKey, clone(receipt));
      jobs.set(job.jobId, clone(job));
      fault("stage:after-commit");
      return clone(receipt);
    },

    async readBatchReceipt(jobId, seq) {
      const receipt = receipts.get(`${jobId}\0${seq}`);
      return receipt && clone(receipt);
    },

    publish: (input) => serial(() => publish(input)),

    async abort(jobId, reason, at) {
      const job = jobs.get(jobId);
      if (!job) return undefined;
      if (job.state !== "open") return clone(job);
      fault("abort:before-commit");
      const aborted: ImportJobRecord = {
        ...job,
        state: "aborted",
        abortReason: reason,
        updatedAt: at,
      };
      jobs.set(jobId, aborted);
      indexes.delete(jobId);
      return clone(aborted);
    },

    async readConnectorState(instance) {
      const state = connectorStates.get(instance);
      return state && clone(state);
    },

    async readSpool(spool: ImportSpoolHandle, offset, maxBytes) {
      const bytes = options.spools?.get(spool.id);
      if (!bytes) throw new ImportJobError("invalid_request", "unknown spool");
      return bytes.slice(offset, offset + maxBytes);
    },
  };

  /** What the store's erase does for import data: open jobs abort, staged rows and the cursor go. */
  function eraseInstance(instance: string) {
    for (const [key, row] of rows)
      if (row.instance === instance) rows.delete(key);
    for (const [jobId, job] of jobs) {
      if (job.binding.instance !== instance) continue;
      indexes.delete(jobId);
      if (job.state === "open")
        jobs.set(jobId, {
          ...job,
          state: "aborted",
          abortReason: "connection_reset",
          updatedAt: new Date().toISOString(),
        });
    }
    connectorStates.delete(instance);
  }

  return Object.assign(capability, {
    registerConnection(input: {
      instance: string;
      sourceId: string;
      method: string;
    }) {
      bindings.set(input.instance, {
        sourceId: input.sourceId,
        method: input.method,
        generation: 1,
        deleted: false,
      });
    },
    /** A connection reset: the generation advances and its data goes. */
    resetConnection(instance: string) {
      bindings.get(instance)!.generation += 1;
      eraseInstance(instance);
    },
    deleteConnection(instance: string) {
      const binding = bindings.get(instance)!;
      binding.deleted = true;
      binding.generation += 1;
      eraseInstance(instance);
    },
    /** Current rows of one stream, tombstones included, sorted by key. */
    rows(instance: string, stream: string): MemoryImportRow[] {
      return [...rows.values()]
        .filter((row) => row.instance === instance && row.stream === stream)
        .sort((a, b) =>
          a.recordKey < b.recordKey ? -1 : a.recordKey > b.recordKey ? 1 : 0,
        )
        .map(clone);
    },
    history: () => history.map(clone),
    outbox: () => outbox.map(clone),
    completion: (instance: string, stream: string) =>
      completions.get(`${instance}\0${stream}`),
    /** Index rows of a job: what a crash would leave staged. */
    stagedCount: (jobId: string) => indexes.get(jobId)?.size ?? 0,
  });
}

export type MemoryImportJobCapability = ReturnType<
  typeof createMemoryImportJobCapability
>;
