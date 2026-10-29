/**
 * The import job engine: every rule of contract version 1. Adapters persist
 * what it decides. See docs/261028-pdpp-import-job.md.
 */

import {
  StreamCompletionError,
  parseCompletionRequest,
} from "../pdpp-records/completion.js";
import { canonicalJson, planIngest } from "../pdpp-records/ingest-plan.js";
import { encodeRecordKey } from "../pdpp-records/record-key.js";
import type { PdppRecordEnvelopeInput } from "../pdpp-records/types.js";
import {
  IMPORT_JOB_DEFAULT_BATCH_BYTES,
  IMPORT_JOB_MAX_BATCH_BYTES,
  IMPORT_JOB_MAX_CONNECTOR_STATE_BYTES,
  IMPORT_JOB_MAX_IN_FLIGHT,
  IMPORT_JOB_MAX_LISTED_REJECTIONS,
  IMPORT_JOB_MAX_RECORD_BYTES,
  ImportJobError,
  PDPP_IMPORT_JOB_CONTRACT_VERSION,
  PDPP_IMPORT_SPOOL_FORMAT,
  type ImportBatchInput,
  type ImportBatchReceipt,
  type ImportCanonicalBatch,
  type ImportCommitInput,
  type ImportCommitReceipt,
  type ImportDeclarations,
  type ImportJobBeginInput,
  type ImportJobRecord,
  type ImportJobStatus,
  type ImportRejection,
  type ImportStagedOperation,
  type PdppImportJobCapability,
  type PdppImportJobs,
} from "./contract.js";

const JOB_ID = /^[A-Za-z0-9._:-]{1,128}$/;
const SHA256_HEX = /^[0-9a-f]{64}$/;
const encoder = new TextEncoder();

export async function sha256HexOf(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(
    await globalThis.crypto.subtle.digest(
      "SHA-256",
      bytes as Uint8Array<ArrayBuffer>,
    ),
  );
  let hex = "";
  for (const byte of digest) hex += byte.toString(16).padStart(2, "0");
  return hex;
}

/** The operation digest of the contract: SHA-256 of `canonicalJson([stream, recordKey, op, data, emittedAt])`. */
export function importOperationDigest(
  stream: string,
  recordKey: string,
  op: "upsert" | "delete",
  data: Record<string, unknown> | null,
  emittedAt: string,
): Promise<string> {
  return sha256HexOf(
    encoder.encode(canonicalJson([stream, recordKey, op, data, emittedAt])),
  );
}

function invalid(message: string): ImportJobError {
  return new ImportJobError("invalid_request", message);
}

function nonEmpty(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function count(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

/** `data.blob_ref.blob_id`, as the record stores read it. */
function blobId(data: unknown): string | undefined {
  const ref = object(data) ? data.blob_ref : undefined;
  return object(ref) && typeof ref.blob_id === "string"
    ? ref.blob_id
    : undefined;
}

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export interface PdppImportJobsOptions {
  capability: PdppImportJobCapability;
  declarations: ImportDeclarations;
  /**
   * The authenticated server owner, read on every operation. Jobs bound to
   * anyone else are refused, and so is every operation while it is empty.
   */
  owner: string | (() => string | undefined);
  now?: () => Date;
  /**
   * Required by, and only allowed with, a `native-staged-copy` adapter: the
   * exact canonical entries of one validated batch (the Lite encoder,
   * `@opendatalabs/personal-server-ts-lite/import-job`). Called once per
   * durable batch; a replayed batch answers from its receipt.
   */
  encodeBatch?: (input: {
    job: ImportJobRecord;
    seq: number;
    operations: readonly ImportStagedOperation[];
  }) => Promise<ImportCanonicalBatch>;
}

export function createPdppImportJobs(
  options: PdppImportJobsOptions,
): PdppImportJobs {
  const { capability, declarations } = options;
  if (capability.contractVersion !== PDPP_IMPORT_JOB_CONTRACT_VERSION) {
    throw new ImportJobError(
      "capability_version_mismatch",
      `import job adapter implements contract ${String(capability.contractVersion)}, engine requires ${PDPP_IMPORT_JOB_CONTRACT_VERSION}`,
    );
  }
  const nativeCopy = capability.publication?.mode === "native-staged-copy";
  if (nativeCopy !== Boolean(options.encodeBatch))
    throw invalid(
      nativeCopy
        ? "a native-staged-copy adapter needs encodeBatch"
        : "encodeBatch is only for a native-staged-copy adapter",
    );
  function currentOwner(): string {
    const value =
      typeof options.owner === "function" ? options.owner() : options.owner;
    if (!nonEmpty(value))
      throw new ImportJobError("owner_mismatch", "no server owner is bound");
    return value.toLowerCase();
  }
  const now = () => (options.now ?? (() => new Date()))().toISOString();

  // One request per job at a time. Appends are also admitted at most
  // IMPORT_JOB_MAX_IN_FLIGHT per job, queued or running (see `append`).
  const queues = new Map<string, Promise<unknown>>();
  const appendsAdmitted = new Map<unknown, number>();
  function exclusive<T>(jobId: string, step: () => Promise<T>): Promise<T> {
    const previous = queues.get(jobId) ?? Promise.resolve();
    const run = previous.then(step, step);
    const settled = run.then(
      () => undefined,
      () => undefined,
    );
    queues.set(jobId, settled);
    void settled.then(() => {
      if (queues.get(jobId) === settled) queues.delete(jobId);
    });
    return run;
  }

  async function readJob(jobId: unknown): Promise<ImportJobRecord> {
    if (typeof jobId !== "string" || !JOB_ID.test(jobId))
      throw invalid("jobId must match [A-Za-z0-9._:-]{1,128}");
    const owner = currentOwner();
    const job = await capability.readJob(jobId);
    if (!job) throw new ImportJobError("job_not_found");
    if (job.binding.owner !== owner) throw new ImportJobError("owner_mismatch");
    return job;
  }

  /** Every spool byte is in a durable batch, and the receipts chain from 0 to the end. */
  async function assertSpoolConsumed(job: ImportJobRecord): Promise<void> {
    const incomplete = () =>
      new ImportJobError(
        "spool_incomplete",
        `durable batches cover ${job.spoolOffset} of ${job.spool.byteLength} spool bytes`,
      );
    if (job.nextSeq < 1 || job.spoolOffset !== job.spool.byteLength)
      throw incomplete();
    let end = 0;
    for (let seq = 0; seq < job.nextSeq; seq++) {
      const receipt = await capability.readBatchReceipt(job.jobId, seq);
      if (!receipt || receipt.spoolStart !== end) throw incomplete();
      end = receipt.spoolEnd;
    }
    if (end !== job.spool.byteLength) throw incomplete();
  }

  function status(job: ImportJobRecord): ImportJobStatus {
    return {
      job,
      resume:
        job.state === "open"
          ? { seq: job.nextSeq, spoolOffset: job.spoolOffset }
          : null,
    };
  }

  async function assertBinding(job: {
    binding: ImportJobRecord["binding"];
  }): Promise<void> {
    const current = await capability.readBinding(job.binding.instance);
    if (
      current.deleted ||
      current.sourceId !== job.binding.sourceId ||
      current.method !== job.binding.method ||
      current.generation !== job.binding.generation
    ) {
      throw new ImportJobError(
        "binding_mismatch",
        "the connection's current source, method or generation differs from the job binding",
      );
    }
  }

  async function begin(input: ImportJobBeginInput): Promise<ImportJobStatus> {
    if (!object(input)) throw invalid("begin body must be an object");
    const { jobId, binding, spool, streams } = input;
    if (typeof jobId !== "string" || !JOB_ID.test(jobId))
      throw invalid("jobId must match [A-Za-z0-9._:-]{1,128}");
    if (
      !object(binding) ||
      !nonEmpty(binding.owner) ||
      !nonEmpty(binding.instance) ||
      !nonEmpty(binding.sourceId) ||
      !nonEmpty(binding.method) ||
      !Number.isSafeInteger(binding.generation) ||
      binding.generation < 1
    )
      throw invalid(
        "binding needs owner, instance, sourceId, method and a positive generation",
      );
    if (
      !object(spool) ||
      !nonEmpty(spool.id) ||
      spool.format !== PDPP_IMPORT_SPOOL_FORMAT ||
      !count(spool.byteLength) ||
      spool.byteLength < 1 ||
      typeof spool.sha256 !== "string" ||
      !SHA256_HEX.test(spool.sha256)
    )
      throw invalid(
        `spool needs id, format ${PDPP_IMPORT_SPOOL_FORMAT}, byteLength and sha256`,
      );
    if (
      !Array.isArray(streams) ||
      streams.length === 0 ||
      !streams.every(nonEmpty) ||
      new Set(streams).size !== streams.length
    )
      throw invalid("streams must be a nonempty list of distinct names");
    const batchBytes = input.batchBytes ?? IMPORT_JOB_DEFAULT_BATCH_BYTES;
    if (
      !Number.isSafeInteger(batchBytes) ||
      batchBytes < 1 ||
      batchBytes > IMPORT_JOB_MAX_BATCH_BYTES
    )
      throw invalid(`batchBytes must be 1..${IMPORT_JOB_MAX_BATCH_BYTES}`);
    if (binding.owner.toLowerCase() !== currentOwner())
      throw new ImportJobError("owner_mismatch");
    for (const stream of streams) {
      if (!declarations.forInstance(binding.instance, stream))
        throw new ImportJobError(
          "stream_not_declared",
          `the source of instance '${binding.instance}' does not declare stream '${stream}'`,
        );
    }
    const normalized = {
      jobId,
      binding: {
        owner: binding.owner.toLowerCase(),
        instance: binding.instance,
        sourceId: binding.sourceId,
        method: binding.method,
        generation: binding.generation,
      },
      spool: {
        id: spool.id,
        format: spool.format,
        byteLength: spool.byteLength,
        sha256: spool.sha256,
      },
      streams: [...streams].sort(),
      batchBytes,
    };
    const fingerprint = await sha256HexOf(
      encoder.encode(canonicalJson(normalized)),
    );
    return exclusive(jobId, async () => {
      const existing = await capability.readJob(jobId);
      if (existing) {
        if (existing.fingerprint !== fingerprint)
          throw new ImportJobError(
            "job_conflict",
            "a job with this id began with other input",
          );
        return status(existing);
      }
      await assertBinding(normalized);
      const at = now();
      const job: ImportJobRecord = {
        contractVersion: PDPP_IMPORT_JOB_CONTRACT_VERSION,
        ...normalized,
        fingerprint,
        state: "open",
        nextSeq: 0,
        nextOrder: 0,
        spoolOffset: 0,
        records: 0,
        rejected: 0,
        createdAt: at,
        updatedAt: at,
      };
      const stored = await capability.createJob(job);
      if (stored.fingerprint !== fingerprint)
        throw new ImportJobError(
          "job_conflict",
          "a job with this id began with other input",
        );
      return status(stored);
    });
  }

  async function append(
    batch: ImportBatchInput,
  ): Promise<ImportBatchReceipt & { replay: boolean }> {
    if (!object(batch)) throw invalid("batch must be an object");
    // Admission is decided before the first await, so a refused payload is
    // never held: IMPORT_JOB_MAX_IN_FLIGHT bounds the batch text in memory.
    const jobId = batch.jobId;
    const admitted = appendsAdmitted.get(jobId) ?? 0;
    if (admitted >= IMPORT_JOB_MAX_IN_FLIGHT)
      throw new ImportJobError(
        "job_busy",
        "another append of this job is in flight",
      );
    appendsAdmitted.set(jobId, admitted + 1);
    try {
      const job0 = await readJob(jobId);
      return await exclusive(job0.jobId, () => appendLocked(batch));
    } finally {
      const left = (appendsAdmitted.get(jobId) ?? 1) - 1;
      if (left > 0) appendsAdmitted.set(jobId, left);
      else appendsAdmitted.delete(jobId);
    }
  }

  async function appendLocked(
    batch: ImportBatchInput,
  ): Promise<ImportBatchReceipt & { replay: boolean }> {
    const job = await readJob(batch.jobId);
    const { seq, text, sha256, spoolStart, spoolEnd } = batch;
    if (
      !count(seq) ||
      typeof text !== "string" ||
      typeof sha256 !== "string" ||
      !SHA256_HEX.test(sha256) ||
      !count(spoolStart) ||
      !count(spoolEnd)
    )
      throw invalid("batch needs seq, text, sha256, spoolStart and spoolEnd");
    if (seq < job.nextSeq) {
      const stored = await capability.readBatchReceipt(job.jobId, seq);
      if (
        stored &&
        stored.sha256 === sha256 &&
        stored.spoolStart === spoolStart &&
        stored.spoolEnd === spoolEnd
      )
        return { ...stored, replay: true };
      throw new ImportJobError(
        "batch_conflict",
        `batch ${seq} is already stored with other content`,
      );
    }
    if (job.state !== "open") throw new ImportJobError("job_not_open");
    if (seq > job.nextSeq)
      throw new ImportJobError(
        "batch_out_of_order",
        `expected batch ${job.nextSeq}, got ${seq}`,
      );
    const bytes = encoder.encode(text);
    if (
      spoolStart !== job.spoolOffset ||
      spoolEnd - spoolStart !== bytes.byteLength ||
      spoolEnd > job.spool.byteLength ||
      bytes.byteLength === 0
    )
      throw new ImportJobError(
        "spool_offset_mismatch",
        `batch must cover spool bytes from ${job.spoolOffset}, ${bytes.byteLength} bytes`,
      );
    const lines = text.split("\n");
    // Whole lines only; the spool's last line may lack its newline.
    if (lines[lines.length - 1] === "") lines.pop();
    else if (spoolEnd !== job.spool.byteLength)
      throw invalid("a batch must end at a line break");
    if (bytes.byteLength > job.batchBytes) {
      if (lines.length !== 1)
        throw new ImportJobError(
          "batch_too_large",
          `batch is ${bytes.byteLength} bytes; the budget is ${job.batchBytes}`,
        );
      if (bytes.byteLength > IMPORT_JOB_MAX_RECORD_BYTES)
        throw new ImportJobError(
          "record_too_large",
          `one record is ${bytes.byteLength} bytes; the limit is ${IMPORT_JOB_MAX_RECORD_BYTES}`,
        );
    }
    if ((await sha256HexOf(bytes)) !== sha256)
      throw new ImportJobError("batch_digest_mismatch");

    const instance = job.binding.instance;
    const operations: ImportStagedOperation[] = [];
    const rejected: ImportRejection[] = [];
    let rejectedCount = 0;
    const reject = (line: number, reason: string) => {
      rejectedCount += 1;
      if (rejected.length < IMPORT_JOB_MAX_LISTED_REJECTIONS)
        rejected.push({ line, reason });
    };
    const allowed = new Set(job.streams);
    for (let line = 0; line < lines.length; line++) {
      let record: unknown;
      try {
        record = JSON.parse(lines[line]);
      } catch {
        reject(line, "invalid_json");
        continue;
      }
      if (!object(record)) {
        reject(line, "record must be a JSON object");
        continue;
      }
      // A record of another connection refuses the whole batch: it is never
      // this job's to decide.
      if (record.instance !== undefined && record.instance !== instance)
        throw invalid(`line ${line} names another instance`);
      const stream = record.stream;
      if (typeof stream !== "string" || !allowed.has(stream)) {
        reject(line, "stream_not_in_job");
        continue;
      }
      const declaration = declarations.forInstance(instance, stream);
      if (!declaration) {
        reject(line, "stream_not_declared");
        continue;
      }
      const envelope: PdppRecordEnvelopeInput = {
        instance,
        stream,
        key: record.key as PdppRecordEnvelopeInput["key"],
        data: (record.data ?? null) as PdppRecordEnvelopeInput["data"],
        emitted_at: record.emitted_at as string,
        op: record.op as PdppRecordEnvelopeInput["op"],
      };
      // Validation only: state-dependent outcomes are decided at publication.
      const plan = planIngest(
        line,
        envelope,
        declaration.semantics,
        declaration.primaryKey,
        () => undefined,
        declarations.validateData,
      );
      if (plan.outcome.outcome === "rejected") {
        reject(line, plan.outcome.reason);
        continue;
      }
      const op = envelope.op === "delete" ? "delete" : "upsert";
      const recordKey = encodeRecordKey(envelope.key);
      const data = op === "upsert" ? envelope.data : null;
      // A blob claim is checked against the store at publication, after the
      // index kept only the latest operation of the key, so a rejected edit
      // would drop an earlier valid version. Version 1 stages no blobs.
      if (blobId(data))
        throw new ImportJobError(
          "blob_ref_unsupported",
          `line ${line} references a blob; import jobs do not stage blobs`,
        );
      operations.push({
        order: job.nextOrder + operations.length,
        stream,
        recordKey,
        keyJson: JSON.stringify(envelope.key),
        op,
        dataJson: data === null ? null : JSON.stringify(data),
        emittedAt: envelope.emitted_at,
        keep: declaration.semantics === "append_only" ? "first" : "last",
        digest: await importOperationDigest(
          stream,
          recordKey,
          op,
          data,
          envelope.emitted_at,
        ),
      });
    }
    const receipt: ImportBatchReceipt = {
      jobId: job.jobId,
      seq,
      sha256,
      spoolStart,
      spoolEnd,
      records: lines.length,
      staged: operations.length,
      rejectedCount,
      rejected,
      firstOrder: job.nextOrder,
    };
    const next: ImportJobRecord = {
      ...job,
      nextSeq: seq + 1,
      nextOrder: job.nextOrder + operations.length,
      spoolOffset: spoolEnd,
      records: job.records + lines.length,
      rejected: job.rejected + rejectedCount,
      updatedAt: now(),
    };
    const stored = await capability.stageBatch({
      job: next,
      receipt,
      operations,
      ...(options.encodeBatch
        ? { canonical: await options.encodeBatch({ job, seq, operations }) }
        : {}),
    });
    if (stored.sha256 !== sha256)
      throw new ImportJobError(
        "batch_conflict",
        `batch ${seq} is already stored with other content`,
      );
    return { ...stored, replay: false };
  }

  async function commit(
    input: ImportCommitInput,
  ): Promise<ImportCommitReceipt> {
    if (!object(input)) throw invalid("commit body must be an object");
    const job0 = await readJob(input.jobId);
    return exclusive(job0.jobId, async () => {
      const job = await readJob(input.jobId);
      if (job.state === "committed" && job.commit) return job.commit;
      if (job.state !== "open") throw new ImportJobError("job_not_open");
      if (!count(input.batches) || input.batches !== job.nextSeq)
        throw new ImportJobError(
          "batch_count_mismatch",
          `the job holds ${job.nextSeq} durable batches`,
        );
      await assertSpoolConsumed(job);
      let connectorStateSha256: string | null = null;
      if (input.connectorState !== undefined) {
        if (typeof input.connectorState !== "string")
          throw invalid("connectorState must be JSON text");
        const bytes = encoder.encode(input.connectorState);
        if (bytes.byteLength > IMPORT_JOB_MAX_CONNECTOR_STATE_BYTES)
          throw new ImportJobError("state_too_large");
        try {
          JSON.parse(input.connectorState);
        } catch {
          throw invalid("connectorState must be JSON text");
        }
        connectorStateSha256 = await sha256HexOf(bytes);
      }
      const completion = input.completion;
      if (completion !== undefined) {
        const message =
          "completion needs sourceCollectedAt and distinct full_stream proofs for job streams";
        if (!object(completion)) throw invalid(message);
        // The store's own shape rules, so every adapter refuses what it refuses.
        try {
          parseCompletionRequest({
            ...job.binding,
            sourceCollectedAt: completion.sourceCollectedAt,
            collectionTimeBasis: "host_run_finished",
            streams: completion.streams,
          });
        } catch (error) {
          if (error instanceof StreamCompletionError) throw invalid(message);
          throw error;
        }
        if (
          !completion.streams.every((proof) =>
            job.streams.includes(proof.stream),
          )
        )
          throw invalid(message);
      }
      await assertBinding(job);
      return capability.publish({
        job,
        ...(input.connectorState === undefined
          ? {}
          : { connectorState: input.connectorState }),
        connectorStateSha256,
        ...(completion === undefined ? {} : { completion }),
        committedAt: now(),
        declarations,
      });
    });
  }

  async function abort(
    jobId: string,
    reason = "aborted",
  ): Promise<ImportJobStatus> {
    const job0 = await readJob(jobId);
    return exclusive(job0.jobId, async () => {
      const job = await readJob(jobId);
      if (job.state !== "open") return status(job);
      const aborted = await capability.abort(jobId, String(reason), now());
      return status(aborted ?? (await readJob(jobId)));
    });
  }

  return {
    begin,
    append,
    status: async (jobId) => status(await readJob(jobId)),
    commit,
    abort,
    async connectorState(instance) {
      const owner = currentOwner();
      const state = await capability.readConnectorState(instance);
      if (!state) return undefined;
      const job = await capability.readJob(state.jobId);
      if (!job || job.binding.owner !== owner)
        throw new ImportJobError("owner_mismatch");
      // A reset or deletion erased what this cursor describes; an adapter
      // that has not erased it yet must not hand it out.
      const binding = await capability.readBinding(instance);
      if (binding.deleted || binding.generation !== state.generation)
        return undefined;
      return state;
    },
  };
}
