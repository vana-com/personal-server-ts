import { describe, expect, it } from "vitest";
import { createMemoryRecordStore } from "../pdpp-records/memory-store.js";
import { liveSnapshotDigestAsync } from "../pdpp-records/completion.js";
import { encodeRecordKey } from "../pdpp-records/record-key.js";
import {
  IMPORT_JOB_MAX_RECORD_BYTES,
  ImportJobError,
  type ImportJobBeginInput,
  type ImportSpoolRecord,
} from "./contract.js";
import { createPdppImportJobs, sha256HexOf } from "./engine.js";
import {
  createMemoryImportJobCapability,
  type MemoryImportFaultPoint,
} from "./memory.js";
import { importSpool } from "./spool.js";
import {
  IMPORT_VECTOR_INSTANCE as INSTANCE,
  IMPORT_VECTOR_METHOD as METHOD,
  IMPORT_VECTOR_OWNER as OWNER,
  IMPORT_VECTOR_SOURCE as SOURCE,
  buildImportSpool,
  importVectorDeclarations as declarations,
  importVectorRecords,
} from "./vectors.js";

const STREAMS = ["conversations", "events", "messages"];

async function setup(
  records: readonly unknown[] = importVectorRecords(),
  options: {
    replication?: boolean;
    batchBytes?: number;
    faults?: Map<MemoryImportFaultPoint, number>;
  } = {},
) {
  const spool = await buildImportSpool(records);
  const faults = options.faults ?? new Map<MemoryImportFaultPoint, number>();
  const capability = createMemoryImportJobCapability({
    replication: options.replication,
    spools: new Map([[spool.handle.id, spool.bytes]]),
    fault: (point) => {
      const remaining = faults.get(point);
      if (remaining === undefined) return;
      if (remaining === 0) {
        faults.delete(point);
        throw new Error(`fault ${point}`);
      }
      faults.set(point, remaining - 1);
    },
  });
  capability.registerConnection({
    instance: INSTANCE,
    sourceId: SOURCE,
    method: METHOD,
  });
  const begin: ImportJobBeginInput = {
    jobId: "job-1",
    binding: {
      owner: OWNER,
      instance: INSTANCE,
      sourceId: SOURCE,
      method: METHOD,
      generation: 1,
    },
    spool: spool.handle,
    streams: STREAMS,
    batchBytes: options.batchBytes ?? 256,
  };
  /** A fresh engine over the same durable adapter: a process restart. */
  const engine = () =>
    createPdppImportJobs({ capability, declarations, owner: OWNER });
  return { capability, spool, begin, engine, faults };
}

/** Line-by-line ingest of every record through the existing store: the oracle. */
function oracleLive(records: readonly ImportSpoolRecord[]) {
  const store = createMemoryRecordStore();
  store.ingestBatch(
    records.map((record) => ({
      instance: INSTANCE,
      stream: record.stream,
      key: record.key,
      data: record.data ?? null,
      emitted_at: record.emitted_at,
      op: record.op ?? null,
    })),
    (stream) => declarations.forInstance(INSTANCE, stream)!.semantics,
    (stream) => declarations.forInstance(INSTANCE, stream)!.primaryKey,
    undefined,
    declarations.validateData,
  );
  const live: Record<string, unknown> = {};
  for (const record of records) {
    const recordKey = encodeRecordKey(record.key);
    const row = store.getRecord(INSTANCE, record.stream, recordKey);
    if (row) live[`${record.stream}/${recordKey}`] = row.data;
  }
  return live;
}

function adapterLive(
  capability: ReturnType<typeof createMemoryImportJobCapability>,
) {
  const live: Record<string, unknown> = {};
  for (const stream of STREAMS)
    for (const row of capability.rows(INSTANCE, stream))
      if (!row.deleted) live[`${stream}/${row.recordKey}`] = row.data;
  return live;
}

describe("PDPP import job engine (in-memory adapter)", () => {
  it("publishes the same live set as line-by-line ingest", async () => {
    const { capability, begin, engine } = await setup();
    const jobs = engine();
    await jobs.begin(begin);
    const status = await importSpool(jobs, "job-1", capability.readSpool!);
    expect(status.resume?.spoolOffset).toBe(begin.spool.byteLength);
    expect(adapterLive(capability)).toEqual({});
    const receipt = await jobs.commit({
      jobId: "job-1",
      batches: status.job.nextSeq,
      connectorState: '{"cursor":"c2"}',
    });
    expect(adapterLive(capability)).toEqual(oracleLive(importVectorRecords()));
    expect(receipt).toMatchObject({
      records: 10,
      rejected: 1,
      operations: 6,
      connectorStateSha256: await sha256HexOf(
        new TextEncoder().encode('{"cursor":"c2"}'),
      ),
    });
    // append_only: the first write stands.
    expect(capability.rows(INSTANCE, "events")[0].data).toEqual({
      id: "e1",
      kind: "first",
    });
    expect((await jobs.connectorState(INSTANCE))?.state).toBe(
      '{"cursor":"c2"}',
    );
  });

  it("answers a replayed batch from its durable receipt and refuses conflicts and gaps", async () => {
    const { capability, begin, engine, spool } = await setup();
    const jobs = engine();
    await jobs.begin(begin);
    const firstLineEnd = spool.bytes.indexOf(0x0a) + 1;
    const line = spool.bytes.subarray(0, firstLineEnd);
    const batch = {
      jobId: "job-1",
      seq: 0,
      text: new TextDecoder().decode(line),
      sha256: await sha256HexOf(line),
      spoolStart: 0,
      spoolEnd: firstLineEnd,
    };
    const first = await jobs.append(batch);
    const again = await jobs.append(batch);
    expect(first.replay).toBe(false);
    expect(again).toEqual({ ...first, replay: true });
    expect(capability.stagedCount("job-1")).toBe(1);
    await expect(
      jobs.append({ ...batch, sha256: "0".repeat(64) }),
    ).rejects.toMatchObject({ code: "batch_conflict" });
    await expect(
      jobs.append({ ...batch, seq: 2, spoolStart: firstLineEnd }),
    ).rejects.toMatchObject({ code: "batch_out_of_order" });
    await expect(
      jobs.append({ ...batch, seq: 1, spoolStart: 0 }),
    ).rejects.toMatchObject({ code: "spool_offset_mismatch" });
    await expect(
      jobs.append({
        ...batch,
        seq: 1,
        sha256: "0".repeat(64),
        spoolStart: firstLineEnd,
        spoolEnd: firstLineEnd * 2,
      }),
    ).rejects.toMatchObject({ code: "batch_digest_mismatch" });
  });

  const points: MemoryImportFaultPoint[] = [
    "stage:before-commit",
    "stage:after-commit",
    "publish:before-commit",
    "publish:after-commit",
  ];
  for (const point of points) {
    it(`recovers from a crash at ${point} on every occurrence without duplicates or an early cursor`, async () => {
      const probe = await setup();
      const probeJobs = probe.engine();
      await probeJobs.begin(probe.begin);
      const batches = (
        await importSpool(probeJobs, "job-1", probe.capability.readSpool!)
      ).job.nextSeq;
      expect(batches).toBeGreaterThan(3);
      const occurrences = point.startsWith("stage") ? batches : 1;
      for (let n = 0; n < occurrences; n++) {
        const { capability, begin, engine } = await setup(
          importVectorRecords(),
          { replication: true, faults: new Map([[point, n]]) },
        );
        let jobs = engine();
        await jobs.begin(begin);
        let crashed = false;
        try {
          await importSpool(jobs, "job-1", capability.readSpool!);
          await jobs.commit({
            jobId: "job-1",
            batches,
            connectorState: '{"cursor":"end"}',
          });
        } catch (error) {
          crashed = true;
          expect(String(error)).toContain(`fault ${point}`);
        }
        expect(crashed).toBe(true);
        // Before a successful publication nothing is visible and no cursor exists.
        if (point !== "publish:after-commit") {
          expect(adapterLive(capability)).toEqual({});
          expect(await capability.readConnectorState(INSTANCE)).toBeUndefined();
          expect(capability.outbox()).toEqual([]);
        }
        // Restart: a new engine resumes from the durable batch.
        jobs = engine();
        const status = await jobs.status("job-1");
        if (point.startsWith("stage")) {
          expect(status.resume?.seq).toBe(
            point === "stage:after-commit" ? n + 1 : n,
          );
        }
        const resumed = await importSpool(jobs, "job-1", capability.readSpool!);
        const receipt = await jobs.commit({
          jobId: "job-1",
          batches: resumed.job.nextSeq,
          connectorState: '{"cursor":"end"}',
        });
        expect(resumed.job.nextSeq).toBe(batches);
        expect(receipt.records).toBe(10);
        expect(adapterLive(capability)).toEqual(
          oracleLive(importVectorRecords()),
        );
        // One published version per key: no duplicate rows from a retry.
        const versions = capability
          .history()
          .map((row) => `${row.stream}/${row.recordKey}`);
        expect(new Set(versions).size).toBe(versions.length);
        expect(capability.outbox()).toHaveLength(versions.length);
        expect((await jobs.connectorState(INSTANCE))?.state).toBe(
          '{"cursor":"end"}',
        );
      }
    });
  }

  it("abort leaves nothing visible and refuses later appends and commits", async () => {
    const { capability, begin, engine } = await setup();
    const jobs = engine();
    await jobs.begin(begin);
    const status = await importSpool(jobs, "job-1", capability.readSpool!);
    expect(capability.stagedCount("job-1")).toBeGreaterThan(0);
    const aborted = await jobs.abort("job-1", "user_cancelled");
    expect(aborted).toMatchObject({
      resume: null,
      job: { state: "aborted", abortReason: "user_cancelled" },
    });
    expect(capability.stagedCount("job-1")).toBe(0);
    expect(adapterLive(capability)).toEqual({});
    await expect(
      jobs.commit({ jobId: "job-1", batches: status.job.nextSeq }),
    ).rejects.toMatchObject({ code: "job_not_open" });
    expect(await capability.readConnectorState(INSTANCE)).toBeUndefined();
  });

  it("a connection reset during the run makes the job unpublishable", async () => {
    const { capability, begin, engine } = await setup();
    const jobs = engine();
    await jobs.begin(begin);
    const status = await importSpool(jobs, "job-1", capability.readSpool!);
    capability.resetConnection(INSTANCE);
    await expect(
      jobs.commit({ jobId: "job-1", batches: status.job.nextSeq }),
    ).rejects.toMatchObject({ code: "binding_mismatch" });
    expect(adapterLive(capability)).toEqual({});
    // A new job of the new generation is a separate binding.
    await expect(jobs.begin(begin)).resolves.toBeDefined();
    await expect(
      jobs.begin({ ...begin, jobId: "job-2" }),
    ).rejects.toMatchObject({ code: "binding_mismatch" });
  });

  it("refuses a short commit, another owner, an undeclared stream and a changed retry", async () => {
    const { capability, begin, engine } = await setup();
    const jobs = engine();
    await expect(
      jobs.begin({ ...begin, binding: { ...begin.binding, owner: "0xother" } }),
    ).rejects.toMatchObject({ code: "owner_mismatch" });
    await expect(
      jobs.begin({ ...begin, streams: ["messages", "secrets"] }),
    ).rejects.toMatchObject({ code: "stream_not_declared" });
    await jobs.begin(begin);
    await expect(
      jobs.begin({ ...begin, batchBytes: 512 }),
    ).rejects.toMatchObject({ code: "job_conflict" });
    const status = await importSpool(jobs, "job-1", capability.readSpool!);
    await expect(
      jobs.commit({ jobId: "job-1", batches: status.job.nextSeq - 1 }),
    ).rejects.toMatchObject({ code: "batch_count_mismatch" });
  });

  it("never publishes a zero-batch or prefix-only job", async () => {
    const { capability, begin, engine, spool } = await setup();
    const jobs = engine();
    await expect(
      jobs.begin({
        ...begin,
        jobId: "empty",
        spool: { ...begin.spool, byteLength: 0 },
      }),
    ).rejects.toMatchObject({ code: "invalid_request" });
    await jobs.begin(begin);
    const completion = {
      sourceCollectedAt: "2026-10-28T00:00:00.000Z",
      streams: [
        {
          stream: "events",
          liveRecordCount: 0,
          liveSnapshotDigest: `sha256:${"0".repeat(64)}`,
        },
      ],
    };
    await expect(
      jobs.commit({
        jobId: "job-1",
        batches: 0,
        connectorState: '{"cursor":"end"}',
        completion,
      }),
    ).rejects.toMatchObject({ code: "spool_incomplete" });
    const firstLineEnd = spool.bytes.indexOf(0x0a) + 1;
    const line = spool.bytes.subarray(0, firstLineEnd);
    await jobs.append({
      jobId: "job-1",
      seq: 0,
      text: new TextDecoder().decode(line),
      sha256: await sha256HexOf(line),
      spoolStart: 0,
      spoolEnd: firstLineEnd,
    });
    await expect(
      jobs.commit({
        jobId: "job-1",
        batches: 1,
        connectorState: '{"cursor":"end"}',
      }),
    ).rejects.toMatchObject({ code: "spool_incomplete" });
    // The adapter refuses a prefix job too, whoever calls it.
    const job = (await jobs.status("job-1")).job;
    await expect(
      capability.publish({
        job,
        connectorState: '{"cursor":"end"}',
        connectorStateSha256: null,
        committedAt: "2026-10-28T00:00:00.000Z",
        declarations,
      }),
    ).rejects.toMatchObject({ code: "spool_incomplete" });
    expect(await jobs.connectorState(INSTANCE)).toBeUndefined();
    expect(adapterLive(capability)).toEqual({});
    expect(capability.completion(INSTANCE, "events")).toBeUndefined();
    expect((await jobs.status("job-1")).job.state).toBe("open");
  });

  it("checks the job's stored owner on every operation and refuses an empty owner", async () => {
    const { capability, begin, engine, spool } = await setup();
    const jobs = engine();
    await jobs.begin(begin);
    const firstLineEnd = spool.bytes.indexOf(0x0a) + 1;
    const line = spool.bytes.subarray(0, firstLineEnd);
    const batch = {
      jobId: "job-1",
      seq: 0,
      text: new TextDecoder().decode(line),
      sha256: await sha256HexOf(line),
      spoolStart: 0,
      spoolEnd: firstLineEnd,
    };
    const other = createPdppImportJobs({
      capability,
      declarations,
      owner: "0xother",
    });
    const missing = createPdppImportJobs({
      capability,
      declarations,
      owner: () => undefined,
    });
    const empty = createPdppImportJobs({ capability, declarations, owner: "" });
    for (const stranger of [other, missing, empty]) {
      await expect(stranger.append(batch)).rejects.toMatchObject({
        code: "owner_mismatch",
      });
      await expect(stranger.status("job-1")).rejects.toMatchObject({
        code: "owner_mismatch",
      });
      await expect(
        stranger.commit({ jobId: "job-1", batches: 0 }),
      ).rejects.toMatchObject({ code: "owner_mismatch" });
      await expect(stranger.abort("job-1")).rejects.toMatchObject({
        code: "owner_mismatch",
      });
    }
    for (const unbound of [missing, empty])
      await expect(unbound.begin(begin)).rejects.toMatchObject({
        code: "owner_mismatch",
      });
    expect((await jobs.status("job-1")).job.state).toBe("open");
    expect(capability.stagedCount("job-1")).toBe(0);

    const status = await importSpool(jobs, "job-1", capability.readSpool!);
    await jobs.commit({
      jobId: "job-1",
      batches: status.job.nextSeq,
      connectorState: '{"cursor":"end"}',
    });
    expect((await jobs.connectorState(INSTANCE))?.state).toBe(
      '{"cursor":"end"}',
    );
    for (const stranger of [other, missing, empty])
      await expect(stranger.connectorState(INSTANCE)).rejects.toMatchObject({
        code: "owner_mismatch",
      });
  });

  it("holds at most one append payload per job and refuses the rest as busy", async () => {
    const { capability, begin, spool } = await setup();
    let release!: () => void;
    const gate = new Promise<void>((resolve) => (release = resolve));
    let held = 0;
    const gated = {
      ...capability,
      stageBatch: async (
        input: Parameters<typeof capability.stageBatch>[0],
      ) => {
        held++;
        await gate;
        return capability.stageBatch(input);
      },
    };
    const jobs = createPdppImportJobs({
      capability: gated,
      declarations,
      owner: OWNER,
    });
    await jobs.begin(begin);
    const firstLineEnd = spool.bytes.indexOf(0x0a) + 1;
    const line = spool.bytes.subarray(0, firstLineEnd);
    const batch = {
      jobId: "job-1",
      seq: 0,
      text: new TextDecoder().decode(line),
      sha256: await sha256HexOf(line),
      spoolStart: 0,
      spoolEnd: firstLineEnd,
    };
    const first = jobs.append(batch);
    const extra = Array.from({ length: 32 }, () => jobs.append(batch));
    const outcomes = await Promise.allSettled(extra);
    expect(outcomes.every((o) => o.status === "rejected")).toBe(true);
    for (const outcome of outcomes)
      expect((outcome as PromiseRejectedResult).reason).toMatchObject({
        code: "job_busy",
      });
    while (held === 0) await new Promise((resolve) => setImmediate(resolve));
    expect(held).toBe(1);
    await expect(jobs.append(batch)).rejects.toMatchObject({
      code: "job_busy",
    });
    release();
    expect((await first).replay).toBe(false);
    // The slot frees once the held append settles; a retry is then admitted.
    expect(await jobs.append(batch)).toMatchObject({ replay: true });
  });

  it("stages encoded canonical entries with each batch for a native staged copy", async () => {
    const { capability, begin, spool } = await setup();
    const native = {
      ...capability,
      publication: {
        mode: "native-staged-copy",
        outbox: "by-reference",
      } as const,
    };
    expect(() =>
      createPdppImportJobs({ capability: native, declarations, owner: OWNER }),
    ).toThrow(expect.objectContaining({ code: "invalid_request" }));
    expect(() =>
      createPdppImportJobs({
        capability,
        declarations,
        owner: OWNER,
        encodeBatch: async () => ({ entries: [] }),
      }),
    ).toThrow(expect.objectContaining({ code: "invalid_request" }));

    const encoded: number[] = [];
    const staged: unknown[] = [];
    const jobs = createPdppImportJobs({
      capability: {
        ...native,
        stageBatch: (input) => {
          staged.push(input.canonical);
          return capability.stageBatch(input);
        },
      },
      declarations,
      owner: OWNER,
      encodeBatch: async ({ seq, operations }) => {
        encoded.push(seq);
        return {
          entries: operations.map((op) => ({
            key: `rows/${op.recordKey}`,
            value: op.dataJson,
          })),
        };
      },
    });
    await jobs.begin(begin);
    const firstLineEnd = spool.bytes.indexOf(0x0a) + 1;
    const line = spool.bytes.subarray(0, firstLineEnd);
    const batch = {
      jobId: "job-1",
      seq: 0,
      text: new TextDecoder().decode(line),
      sha256: await sha256HexOf(line),
      spoolStart: 0,
      spoolEnd: firstLineEnd,
    };
    await jobs.append(batch);
    await jobs.append(batch);
    // A replay answers from the durable receipt; it never re-encodes.
    expect(encoded).toEqual([0]);
    expect(staged).toEqual([
      { entries: [expect.objectContaining({ key: expect.any(String) })] },
    ]);
  });

  it("refuses an adapter of another contract version", () => {
    const capability = createMemoryImportJobCapability({ contractVersion: 2 });
    expect(() =>
      createPdppImportJobs({ capability, declarations, owner: OWNER }),
    ).toThrow(ImportJobError);
  });

  it("captures replication with publication only when enabled", async () => {
    for (const replication of [true, false]) {
      const { capability, begin, engine } = await setup(importVectorRecords(), {
        replication,
      });
      const jobs = engine();
      await jobs.begin(begin);
      const status = await importSpool(jobs, "job-1", capability.readSpool!);
      expect(capability.outbox()).toEqual([]);
      const receipt = await jobs.commit({
        jobId: "job-1",
        batches: status.job.nextSeq,
      });
      expect(capability.outbox()).toHaveLength(
        replication ? receipt.accepted : 0,
      );
    }
  });

  it("stores a completion receipt only when the proof matches, atomically", async () => {
    const at = "2026-10-28T12:00:00.000Z";
    const records = importVectorRecords().filter(
      (record) => record.stream === "conversations",
    );
    const rows = records.map((record) => ({
      recordKey: encodeRecordKey(record.key),
      dataJson: JSON.stringify(record.data),
    }));
    const snapshotSha256 = await liveSnapshotDigestAsync(
      {
        sourceId: SOURCE,
        instance: INSTANCE,
        method: METHOD,
        generation: 1,
        stream: "conversations",
      },
      ["id"],
      rows,
    );
    for (const proof of [
      { liveCount: 2, snapshotSha256 },
      { liveCount: 2, snapshotSha256: "f".repeat(64) },
    ]) {
      const { capability, begin, engine } = await setup();
      const jobs = engine();
      await jobs.begin(begin);
      const status = await importSpool(jobs, "job-1", capability.readSpool!);
      const commit = jobs.commit({
        jobId: "job-1",
        batches: status.job.nextSeq,
        connectorState: "{}",
        completion: {
          sourceCollectedAt: at,
          streams: [
            { stream: "conversations", coverage: "full_stream", ...proof },
          ],
        },
      });
      if (proof.snapshotSha256 === snapshotSha256) {
        expect((await commit).completedStreams).toEqual(["conversations"]);
        expect(capability.completion(INSTANCE, "conversations")).toMatchObject({
          liveCount: 2,
          sourceCollectedAt: at,
        });
      } else {
        await expect(commit).rejects.toMatchObject({
          code: "completion_failed",
        });
        expect(adapterLive(capability)).toEqual({});
        expect(await capability.readConnectorState(INSTANCE)).toBeUndefined();
      }
    }
  });

  it("takes one record over the batch budget alone and refuses one over the record limit", async () => {
    const big = {
      stream: "messages",
      key: "big",
      data: { id: "big", text: "é".repeat(4096) },
      emitted_at: "2026-10-28T00:00:00.000Z",
    };
    const { capability, begin, engine } = await setup([
      importVectorRecords()[0],
      big,
      importVectorRecords()[9],
    ]);
    const jobs = engine();
    await jobs.begin(begin);
    const sizes: number[] = [];
    const status = await importSpool(jobs, "job-1", capability.readSpool!, {
      onBatch: (receipt) => sizes.push(receipt.spoolEnd - receipt.spoolStart),
    });
    expect(sizes.some((size) => size > 256)).toBe(true);
    await jobs.commit({ jobId: "job-1", batches: status.job.nextSeq });
    expect(capability.rows(INSTANCE, "messages")[0].data).toEqual(big.data);

    const huge = await setup([big], { batchBytes: 256 });
    const hugeJobs = huge.engine();
    await hugeJobs.begin(huge.begin);
    await expect(
      importSpool(hugeJobs, "job-1", huge.capability.readSpool!, {
        maxRecordBytes: 1024,
      }),
    ).rejects.toMatchObject({ code: "record_too_large" });
    expect(IMPORT_JOB_MAX_RECORD_BYTES).toBe(16 * 1024 * 1024);
  });

  it("refuses a blob reference, whose claim check would run after the index collapses", async () => {
    // Line-by-line ingest keeps "first" when the edit's blob is unclaimed;
    // the index would keep only the edit and then reject it at publication.
    const [first, edit] = importVectorRecords().filter(
      (record) => record.key === "m2",
    );
    const { capability, begin, engine } = await setup([
      first!,
      {
        ...edit!,
        data: { ...edit!.data, blob_ref: { blob_id: "blob-unclaimed" } },
      },
    ]);
    const jobs = engine();
    await jobs.begin(begin);
    await expect(
      importSpool(jobs, "job-1", capability.readSpool!),
    ).rejects.toMatchObject({ code: "blob_ref_unsupported" });
    // The refused batch stages nothing, and the job cannot publish past it.
    const status = await jobs.status("job-1");
    expect(status.job.state).toBe("open");
    expect(status.job.nextSeq).toBe(1);
    expect(capability.stagedCount("job-1")).toBe(1);
    await expect(
      jobs.commit({ jobId: "job-1", batches: 1, connectorState: "{}" }),
    ).rejects.toMatchObject({ code: "spool_incomplete" });
    expect(await capability.readConnectorState(INSTANCE)).toBeUndefined();
  });

  it("refuses a batch that names another instance", async () => {
    const { capability, begin, engine } = await setup([
      { ...importVectorRecords()[0], instance: "someone-else" },
    ]);
    const jobs = engine();
    await jobs.begin(begin);
    await expect(
      importSpool(jobs, "job-1", capability.readSpool!),
    ).rejects.toMatchObject({ code: "invalid_request" });
    expect(capability.stagedCount("job-1")).toBe(0);
  });
});
