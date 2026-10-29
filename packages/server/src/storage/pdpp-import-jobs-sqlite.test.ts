import Database from "better-sqlite3";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  createPdppImportJobs,
  importSpool,
  importVectorDeclarations,
  importVectorRecords,
  buildImportSpool,
  IMPORT_VECTOR_INSTANCE as INSTANCE,
  IMPORT_VECTOR_METHOD as METHOD,
  IMPORT_VECTOR_OWNER as OWNER,
  IMPORT_VECTOR_SOURCE as SOURCE,
  type ImportDeclarations,
  type ImportJobBeginInput,
  type ImportSpoolRecord,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-import-job";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import { createReplicaRecordStore } from "./pdpp-replica-canonical-port.js";
import {
  createSqliteImportJobCapability,
  type SqliteImportFaultPoint,
} from "./pdpp-import-jobs-sqlite.js";

const STREAMS = ["conversations", "events", "messages"];

/** Declarations carrying the retained bindings replication checks writes against. */
const bindingOf = (stream: string) => {
  const declaration = importVectorDeclarations.forInstance(INSTANCE, stream)!;
  return {
    digest: `sha256:${"a".repeat(64)}`,
    version: "1",
    stream,
    semantics: declaration.semantics,
    primaryKey: declaration.primaryKey,
    schemaDigest: `sha256:${"b".repeat(64)}`,
  };
};
const declarations: ImportDeclarations = {
  forInstance: (instance, stream) => {
    const declaration = importVectorDeclarations.forInstance(instance, stream);
    return declaration && { ...declaration, binding: bindingOf(stream) };
  },
  validateData: importVectorDeclarations.validateData,
};

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "pdpp-import-job-"));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function openStore(
  path: string,
  options: {
    replication?: boolean;
    fault?: (point: SqliteImportFaultPoint) => void;
  } = {},
) {
  const db = new Database(path);
  const store = options.replication
    ? createReplicaRecordStore(db)
    : createSqliteRecordStore(db);
  const capability = createSqliteImportJobCapability(db, store, {
    pageSize: 3,
    spoolPath: (spool) => join(dir, `${spool.id}.ndjson`),
    fault: options.fault,
  });
  const jobs = createPdppImportJobs({ capability, declarations, owner: OWNER });
  return { db, store, capability, jobs };
}

async function prepare(
  records: readonly unknown[] = importVectorRecords(),
  options: { replication?: boolean } = {},
) {
  const path = join(dir, "records.db");
  const spool = await buildImportSpool(records);
  writeFileSync(join(dir, `${spool.handle.id}.ndjson`), spool.bytes);
  const opened = openStore(path, options);
  opened.store.registerConnection({
    instance: INSTANCE,
    sourceId: SOURCE,
    method: METHOD,
    label: "ChatGPT",
  });
  if (options.replication && "replication" in opened.store)
    opened.store.replication.beginBaseline({
      owner: OWNER,
      declarations: STREAMS.map((stream) => ({
        sourceId: SOURCE,
        binding: bindingOf(stream),
      })),
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
    batchBytes: 256,
  };
  return { ...opened, path, spool, begin };
}

/** Line-by-line ingest of every record into a fresh store: the oracle. */
function oracleLive(records: readonly ImportSpoolRecord[]) {
  const db = new Database(":memory:");
  const store = createSqliteRecordStore(db);
  store.registerConnection({
    instance: INSTANCE,
    sourceId: SOURCE,
    method: METHOD,
    label: "oracle",
  });
  for (const record of records)
    store.ingestBatch(
      [
        {
          instance: INSTANCE,
          stream: record.stream,
          key: record.key,
          data: record.data ?? null,
          emitted_at: record.emitted_at,
          op: record.op ?? null,
        },
      ],
      (stream) => declarations.forInstance(INSTANCE, stream)!.semantics,
      (stream) => declarations.forInstance(INSTANCE, stream)!.primaryKey,
      { method: METHOD, generation: 1 },
      declarations.validateData,
    );
  const live = liveOf(store, records);
  db.close();
  return live;
}

function liveOf(
  store: Pick<ReturnType<typeof createSqliteRecordStore>, "getRecord">,
  records: readonly ImportSpoolRecord[],
) {
  const live: Record<string, unknown> = {};
  for (const record of records) {
    const recordKey =
      typeof record.key === "string" ? record.key : JSON.stringify(record.key);
    const row = store.getRecord(INSTANCE, record.stream, recordKey);
    if (row) live[`${record.stream}/${recordKey}`] = row.data;
  }
  return live;
}

function count(db: Database.Database, sql: string): number {
  return (db.prepare(sql).get() as { n: number }).n;
}

describe("Node SQLite import job adapter", () => {
  it("publishes the same live set as line-by-line ingest, in one transaction", async () => {
    const { store, capability, jobs, begin, db } = await prepare();
    await jobs.begin(begin);
    const status = await importSpool(jobs, "job-1", capability.readSpool!);
    expect(count(db, "SELECT COUNT(*) AS n FROM pdpp_records")).toBe(0);
    expect(
      count(db, "SELECT COUNT(*) AS n FROM pdpp_import_staged"),
    ).toBeGreaterThan(0);
    const receipt = await jobs.commit({
      jobId: "job-1",
      batches: status.job.nextSeq,
      connectorState: '{"cursor":"c2"}',
    });
    expect(liveOf(store, importVectorRecords())).toEqual(
      oracleLive(importVectorRecords()),
    );
    expect(receipt).toMatchObject({ records: 10, operations: 6, rejected: 1 });
    expect(count(db, "SELECT COUNT(*) AS n FROM pdpp_import_staged")).toBe(0);
    expect((await jobs.connectorState(INSTANCE))?.state).toBe(
      '{"cursor":"c2"}',
    );
    // A retried commit (lost ack) returns the stored receipt and writes nothing.
    const changes = count(db, "SELECT COUNT(*) AS n FROM pdpp_record_changes");
    expect(
      await jobs.commit({ jobId: "job-1", batches: status.job.nextSeq }),
    ).toEqual(receipt);
    expect(count(db, "SELECT COUNT(*) AS n FROM pdpp_record_changes")).toBe(
      changes,
    );
  });

  const points: SqliteImportFaultPoint[] = [
    "stage:before-commit",
    "stage:after-commit",
    "publish:before-commit",
    "publish:after-commit",
  ];
  for (const point of points) {
    it(`recovers from a failure at ${point} on every occurrence after reopening`, async () => {
      // A clean run fixes the batch count and the replica operations it captures.
      const probe = await prepare(importVectorRecords(), { replication: true });
      await probe.jobs.begin(probe.begin);
      const batches = (
        await importSpool(probe.jobs, "job-1", probe.capability.readSpool!)
      ).job.nextSeq;
      await probe.jobs.commit({ jobId: "job-1", batches });
      const expectedOps = count(
        probe.db,
        "SELECT COUNT(*) AS n FROM pdpp_replica_operations",
      );
      probe.db.close();
      rmSync(probe.path);
      rmSync(`${probe.path}-wal`, { force: true });
      rmSync(`${probe.path}-shm`, { force: true });
      const occurrences = point.startsWith("stage") ? batches : 1;
      for (let n = 0; n < occurrences; n++) {
        const setup = await prepare(importVectorRecords(), {
          replication: true,
        });
        setup.db.close();
        let seen = 0;
        let { db, jobs, capability, store } = openStore(setup.path, {
          replication: true,
          fault: (at) => {
            if (at === point && seen++ === n) throw new Error(`fault ${at}`);
          },
        });
        await jobs.begin(setup.begin);
        await expect(
          (async () => {
            await importSpool(jobs, "job-1", capability.readSpool!);
            await jobs.commit({
              jobId: "job-1",
              batches,
              connectorState: '{"cursor":"end"}',
            });
          })(),
        ).rejects.toThrow(`fault ${point}`);
        if (point !== "publish:after-commit") {
          expect(count(db, "SELECT COUNT(*) AS n FROM pdpp_records")).toBe(0);
          expect(await capability.readConnectorState(INSTANCE)).toBeUndefined();
          expect(
            count(db, "SELECT COUNT(*) AS n FROM pdpp_import_connector_state"),
          ).toBe(0);
        }
        db.close();
        ({ db, jobs, capability, store } = openStore(setup.path, {
          replication: true,
        }));
        const resumed = await importSpool(jobs, "job-1", capability.readSpool!);
        const receipt = await jobs.commit({
          jobId: "job-1",
          batches: resumed.job.nextSeq,
          connectorState: '{"cursor":"end"}',
        });
        expect(receipt.records).toBe(10);
        expect(liveOf(store, importVectorRecords())).toEqual(
          oracleLive(importVectorRecords()),
        );
        // One version per key: a retried batch or commit never duplicates rows.
        expect(
          count(
            db,
            "SELECT COUNT(*) AS n FROM (SELECT record_key FROM pdpp_record_changes GROUP BY stream, record_key HAVING COUNT(*) > 1)",
          ),
        ).toBe(0);
        expect(count(db, "SELECT COUNT(*) AS n FROM pdpp_record_changes")).toBe(
          receipt.accepted,
        );
        // Replication captured each published write exactly once.
        expect(
          count(db, "SELECT COUNT(*) AS n FROM pdpp_replica_operations"),
        ).toBe(expectedOps);
        expect((await jobs.connectorState(INSTANCE))?.state).toBe(
          '{"cursor":"end"}',
        );
        db.close();
        rmSync(setup.path);
        rmSync(`${setup.path}-wal`, { force: true });
        rmSync(`${setup.path}-shm`, { force: true });
      }
    }, 60_000);
  }

  // SIGKILL bypasses finally/close: SQLite must keep exactly the committed prefix.
  it.each(points.map((point) => ({ point })))(
    "resumes after SIGKILL at $point",
    async ({ point }) => {
      const setup = await prepare();
      setup.db.close();
      const adapterUrl = new URL(
        "./pdpp-import-jobs-sqlite.ts",
        import.meta.url,
      ).href;
      const storeUrl = new URL(
        "./pdpp-records-sqlite-store.ts",
        import.meta.url,
      ).href;
      const nth = point.startsWith("stage") ? 2 : 0;
      const code = `
        import Database from 'better-sqlite3';
        import {createSqliteRecordStore} from '${storeUrl}';
        import {createSqliteImportJobCapability} from '${adapterUrl}';
        import {createPdppImportJobs, importSpool, importVectorDeclarations} from '@opendatalabs/personal-server-ts-core/storage/pdpp-import-job';
        const db = new Database(${JSON.stringify(setup.path)});
        const store = createSqliteRecordStore(db);
        let seen = 0;
        const capability = createSqliteImportJobCapability(db, store, {
          pageSize: 3,
          spoolPath: (spool) => ${JSON.stringify(dir)} + '/' + spool.id + '.ndjson',
          fault: (at) => { if (at === '${point}' && seen++ === ${nth}) process.kill(process.pid, 'SIGKILL'); },
        });
        const jobs = createPdppImportJobs({capability, declarations: importVectorDeclarations, owner: '${OWNER}'});
        await jobs.begin(${JSON.stringify(setup.begin)});
        const status = await importSpool(jobs, 'job-1', capability.readSpool);
        await jobs.commit({jobId: 'job-1', batches: status.job.nextSeq, connectorState: '{"cursor":"end"}'});
        process.exit(3);
      `;
      const child = spawnSync(
        process.execPath,
        ["--import", "tsx", "--input-type=module", "-e", code],
        { encoding: "utf8", timeout: 30000 },
      );
      expect(child.stderr).toBe("");
      expect(child.signal).toBe("SIGKILL");
      const { db, jobs, capability, store } = openStore(setup.path);
      const status = await jobs.status("job-1");
      if (point === "publish:after-commit") {
        expect(status.job.state).toBe("committed");
      } else {
        expect(status.job.state).toBe("open");
        expect(count(db, "SELECT COUNT(*) AS n FROM pdpp_records")).toBe(0);
        expect(await capability.readConnectorState(INSTANCE)).toBeUndefined();
        if (point === "stage:before-commit") expect(status.resume?.seq).toBe(2);
        if (point === "stage:after-commit") expect(status.resume?.seq).toBe(3);
      }
      const resumed = await importSpool(jobs, "job-1", capability.readSpool!);
      await jobs.commit({
        jobId: "job-1",
        batches: resumed.job.nextSeq,
        connectorState: '{"cursor":"end"}',
      });
      expect(liveOf(store, importVectorRecords())).toEqual(
        oracleLive(importVectorRecords()),
      );
      expect(
        count(
          db,
          "SELECT COUNT(*) AS n FROM (SELECT record_key FROM pdpp_record_changes GROUP BY stream, record_key HAVING COUNT(*) > 1)",
        ),
      ).toBe(0);
      expect((await jobs.connectorState(INSTANCE))?.state).toBe(
        '{"cursor":"end"}',
      );
      db.close();
    },
    60_000,
  );

  it("refuses a page size that is not a positive integer", () => {
    const db = new Database(join(dir, "pages.db"));
    const store = createSqliteRecordStore(db);
    for (const pageSize of [0, -1, 1.5, Number.NaN])
      expect(() =>
        createSqliteImportJobCapability(db, store, { pageSize }),
      ).toThrow(expect.objectContaining({ code: "invalid_request" }));
    db.close();
  });

  it("abort leaves nothing visible", async () => {
    const { capability, jobs, begin, db } = await prepare();
    await jobs.begin(begin);
    const status = await importSpool(jobs, "job-1", capability.readSpool!);
    await jobs.abort("job-1", "user_cancelled");
    expect(count(db, "SELECT COUNT(*) AS n FROM pdpp_import_staged")).toBe(0);
    expect(count(db, "SELECT COUNT(*) AS n FROM pdpp_records")).toBe(0);
    await expect(
      jobs.commit({ jobId: "job-1", batches: status.job.nextSeq }),
    ).rejects.toMatchObject({ code: "job_not_open" });
    expect(await capability.readConnectorState(INSTANCE)).toBeUndefined();
  });

  it("refuses to publish a zero-batch or prefix-only job, even called directly", async () => {
    const { capability, jobs, begin, db } = await prepare();
    await jobs.begin(begin);
    const publishNow = async () =>
      capability.publish({
        job: (await jobs.status("job-1")).job,
        connectorState: '{"cursor":"end"}',
        connectorStateSha256: null,
        committedAt: "2026-10-28T00:00:00.000Z",
        declarations,
      });
    await expect(publishNow()).rejects.toMatchObject({
      code: "spool_incomplete",
    });
    const window = await capability.readSpool!(begin.spool, 0, 256);
    const end = window.lastIndexOf(0x0a) + 1;
    const text = new TextDecoder().decode(window.subarray(0, end));
    await jobs.append({
      jobId: "job-1",
      seq: 0,
      text,
      sha256: createHash("sha256")
        .update(window.subarray(0, end))
        .digest("hex"),
      spoolStart: 0,
      spoolEnd: end,
    });
    await expect(publishNow()).rejects.toMatchObject({
      code: "spool_incomplete",
    });
    await expect(
      jobs.commit({ jobId: "job-1", batches: 1, connectorState: "{}" }),
    ).rejects.toMatchObject({ code: "spool_incomplete" });
    expect(count(db, "SELECT COUNT(*) AS n FROM pdpp_records")).toBe(0);
    expect(await capability.readConnectorState(INSTANCE)).toBeUndefined();
  });

  it("a reset during the run aborts the job and drops what it staged", async () => {
    const { store, capability, jobs, begin, db } = await prepare();
    await jobs.begin(begin);
    const status = await importSpool(jobs, "job-1", capability.readSpool!);
    expect(
      count(db, "SELECT COUNT(*) AS n FROM pdpp_import_staged"),
    ).toBeGreaterThan(0);
    const job = (await capability.readJob("job-1"))!;
    store.resetInstanceBinding({
      instance: INSTANCE,
      expectedMethod: METHOD,
      expectedGeneration: 1,
      nextMethod: METHOD,
    });
    expect(count(db, "SELECT COUNT(*) AS n FROM pdpp_import_staged")).toBe(0);
    expect((await jobs.status("job-1")).job).toMatchObject({
      state: "aborted",
      abortReason: "connection_reset",
    });
    await expect(
      jobs.commit({ jobId: "job-1", batches: status.job.nextSeq }),
    ).rejects.toMatchObject({ code: "job_not_open" });
    // Publication re-checks the job inside its transaction, too.
    await expect(
      capability.publish({
        job,
        connectorStateSha256: null,
        committedAt: "2026-10-28T00:00:00.000Z",
        declarations,
      }),
    ).rejects.toMatchObject({ code: "job_not_open" });
    expect(count(db, "SELECT COUNT(*) AS n FROM pdpp_records")).toBe(0);
  });

  it("a reset or deletion erases the committed cursor with the connection's data", async () => {
    for (const erase of ["reset", "delete"] as const) {
      const { store, capability, jobs, begin, db } = await prepare();
      await jobs.begin(begin);
      const status = await importSpool(jobs, "job-1", capability.readSpool!);
      await jobs.commit({
        jobId: "job-1",
        batches: status.job.nextSeq,
        connectorState: '{"cursor":"end"}',
      });
      expect((await jobs.connectorState(INSTANCE))?.state).toBe(
        '{"cursor":"end"}',
      );
      if (erase === "reset")
        store.resetInstanceBinding({
          instance: INSTANCE,
          expectedMethod: METHOD,
          expectedGeneration: 1,
          nextMethod: METHOD,
        });
      else store.deleteConnection(INSTANCE);
      expect(await capability.readConnectorState(INSTANCE)).toBeUndefined();
      expect(await jobs.connectorState(INSTANCE)).toBeUndefined();
      expect(
        count(db, "SELECT COUNT(*) AS n FROM pdpp_import_connector_state"),
      ).toBe(0);
      expect((await jobs.status("job-1")).job.state).toBe("committed");
      db.close();
      rmSync(join(dir, "records.db"), { force: true });
    }
  });

  it("captures replication with publication only when enabled; flag off leaves no replica schema", async () => {
    for (const replication of [false, true]) {
      const { capability, jobs, begin, db } = await prepare(
        importVectorRecords(),
        { replication },
      );
      const replicaTables = () =>
        count(
          db,
          "SELECT COUNT(*) AS n FROM sqlite_master WHERE name LIKE 'pdpp_replica_%'",
        );
      if (!replication) expect(replicaTables()).toBe(0);
      await jobs.begin(begin);
      const status = await importSpool(jobs, "job-1", capability.readSpool!);
      const before = replication
        ? count(db, "SELECT COUNT(*) AS n FROM pdpp_replica_operations")
        : 0;
      const receipt = await jobs.commit({
        jobId: "job-1",
        batches: status.job.nextSeq,
      });
      if (replication) {
        const captured =
          count(db, "SELECT COUNT(*) AS n FROM pdpp_replica_operations") -
          before;
        expect(captured).toBeGreaterThanOrEqual(receipt.accepted);
      } else {
        expect(replicaTables()).toBe(0);
      }
      db.close();
      rmSync(join(dir, "records.db"));
      rmSync(join(dir, "records.db-wal"), { force: true });
      rmSync(join(dir, "records.db-shm"), { force: true });
    }
  });
});
