import { describe, expect, it } from "vitest";
import { createPsLiteRuntime } from "./runtime.js";
import {
  createMemoryPsLiteAccessLogStore,
  createMemoryPsLiteStorage,
  createMemoryPsLiteTokenStore,
} from "./test-support/memory.js";
import { createMockPsLiteGateway } from "./test-support/gateway.js";
import {
  IMPORT_VECTOR_INSTANCE,
  IMPORT_VECTOR_METHOD,
  IMPORT_VECTOR_OWNER,
  IMPORT_VECTOR_SOURCE,
  ImportJobError,
  buildImportSpool,
  createMemoryImportJobCapability,
  importSpool,
  importVectorDeclarations,
  importVectorRecords,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-import-job";

type PsLiteRuntimeOptions = Parameters<typeof createPsLiteRuntime>[0];

function createTestRuntime(options: Partial<PsLiteRuntimeOptions> = {}) {
  const accessLogStore = createMemoryPsLiteAccessLogStore();
  return createPsLiteRuntime({
    storage: createMemoryPsLiteStorage(),
    gateway: createMockPsLiteGateway(),
    accessLogReader: accessLogStore,
    accessLogWriter: accessLogStore,
    tokenStore: createMemoryPsLiteTokenStore(),
    saveConfig: async () => {},
    stateCapabilities: { config: "memory" },
    ...options,
  });
}

async function vectorCapability() {
  const spool = await buildImportSpool(importVectorRecords());
  const capability = createMemoryImportJobCapability({
    spools: new Map([[spool.handle.id, spool.bytes]]),
  });
  capability.registerConnection({
    instance: IMPORT_VECTOR_INSTANCE,
    sourceId: IMPORT_VECTOR_SOURCE,
    method: IMPORT_VECTOR_METHOD,
  });
  return { capability, spool };
}

function beginInput(spool: Awaited<ReturnType<typeof buildImportSpool>>) {
  return {
    jobId: "job-1",
    binding: {
      owner: IMPORT_VECTOR_OWNER,
      instance: IMPORT_VECTOR_INSTANCE,
      sourceId: IMPORT_VECTOR_SOURCE,
      method: IMPORT_VECTOR_METHOD,
      generation: 1,
    },
    spool: spool.handle,
    streams: ["conversations", "messages", "events"],
    batchBytes: 256,
  };
}

describe("PS Lite import jobs", () => {
  it("is absent without the capability, so whole-scope ingest stays the only path", () => {
    const runtime = createTestRuntime({ serverOwner: IMPORT_VECTOR_OWNER });
    expect("importJobs" in runtime).toBe(false);
    expect(runtime.importJobs).toBeUndefined();
  });

  it("runs a job against the host capability, bound to the server owner", async () => {
    const { capability, spool } = await vectorCapability();
    const storage = createMemoryPsLiteStorage();
    const runtime = createTestRuntime({
      storage,
      serverOwner: IMPORT_VECTOR_OWNER,
      importJobs: { capability, declarations: importVectorDeclarations },
    });
    const jobs = runtime.importJobs!;
    await jobs.begin(beginInput(spool));
    const status = await importSpool(jobs, "job-1", capability.readSpool!);
    const receipt = await jobs.commit({
      jobId: "job-1",
      batches: status.job.nextSeq,
      connectorState: '{"cursor":"end"}',
    });
    expect(receipt).toMatchObject({ records: 10, rejected: 1, operations: 6 });
    expect(
      capability.rows(IMPORT_VECTOR_INSTANCE, "conversations").length,
    ).toBe(2);
    expect((await jobs.connectorState(IMPORT_VECTOR_INSTANCE))?.state).toBe(
      '{"cursor":"end"}',
    );
    // The job writes only through the capability, never the scope files.
    expect(storage.listScopes({}).total).toBe(0);
  });

  it("refuses every job when the runtime has no owner", async () => {
    const { capability, spool } = await vectorCapability();
    const runtime = createTestRuntime({
      importJobs: { capability, declarations: importVectorDeclarations },
    });
    await expect(runtime.importJobs!.begin(beginInput(spool))).rejects.toThrow(
      ImportJobError,
    );
    await expect(
      runtime.importJobs!.begin(beginInput(spool)),
    ).rejects.toMatchObject({ code: "owner_mismatch" });
  });

  it("refuses every operation on an owned job when the runtime has no owner", async () => {
    const { capability, spool } = await vectorCapability();
    const owned = createTestRuntime({
      serverOwner: IMPORT_VECTOR_OWNER,
      importJobs: { capability, declarations: importVectorDeclarations },
    }).importJobs!;
    await owned.begin(beginInput(spool));
    const status = await importSpool(owned, "job-1", capability.readSpool!);
    const unowned = createTestRuntime({
      importJobs: { capability, declarations: importVectorDeclarations },
    }).importJobs!;
    for (const call of [
      () => unowned.status("job-1"),
      () => unowned.commit({ jobId: "job-1", batches: status.job.nextSeq }),
      () => unowned.abort("job-1"),
      () => unowned.connectorState(IMPORT_VECTOR_INSTANCE),
    ])
      await expect(call()).rejects.toMatchObject({ code: "owner_mismatch" });
    expect((await owned.status("job-1")).job.state).toBe("open");
  });

  it("passes the host's batch encoder to a native staged-copy capability", async () => {
    const { capability, spool } = await vectorCapability();
    const staged: unknown[] = [];
    const native = {
      ...capability,
      publication: {
        mode: "native-staged-copy",
        outbox: "by-reference",
      } as const,
      stageBatch: (input: Parameters<typeof capability.stageBatch>[0]) => {
        staged.push(input.canonical);
        return capability.stageBatch(input);
      },
    };
    const runtime = createTestRuntime({
      serverOwner: IMPORT_VECTOR_OWNER,
      importJobs: {
        capability: native,
        declarations: importVectorDeclarations,
        encodeBatch: async ({ operations }) => ({
          entries: operations.map((op) => ({
            key: op.recordKey,
            value: op.dataJson,
          })),
        }),
      },
    });
    await runtime.importJobs!.begin(beginInput(spool));
    const status = await importSpool(
      runtime.importJobs!,
      "job-1",
      capability.readSpool!,
    );
    expect(staged).toHaveLength(status.job.nextSeq);
    expect(
      staged.every((batch) =>
        Array.isArray((batch as { entries: unknown }).entries),
      ),
    ).toBe(true);
  });
});
