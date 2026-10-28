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
});
