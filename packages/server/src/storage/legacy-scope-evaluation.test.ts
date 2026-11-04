import { createLegacyScopeRevalidator } from "./legacy-scope-revalidator.js";
import { homedir } from "node:os";
import { performance } from "node:perf_hooks";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, it } from "vitest";
import { createLegacyScopeView } from "@opendatalabs/personal-server-ts-core/storage/legacy-scope-view";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import { trackLegacyScopeMutations } from "./legacy-scope-revalidation-state.js";
import { initializeDatabase } from "./index-schema.js";
import { createLegacyScopeAuthority } from "./legacy-scope-authority.js";
import { createLegacyEvaluationWorker } from "./legacy-scope-evaluation.js";
let cleanup: (() => Promise<void>) | undefined;
afterEach(async () => {
  await cleanup?.();
  cleanup = undefined;
});
it("runs a fresh comparison off-thread and publishes a negative after same-stream sync", async () => {
  const parent = join(homedir(), ".tmp");
  await mkdir(parent, { recursive: true });
  const root = await mkdtemp(join(parent, "swr-worker-"));
  const dataDir = join(root, "data");
  await mkdir(dataDir);
  const db = initializeDatabase(join(root, "index.db"));
  const state = trackLegacyScopeMutations(db, { ceilingMs: 1_800_000 });
  const store = createSqliteRecordStore(state.db);
  const worker = createLegacyEvaluationWorker();
  cleanup = async () => {
    await worker.stop();
    store.close();
    await rm(root, { recursive: true, force: true });
  };
  const source = "https://registry.pdpp.dev/sources/oura";
  store.registerConnection({
    instance: "i",
    sourceId: source,
    method: "oura",
    label: "",
  });
  const put = (score: number) =>
    store.ingestBatch(
      [
        {
          instance: "i",
          stream: "activity",
          key: "a",
          data: { id: "a", day: "2026-09-01", score },
          emitted_at: "2026-09-01T00:00:00Z",
        },
      ],
      () => "mutable_state",
      () => ["id"],
      { method: "oura", generation: 1 },
    );
  put(80);
  const authority = createLegacyScopeAuthority(state.db, state);
  const config = {
    authority,
    records: store,
    configuredMethods: () => ["oura"],
  };
  const projected =
    await createLegacyScopeView(config).readLatest("oura.activity");
  if (projected.kind !== "canonical") throw Error("fixture");
  db.exec(
    "INSERT INTO data_files(path,scope,collected_at,size_bytes) VALUES ('old.json','oura.activity','2026-10-01',1)",
  );
  await writeFile(
    join(dataDir, "old.json"),
    JSON.stringify(projected.envelope),
  );
  const view = createLegacyScopeView({
    ...config,
    readLegacyHead: async () => projected.envelope,
  });
  expect((await view.readLatest("oura.activity")).kind).toBe("canonical");
  const job = {
    database: db.name,
    dataDir,
    owner: "0x1111111111111111111111111111111111111111",
    replication: false,
    declarations: [],
    configuredMethods: [[source, ["oura"]]] as [string, string[]][],
    optInMethods: [],
    coverageThresholds: undefined,
    instance: "i",
    scopes: ["oura.activity"],
  };
  const recovery = createLegacyScopeRevalidator({
    candidates: () => state.candidates(),
    fingerprint: () => "deliberately dropped notification",
    intervalMs: 1000,
    logger: { warn: () => {} },
    evaluate: async () => {
      await worker.evaluate(job);
    },
  });
  recovery.start();
  await recovery.idle();
  const previousCleanup = cleanup!;
  cleanup = async () => {
    const stopping = recovery.stop();
    await worker.stop();
    await stopping;
    await previousCleanup();
  };
  await new Promise((resolve) => setTimeout(resolve, 100));
  const mutationAt = performance.now();
  put(1);
  expect(view.listingFor("oura.activity").kind).toBe("canonical");
  while (
    view.verdictFor("oura.activity")[0]?.verdict !== "not_covered" &&
    performance.now() - mutationAt < 1000
  )
    await new Promise((resolve) => setTimeout(resolve, 10));
  const windowMs = performance.now() - mutationAt;
  console.log(
    JSON.stringify({ droppedEnqueueWindowMs: windowMs, intervalMs: 1000 }),
  );
  expect(windowMs).toBeLessThan(1000);
  expect(view.verdictFor("oura.activity")[0]?.verdict).toBe("not_covered");
  expect(view.listingFor("oura.activity").kind).toBe("refused");
});

it.each(["pdpp-projector", "pdpp-import-projection"] as const)(
  "completes a fenced headless candidate after a %s head replaces its legacy head",
  async (producer) => {
    const root = await mkdtemp(join(homedir(), ".tmp", "swr-headless-"));
    const dataDir = join(root, "data");
    await mkdir(dataDir);
    const raw = initializeDatabase(join(root, "index.db"));
    let now = 1000;
    const state = trackLegacyScopeMutations(raw, {
      ceilingMs: 2000,
      now: () => now,
    });
    const store = createSqliteRecordStore(state.db);
    const worker = createLegacyEvaluationWorker();
    cleanup = async () => {
      await worker.stop();
      store.close();
      await rm(root, { recursive: true, force: true });
    };
    const scope = "oura.activity";
    const source = "https://registry.pdpp.dev/sources/oura";
    store.registerConnection({
      instance: "i",
      sourceId: source,
      method: "oura",
      label: "Synthetic",
    });
    store.ingestBatch(
      [
        {
          instance: "i",
          stream: "activity",
          key: "a",
          data: { id: "a", day: "2026-09-01", score: 80 },
          emitted_at: "2026-09-01T00:00:00.000Z",
        },
      ],
      () => "mutable_state",
      () => ["id"],
      { method: "oura", generation: 1 },
    );
    const authority = createLegacyScopeAuthority(state.db, state);
    const config = {
      authority,
      records: store,
      configuredMethods: () => ["oura"],
    };
    const original = await createLegacyScopeView(config).readLatest(scope);
    if (original.kind !== "canonical") throw Error("synthetic fixture");
    state.db
      .prepare(
        "INSERT INTO data_files(path,scope,collected_at,size_bytes) VALUES ('legacy.json',?,'2026-09-01T00:00:00.000Z',1)",
      )
      .run(scope);
    const view = createLegacyScopeView({
      ...config,
      readLegacyHead: async () => original.envelope,
    });
    expect((await view.readLatest(scope)).kind).toBe("canonical");
    expect(state.status("i", scope)?.dirty_since).toBeNull();
    state.db
      .prepare(
        "INSERT INTO data_files(path,scope,collected_at,size_bytes,producer) VALUES ('projector.json',?,'2026-11-04T00:00:00.000Z',1,?)",
      )
      .run(scope, producer);
    expect(authority.eligibleLegacyHead(scope)).toBeNull();
    expect(state.status("i", scope)?.dirty_since).toBe(1000);
    const result = await worker.evaluate({
      database: raw.name,
      dataDir,
      owner: "synthetic-owner",
      replication: false,
      declarations: [],
      configuredMethods: [[source, ["oura"]]],
      optInMethods: [],
      coverageThresholds: undefined,
      ceilingMs: 2000,
      instance: "i",
      scopes: [scope],
    });
    expect(result.refused).toEqual([]);
    // Only the production Worker confirmation may complete this marker.
    expect.soft(state.status("i", scope)?.dirty_since).toBeNull();
    now = 4000;
    expect(state.diagnostics()).toEqual([]);
    expect((await view.readLatest(scope)).kind).toBe("canonical");
  },
);
