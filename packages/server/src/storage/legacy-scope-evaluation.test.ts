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
