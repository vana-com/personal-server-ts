import { createLegacyScopeAuthority } from "./legacy-scope-authority.js";
import { createLegacyScopeView } from "@opendatalabs/personal-server-ts-core/storage/legacy-scope-view";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import { initializeDatabase } from "./index-schema.js";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import { trackLegacyScopeMutations } from "./legacy-scope-revalidation-state.js";
afterEach(() => vi.useRealTimers());
function seed(path = ":memory:") {
  const raw = initializeDatabase(path);
  const store = createSqliteRecordStore(raw);
  store.registerConnection({
    instance: "i",
    sourceId: "https://registry.pdpp.dev/sources/oura",
    method: "oura",
    label: "",
  });
  raw.exec(
    "INSERT INTO data_files(path,scope,collected_at) VALUES ('old','oura.activity','2026-01-01'); INSERT INTO legacy_scope_takeovers(scope,instance,generation,method,superseded_path,superseded_version,superseded_cas_revision,superseded_collected_at) VALUES ('oura.activity','i',1,'oura','old',1,1,'2026-01-01')",
  );
  store.ingestBatch(
    [
      {
        instance: "i",
        stream: "activity",
        key: "a",
        data: { id: "a", day: "2026-01-01", score: 80 },
        emitted_at: "2026-01-01T00:00:00Z",
      },
    ],
    () => "mutable_state",
    () => ["id"],
    { method: "oura", generation: 1 },
  );
  raw.exec(
    "INSERT INTO legacy_scope_takeover_verdicts(scope,instance,generation,legacy_version_id,canonical_cursor,verdict,comparison_case,reason_counts_json,applied_exceptions_json,legacy_bytes,canonical_bytes,byte_delta) SELECT 'oura.activity','i',1,id,'old-proof','covered','same_time','{}','[]',1,1,0 FROM data_files WHERE scope='oura.activity'",
  );
  return raw;
}
it("marks once per commit, preserves first mutation time, and rolls back with the source", () => {
  let now = 1000;
  const raw = seed();
  const state = trackLegacyScopeMutations(raw, {
    ceilingMs: 2000,
    now: () => now,
  });
  const db = state.db;
  try {
    db.transaction(() => {
      for (let i = 0; i < 10; i++)
        db.prepare(
          "INSERT INTO pdpp_record_arrival VALUES ('i','activity',?,1,?)",
        ).run(String(i), i);
      now = 1500;
    })();
    expect(state.revision("i")).toBe(1);
    expect(state.status("i", "oura.activity")).toMatchObject({
      dirty_since: 1000,
      error_count: 0,
    });
    now = 1900;
    db.exec("UPDATE pdpp_record_arrival SET arrival=arrival+1");
    expect(state.revision("i")).toBe(2);
    expect(state.status("i", "oura.activity")?.dirty_since).toBe(1000);
    expect(() =>
      db.transaction(() => {
        db.exec("DELETE FROM pdpp_record_arrival");
        throw Error("rollback");
      })(),
    ).toThrow();
    expect(state.revision("i")).toBe(2);
  } finally {
    db.close();
  }
});
it("expires failing evidence at the ceiling and keeps a slow successful evaluation inside it", () => {
  vi.useFakeTimers({ toFake: ["Date"] });
  let now = 1000;
  vi.setSystemTime(now);
  const raw = seed();
  const state = trackLegacyScopeMutations(raw, {
    ceilingMs: 2000,
    now: () => now,
  });
  const view = createLegacyScopeView({
    authority: createLegacyScopeAuthority(raw),
    records: createSqliteRecordStore(raw),
    configuredMethods: () => ["oura"],
  });
  expect(view.listingFor("oura.activity").kind).toBe("canonical");
  try {
    state.markDirty();
    state.fail("i", ["oura.activity"]);
    state.fail("i", ["oura.activity"]);
    now = 2999;
    vi.setSystemTime(now);
    expect(view.listingFor("oura.activity").kind).toBe("canonical");
    expect(state.overdue("i", "oura.activity")).toBe(false);
    now = 3000;
    vi.setSystemTime(now);
    expect(view.listingFor("oura.activity").kind).toBe("refused");
    expect(state.overdue("i", "oura.activity")).toBe(true);
    expect(state.diagnostics()).toMatchObject([
      { reason: "evaluation_failing", error_count: 2 },
    ]);
    state.complete("i", "oura.activity", state.revision("i"));
    expect(state.overdue("i", "oura.activity")).toBe(false);
    now = 4000;
    state.markDirty();
    now = 5900;
    vi.setSystemTime(now);
    expect(view.listingFor("oura.activity").kind).toBe("canonical");
    expect(state.overdue("i", "oura.activity")).toBe(false);
    state.complete("i", "oura.activity", state.revision("i"));
    now = 8000;
    vi.setSystemTime(now);
    state.ensureDirty();
    expect(state.status("i", "oura.activity")?.dirty_since).toBeNull();
    expect(view.listingFor("oura.activity").kind).toBe("canonical");
    expect(state.overdue("i", "oura.activity")).toBe(false);
  } finally {
    raw.close();
  }
});
it("retains dirty-since and error count across restart", () => {
  const parent = join(homedir(), ".tmp");
  mkdirSync(parent, { recursive: true });
  const dir = mkdtempSync(join(parent, "swr-dirty-"));
  const path = join(dir, "index.db");
  let now = 1000;
  let raw = seed(path);
  let state = trackLegacyScopeMutations(raw, {
    ceilingMs: 2000,
    now: () => now,
  });
  try {
    state.markDirty();
    state.fail("i", ["oura.activity"]);
    raw.close();
    now = 2500;
    raw = initializeDatabase(path);
    state = trackLegacyScopeMutations(raw, { ceilingMs: 2000, now: () => now });
    state.ensureDirty();
    expect(state.status("i", "oura.activity")).toMatchObject({
      dirty_since: 1000,
      error_count: 1,
    });
    now = 3001;
    expect(state.overdue("i", "oura.activity")).toBe(true);
  } finally {
    raw.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
it("blob and replica mutations coarsely dirty every candidate, including shared-blob owners", () => {
  const raw = seed();
  raw.exec(
    "CREATE TABLE pdpp_replica_pending_bytes(batch_id TEXT,blob_id TEXT,bytes BLOB); INSERT INTO pdpp_instance_binding(instance,source_id,method,generation,reset_clock,label) VALUES ('j','https://registry.pdpp.dev/sources/oura','oura',1,0,''); INSERT INTO legacy_scope_takeovers(scope,instance,generation,method,superseded_path,superseded_version,superseded_cas_revision,superseded_collected_at) VALUES ('oura.activity','j',1,'oura','old',1,1,'2026-01-01')",
  );
  const state = trackLegacyScopeMutations(raw, { ceilingMs: 2000 });
  try {
    state.db.exec(
      "INSERT INTO pdpp_replica_pending_bytes VALUES ('batch','shared',X'00')",
    );
    expect(state.revision("i")).toBe(1);
    expect(state.revision("j")).toBe(1);
  } finally {
    raw.close();
  }
});
