// Regression coverage for cached bodies and first-takeover publication fences.
import { homedir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createLegacyScopeView } from "@opendatalabs/personal-server-ts-core/storage/legacy-scope-view";
import { handlePersonalServerDataRequest } from "@opendatalabs/personal-server-ts-core/api";
import { initializeDatabase } from "./index-schema.js";
import { createIndexManager } from "./index-manager.js";
import { createNodeDataStorage } from "./node-data-storage.js";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import { createLegacyScopeAuthority } from "./legacy-scope-authority.js";
import { trackLegacyScopeMutations } from "./legacy-scope-revalidation-state.js";
import { createLegacyScopeRevalidator } from "./legacy-scope-revalidator.js";

const I = "p1-synthetic-claude";
const S = "claude.projects";
const SOURCE = "https://registry.pdpp.dev/sources/claude";
const COLLECTED = "2026-09-01T00:00:00.000Z";
const T0 = Date.parse("2026-10-01T00:00:00.000Z");
const SWEEP = 900_000;
const CEILING = 2 * SWEEP;
const closers: (() => void | Promise<void>)[] = [];
const releases: (() => void)[] = [];

function barrier() {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => (release = resolve));
  releases.push(release);
  return { promise, release };
}

beforeEach(() => {
  // Same clock convention as oracle-1903; no real sleeps or worker processes.
  vi.useFakeTimers({ toFake: ["Date", "setInterval", "clearInterval"] });
  vi.setSystemTime(T0);
});
afterEach(async () => {
  while (releases.length) releases.pop()!();
  while (closers.length) await closers.pop()!();
  vi.restoreAllMocks();
  vi.useRealTimers();
});

async function fixture(takeover = true) {
  // No disk DB or data files: all records and source bytes are synthetic.
  const raw = initializeDatabase(":memory:");
  const state = trackLegacyScopeMutations(raw, { ceilingMs: CEILING });
  const db = state.db;
  const store = createSqliteRecordStore(db);
  closers.push(() => store.close());
  store.registerConnection({
    instance: I,
    sourceId: SOURCE,
    method: "anthropic",
    label: "Synthetic",
  });
  const payload = { uuid: "p1-project", name: "Synthetic project", docs: [] };
  const bytes = new TextEncoder().encode(
    JSON.stringify({
      format: "anthropic-source-record-v1",
      stream: "projects",
      record_key: payload.uuid,
      payload,
    }),
  );
  const blob = store.storeBlobBytesForInstance({
    instance: I,
    method: "anthropic",
    generation: 1,
    bytes,
    mimeType: "application/json",
  });
  const project = {
    id: payload.uuid,
    blob_ref: {
      blob_id: blob.blobId,
      sha256: blob.sha256,
      size_bytes: blob.sizeBytes,
      mime_type: blob.mimeType,
    },
  };
  const rows: Record<string, Record<string, unknown>[]> = {
    account_profile: [
      {
        id: "org",
        organization_id: "org",
        full_name: "Synthetic reader",
        plan: null,
        name_source: "users_json",
        metadata_status: "valid",
      },
    ],
    projects: [project],
    project_documents: [],
  };
  for (const [stream, data] of Object.entries(rows))
    store.replaceStream({
      instance: I,
      stream,
      method: "anthropic",
      generation: 1,
      primaryKey: ["id"],
      emittedAt: COLLECTED,
      sourceCollectedAt: COLLECTED,
      envelopes: data.map((row) => ({
        instance: I,
        stream,
        key: String(row.id),
        data: row,
        emitted_at: COLLECTED,
      })),
    });
  const authority = createLegacyScopeAuthority(db, state);
  const configuredMethods = (source: string) =>
    source === SOURCE ? ["anthropic"] : [];
  const unbound = createLegacyScopeView({
    authority,
    records: store,
    configuredMethods,
  });
  const projected = await unbound.readLatest(S);
  expect(projected.kind).toBe("canonical");
  if (projected.kind !== "canonical") throw Error("synthetic setup failed");
  db.prepare(
    "INSERT INTO data_files(path,scope,collected_at,size_bytes) VALUES ('synthetic/legacy.json',?,?,1)",
  ).run(S, COLLECTED);
  const loader = vi.fn(async () => projected.envelope);
  const view = createLegacyScopeView({
    authority,
    records: store,
    configuredMethods,
    readLegacyHead: loader,
  });
  if (takeover) {
    expect((await view.readLatest(S)).kind).toBe("canonical");
    expect(authority.verdictFor(S)[0]?.verdict).toBe("covered");
    // A second real read exercises the warmed body + cached confirmation path.
    expect((await view.readLatest(S)).kind).toBe("canonical");
    expect(state.status(I, S)?.dirty_since).toBeNull();
  }
  const storage = createNodeDataStorage({
    indexManager: createIndexManager(db),
    hierarchyOptions: {
      dataDir: join(homedir(), ".tmp", "ps-swr-redtest-1103"),
    },
  });
  const get = () =>
    handlePersonalServerDataRequest(
      new Request(`http://localhost/v1/data/${S}`),
      {
        storage,
        legacyScopeView: view,
        auth: {
          authorizeOwner: async () => {},
          authorizeBuilderList: async () => {},
          authorizeBuilderRead: async () => ({ grantId: "owner" }),
        },
        accessLogWriter: { write: async () => {} },
        serverOwner: "0x1111111111111111111111111111111111111111",
      },
      { basePath: "/v1/data" },
    );
  const cursorInputs = () => ({
    writeClock: authority.writeClock(),
    arrival: authority.arrivalRevision(),
    receipts: store.listStreamCompletions(I),
    binding: store.getInstanceBinding(I),
    head: authority.eligibleLegacyHead(S),
    // No declaration provider or configurable thresholds in either view.
    schema: db.prepare("PRAGMA schema_version").get(),
  });
  function loseRequiredBytes() {
    const before = cursorInputs();
    const revision = state.revision(I);
    // Fault injection at the real tracked persistence seam, not a claim that
    // ordinary USER DELETE removes bytes without a record-clock change.
    expect(
      db.prepare("DELETE FROM pdpp_blob_bytes WHERE blob_id=?").run(blob.blobId)
        .changes,
    ).toBe(1);
    expect(store.getBlobBytes(blob.blobId)).toBeUndefined();
    expect(cursorInputs()).toEqual(before);
    expect(state.revision(I)).toBeGreaterThan(revision);
    expect(state.status(I, S)?.dirty_since).not.toBeNull();
  }
  function addCoveredDependency() {
    const before = cursorInputs();
    const revision = state.revision(I);
    // New instance-claimed bytes change tracked blob dependencies without
    // changing the projected project or any component of the old read key.
    store.storeBlobBytesForInstance({
      instance: I,
      method: "anthropic",
      generation: 1,
      bytes: new TextEncoder().encode("synthetic additional source bytes"),
      mimeType: "application/octet-stream",
    });
    expect(cursorInputs()).toEqual(before);
    expect(state.revision(I)).toBeGreaterThan(revision);
    expect(state.status(I, S)?.dirty_since).not.toBeNull();
  }
  return {
    state,
    store,
    authority,
    view,
    loader,
    get,
    loseRequiredBytes,
    addCoveredDependency,
    restoreRequiredBytes: () =>
      db
        .prepare("INSERT INTO pdpp_blob_bytes(blob_id,bytes) VALUES (?,?)")
        .run(blob.blobId, bytes),
    project,
    envelope: projected.envelope,
  };
}

describe("P1 foreground proof must observe tracked dependency mutations", () => {
  it("fences a tracked byte deletion during the first parity read without a takeover", async () => {
    const h = await fixture(false);
    const db = h.state.db;
    expect(
      db.prepare("SELECT COUNT(*) FROM legacy_scope_takeovers").pluck().get(),
    ).toBe(0);
    expect(h.state.status(I, S)).toBeUndefined();
    const revision = h.state.revision(I);
    const clocks = [h.authority.writeClock(), h.authority.arrivalRevision()];
    const sourceReads = vi.spyOn(h.store, "getBlobBytes");
    const paused = barrier();
    const resume = barrier();
    h.loader.mockImplementationOnce(async () => {
      paused.release();
      await resume.promise;
      return h.envelope;
    });
    const request = h.view.readLatest(S);
    await paused.promise;
    expect(sourceReads).toHaveBeenCalled();
    db.prepare("DELETE FROM pdpp_blob_bytes").run();
    expect([h.authority.writeClock(), h.authority.arrivalRevision()]).toEqual(
      clocks,
    );
    resume.release();
    const result = await request;
    expect.soft(h.state.revision(I)).toBeGreaterThan(revision);
    expect.soft(result.kind).toBe("refused");
    expect.soft(h.state.status(I, S)?.dirty_since).not.toBeNull();
    expect
      .soft(
        db.prepare("SELECT COUNT(*) FROM legacy_scope_takeovers").pluck().get(),
      )
      .toBe(0);
    expect.soft(h.authority.verdictFor(S)).toEqual([]);
  });

  it.each(["covered", "not_covered"] as const)(
    "1924 minimal trace: dependency_change(%s) -> advance_to_ceiling -> direct_read",
    async (outcome) => {
      const h = await fixture();
      // Exact three-event script from the two subsequence-minimal violations
      // in dot 1924. No intervening read, evaluation, timeout or restart.
      if (outcome === "covered") h.addCoveredDependency();
      else h.loseRequiredBytes();
      const dirtySince = h.state.status(I, S)!.dirty_since!;
      const sourceReads = vi.spyOn(h.store, "getBlobBytes");
      vi.setSystemTime(dirtySince + CEILING);
      const response = await h.get();
      if (outcome === "covered" && response.status === 200) {
        // Equal visible bytes do not establish fresh construction provenance:
        // serving at this revision requires a fresh real source projection.
        expect(sourceReads).toHaveBeenCalled();
      } else {
        expect.soft(response.status).toBe(503);
        expect.soft(await response.json()).toMatchObject({
          error: "CANONICAL_VIEW_UNAVAILABLE",
          // ruled by lead 2026-11-04: confirmed loss and inconsistent reads are final.
          retryable: false,
          reason: expect.any(String),
        });
      }
    },
  );

  // Complementary integration assertions keep the original before/after
  // inventory and failing-evaluator requirements beyond the minimal traces.
  it("never serves a warmed covered body during SWR or after its ceiling", async () => {
    for (const boundary of ["inside SWR", "at ceiling"] as const) {
      vi.setSystemTime(T0);
      const h = await fixture();
      const previous = h.authority.verdictFor(S)[0]!;
      vi.setSystemTime(T0 + 1_000);
      h.loseRequiredBytes();
      const dirtySince = h.state.status(I, S)!.dirty_since!;
      const evaluate = vi.fn(async () => {
        throw Error("synthetic evaluator failure");
      });
      const worker = createLegacyScopeRevalidator({
        evaluate,
        candidates: () => h.state.candidates(),
        fingerprint: () => h.state.fingerprint(),
        onSweep: () => h.state.ensureDirty(),
        onFailure: (instance, scopes) => h.state.fail(instance, scopes),
        intervalMs: SWEEP,
        logger: { warn: vi.fn() },
      });
      closers.push(() => worker.stop());
      worker.start();
      await worker.idle();
      expect(evaluate).toHaveBeenCalledTimes(1);
      expect(h.state.status(I, S)?.error_count).toBe(1);
      vi.setSystemTime(dirtySince + (boundary === "inside SWR" ? 1 : CEILING));
      expect(h.view.listingFor(S).kind).toBe(
        boundary === "inside SWR" ? "canonical" : "refused",
      );
      const sourceReads = vi.spyOn(h.store, "getBlobBytes");
      const response = await h.get();
      expect.soft(response.status, boundary).toBe(503);
      expect.soft(await response.json(), boundary).toMatchObject({
        error: "CANONICAL_VIEW_UNAVAILABLE",
        // ruled by lead 2026-11-04: confirmed loss and inconsistent reads are final.
        retryable: false,
        reason: expect.any(String),
      });
      // ruled by lead 11-04: a confirmed negative from a same-evaluation byte check is a valid outcome
      const verdict = h.authority.verdictFor(S)[0]!;
      if (
        verdict.verdict === "not_covered" &&
        h.state.status(I, S)?.dirty_since === null
      ) {
        expect(sourceReads).toHaveBeenCalled();
      } else {
        expect(verdict).toEqual(previous);
        expect(h.state.status(I, S)?.dirty_since).toBe(dirtySince);
      }
      expect(h.view.listingFor(S).kind).toBe("refused");
      // A negative cannot stick after a tracked restoration of the bytes.
      h.restoreRequiredBytes();
      sourceReads.mockClear();
      const recovered = await h.get();
      expect(recovered.status).toBe(200);
      expect(sourceReads).toHaveBeenCalled();
      expect(await recovered.json()).toEqual(h.envelope);
      expect(h.authority.verdictFor(S)[0]?.verdict).toBe("covered");
      expect(h.state.status(I, S)?.dirty_since).toBeNull();
    }
  });

  it("cannot clear a dirty marker through a cached verdict without a byte check", async () => {
    const h = await fixture();
    const proof = h.authority.verdictFor(S)[0]!;
    const coverage = h.authority.cachedVerdict(
      S,
      I,
      1,
      proof.legacyVersionId,
      proof.canonicalCursor,
    )!;
    vi.setSystemTime(T0 + 1_000);
    h.loseRequiredBytes();
    const dirty = h.state.status(I, S)!.dirty_since;
    const sourceReads = vi.spyOn(h.store, "getBlobBytes");
    const confirmed = h.authority.confirmRead(
      S,
      h.authority.eligibleLegacyHead(S),
      () => true,
      "anthropic",
      {
        instance: I,
        generation: 1,
        writeClock: h.authority.writeClock(),
        arrivalRevision: h.authority.arrivalRevision(),
        dependencyRevision: h.state.revision(I),
        canonicalCursor: proof.canonicalCursor,
        coverage,
        cached: true,
      },
    );
    expect(confirmed).toBe(false);
    expect(sourceReads).not.toHaveBeenCalled();
    expect(h.state.status(I, S)?.dirty_since).toBe(dirty);
    expect(h.authority.verdictFor(S)[0]).toEqual(proof);
    vi.setSystemTime(dirty! + CEILING);
    expect(h.view.listingFor(S).kind).toBe("refused");
    const response = await h.get();
    expect(response.status).toBe(503);
    expect(await response.json()).toMatchObject({
      // ruled by lead 2026-11-04: confirmed loss and inconsistent reads are final.
      retryable: false,
      reason: expect.any(String),
    });
    expect(h.view.listingFor(S).kind).toBe("refused");
  });

  it("does not publish an obsolete positive or clear dirty_since after a paused fresh projection", async () => {
    const h = await fixture();
    const prior = h.authority.verdictFor(S)[0]!;
    // A real same-record ingest invalidates the old read cursor. The request
    // below must project source bytes anew rather than take the warmed branch.
    vi.setSystemTime(T0 + 1_000);
    const accepted = h.store.ingestBatch(
      [
        {
          instance: I,
          stream: "projects",
          key: h.project.id,
          data: h.project,
          emitted_at: COLLECTED,
        },
      ],
      () => "mutable_state",
      () => ["id"],
      { method: "anthropic", generation: 1 },
    );
    expect(accepted.rejected).toEqual([]);
    const bytesRead = vi.spyOn(h.store, "getBlobBytes");
    const paused = barrier();
    const resume = barrier();
    h.loader.mockImplementationOnce(async () => {
      paused.release();
      await resume.promise;
      return h.envelope;
    });
    const request = h.view.readLatest(S);
    await paused.promise;
    expect(bytesRead).toHaveBeenCalled();
    vi.setSystemTime(T0 + 2_000);
    h.loseRequiredBytes();
    const dirtySince = h.state.status(I, S)!.dirty_since!;
    resume.release();
    const result = await request;
    expect.soft(result.kind).toBe("refused");
    expect.soft(h.state.status(I, S)?.dirty_since).toBe(dirtySince);
    const published = h.authority.verdictFor(S)[0]!;
    expect
      .soft(
        published.verdict === "covered" &&
          published.canonicalCursor !== prior.canonicalCursor,
      )
      .toBe(false);
  });
});
