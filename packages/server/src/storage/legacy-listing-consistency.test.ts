import { ensureReplicaSchema } from "./pdpp-replica-canonical-port.js";
import { beforeEach, afterEach, expect, it, vi } from "vitest";
import {
  handlePersonalServerDataRequest,
  type PersonalServerDataApiDeps,
} from "@opendatalabs/personal-server-ts-core/api";
import { createMemoryDataStorage } from "@opendatalabs/personal-server-ts-core/test-utils";
import { createScopeDeletionTracker } from "@opendatalabs/personal-server-ts-core/sync";
import { createLegacyScopeView } from "@opendatalabs/personal-server-ts-core/storage/legacy-scope-view";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import { createLegacyScopeAuthority } from "./legacy-scope-authority.js";
import { initializeDatabase } from "./index-schema.js";
import { createStravaMethodTransition } from "./strava-method-transition.js";
import type { DataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
const SOURCE = "https://registry.pdpp.dev/sources/oura";
let db: ReturnType<typeof initializeDatabase>;
let store: ReturnType<typeof createSqliteRecordStore>;
beforeEach(() => {
  db = initializeDatabase(":memory:");
  store = createSqliteRecordStore(db);
});
afterEach(() => store.close());
const configuredMethods = () => ["oura"];
function seed(stream = "activity") {
  store.replaceStream({
    instance: "i",
    stream,
    method: "oura",
    generation: 1,
    primaryKey: ["id"],
    emittedAt: "2026-09-10T07:00:00Z",
    sourceCollectedAt: "2026-09-09T07:00:00Z",
    envelopes: [
      {
        instance: "i",
        stream,
        key: "a",
        data: { id: "a", day: "2026-09-01", score: 80 },
        emitted_at: "2026-09-10T07:00:00Z",
      },
    ],
  });
}
async function covered() {
  store.registerConnection({
    instance: "i",
    sourceId: SOURCE,
    method: "oura",
    label: "",
  });
  seed();
  const authority = createLegacyScopeAuthority(db);
  const plain = createLegacyScopeView({
    authority,
    records: store,
    configuredMethods,
  });
  const projected = await plain.readLatest("oura.activity");
  if (projected.kind !== "canonical") throw Error("fixture");
  db.exec(
    "INSERT INTO data_files(path,scope,collected_at,size_bytes) VALUES ('old','oura.activity','2026-10-01',1); DELETE FROM pdpp_stream_completion",
  );
  const view = createLegacyScopeView({
    authority,
    records: store,
    configuredMethods,
    readLegacyHead: async () => projected.envelope,
  });
  expect((await view.readLatest("oura.activity")).kind).toBe("canonical");
  return view;
}
async function pausedListing(
  view: PersonalServerDataApiDeps["legacyScopeView"],
) {
  const storage = createMemoryDataStorage();
  await storage.insertEntry({
    scope: "notes.manual",
    fileId: "notes",
    path: "notes",
    collectedAt: "2026-09-01",
    sizeBytes: 1,
  });
  let enter!: () => void;
  const entered = new Promise<void>((r) => {
    enter = r;
  });
  let resume!: () => void;
  const gate = new Promise<void>((r) => {
    resume = r;
  });
  const tracker = createScopeDeletionTracker({
    serverOwner: "0x1111111111111111111111111111111111111111",
    feed: {
      listDataPointsByOwner: vi.fn(),
      getDataPoint: async () => {
        enter();
        await gate;
        return null;
      },
    },
  });
  const deps: PersonalServerDataApiDeps = {
    storage,
    legacyScopeView: view,
    scopeDeletions: tracker,
    auth: {
      authorizeOwner: vi.fn(),
      authorizeBuilderList: vi.fn(),
      authorizeBuilderRead: vi.fn(),
    },
    accessLogWriter: { write: vi.fn() },
  };
  const request = () =>
    handlePersonalServerDataRequest(
      new Request("https://ps.local/?limit=100"),
      deps,
    );
  const pending = request();
  await entered;
  return { pending, resume, request };
}
it.each([true, false])(
  "checks relevant=%s writes after asynchronous deletion",
  async (relevant) => {
    const view = await covered();
    const { pending, resume, request } = await pausedListing(view);
    if (relevant) db.exec("UPDATE pdpp_records SET data='{}'");
    else seed("unrelated");
    resume();
    const response = await pending;
    expect(response.status).toBe(relevant ? 503 : 200);
    if (relevant) {
      expect(response.headers.get("Retry-After")).toBe("1");
      expect((await response.json()).error).toBe("STORE_INCONSISTENT_READ");
      const next = await request();
      expect(
        (await next.json()).scopes.map((s: { scope: string }) => s.scope),
      ).not.toContain("oura.activity");
    }
  },
);
it("rejects a refused-to-canonical candidate change during deletion work", async () => {
  const view = await covered();
  db.exec("UPDATE pdpp_record_arrival SET arrival=arrival+1");
  expect(view.listingFor("oura.activity").kind).toBe("refused");
  const { pending, resume } = await pausedListing(view);
  expect((await view.readLatest("oura.activity")).kind).toBe("canonical");
  resume();
  expect((await pending).status).toBe(503);
});
it.each([true, false])(
  "validates composed Strava transition state, changed=%s",
  async (changed) => {
    const source = "https://registry.pdpp.dev/sources/strava";
    store.registerConnection({
      instance: "s",
      sourceId: source,
      method: "strava",
      label: "",
    });
    store.transitionStravaToBrowser({
      instance: "s",
      expectedGeneration: 1,
      expectedWriteClock: store.transitionWriteClock(),
      snapshots: {
        "strava.activities": {
          scope: "strava.activities",
          collectedAt: "2026-10-01",
          data: { activities: [] },
        } as unknown as DataFileEnvelope,
      },
    });
    const base = createLegacyScopeView({
      authority: createLegacyScopeAuthority(db),
      records: store,
      configuredMethods: () => ["strava-browser"],
    });
    const { view } = createStravaMethodTransition(
      store,
      base,
      createMemoryDataStorage(),
    );
    const { pending, resume } = await pausedListing(view);
    if (changed) store.clearStravaTransitionScope("strava.activities");
    resume();
    expect((await pending).status).toBe(changed ? 503 : 200);
  },
);

it.each(["quarantine", "unrelated", "threshold"])(
  "rejects %s changes during awaited parity",
  async (mutation) => {
    ensureReplicaSchema(db);
    await covered();
    db.exec("UPDATE legacy_scope_takeover_verdicts SET canonical_cursor='old'");
    let enter!: () => void;
    const entered = new Promise<void>((r) => {
      enter = r;
    });
    let resume!: () => void;
    const gate = new Promise<void>((r) => {
      resume = r;
    });
    const projected = await createLegacyScopeView({
      authority: createLegacyScopeAuthority(db),
      records: store,
      configuredMethods,
    }).readLatest("oura.activity");
    // It still has a covered legacy head, so obtain its known synthetic body directly.
    const body = {
      scope: "oura.activity",
      collectedAt: "2026-09-09T07:00:00.000Z",
      data: { activities: [{ id: "a", day: "2026-09-01", score: 80 }] },
    } as unknown as DataFileEnvelope;
    const thresholds = { maxPayloadRatio: 1.5 };
    const racing = createLegacyScopeView({
      authority: createLegacyScopeAuthority(db),
      records: store,
      configuredMethods,
      coverageThresholds: thresholds,
      readLegacyHead: async () => {
        enter();
        await gate;
        return projected.kind === "canonical" ? projected.envelope : body;
      },
    });
    const pending = racing.readLatest("oura.activity");
    await entered;
    if (mutation === "quarantine")
      db.exec(
        "INSERT INTO pdpp_replica_quarantined_keys VALUES ('i',1,'activity','a')",
      );
    else if (mutation === "unrelated") seed("unrelated");
    else thresholds.maxPayloadRatio = 2;
    resume();
    expect(await pending).toMatchObject({
      kind: "refused",
      refusal: { reason: "store_inconsistent_read" },
    });
  },
);
