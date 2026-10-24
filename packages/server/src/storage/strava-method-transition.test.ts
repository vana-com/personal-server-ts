import type { DataStoragePort } from "@opendatalabs/personal-server-ts-core/ports";
import { createLegacyScopeView } from "@opendatalabs/personal-server-ts-core/storage/legacy-scope-view";
import type { DataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { pdppInstanceBindingRoutes } from "../routes/pdpp-instance-bindings.js";
import { initializeDatabase } from "./index-schema.js";
import { createLegacyScopeAuthority } from "./legacy-scope-authority.js";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import { createStravaMethodTransition } from "./strava-method-transition.js";

const INSTANCE = "strava:0xowner";
const SOURCE = "https://registry.pdpp.dev/sources/strava";
const ACTIVITIES = "strava.activities";
const DIAGNOSTICS = "strava.coverage_diagnostics";
const SAVED_AT = "2026-10-20T00:00:00.000Z";

type Store = ReturnType<typeof createSqliteRecordStore>;

const activity = (id: string, freshness = "snapshot") => ({
  id,
  activity_type: "Ride",
  freshness,
});

const savedEnvelope = (scope: string, data: Record<string, unknown>) =>
  ({ scope, collectedAt: SAVED_AT, data }) as unknown as DataFileEnvelope;

/** Export rows for the current generation, as a completed export run left them. */
function seedExport(store: Store, ids: string[]) {
  store.replaceStream({
    instance: INSTANCE,
    stream: "activities",
    method: "strava",
    generation: 1,
    primaryKey: ["id"],
    emittedAt: SAVED_AT,
    sourceCollectedAt: SAVED_AT,
    envelopes: ids.map((id) => ({
      instance: INSTANCE,
      stream: "activities",
      key: id,
      data: activity(id),
      emitted_at: SAVED_AT,
    })),
  });
}

/** A browser run; `complete` writes the stream's completion receipt. */
function browserRun(store: Store, ids: string[], complete: boolean) {
  const emittedAt = "2026-10-22T00:00:00.000Z";
  const envelopes = ids.map((id) => ({
    instance: INSTANCE,
    stream: "activities",
    key: id,
    data: activity(id, "live"),
    emitted_at: emittedAt,
  }));
  if (!complete) {
    store.ingestBatch(
      envelopes,
      () => "mutable_state",
      () => ["id"],
      { method: "strava-browser", generation: 2 },
    );
    return;
  }
  store.replaceStream({
    instance: INSTANCE,
    stream: "activities",
    method: "strava-browser",
    generation: 2,
    primaryKey: ["id"],
    emittedAt,
    sourceCollectedAt: emittedAt,
    envelopes,
  });
}

describe("Strava export-to-browser transition", () => {
  let db: ReturnType<typeof initializeDatabase>;
  let store: Store;
  let method: string;
  const files = {
    findEntry: () => undefined,
    readEnvelope: async () => {
      throw new Error("no legacy file");
    },
  } as unknown as DataStoragePort;
  const create = () =>
    createStravaMethodTransition(
      store,
      createLegacyScopeView({
        authority: createLegacyScopeAuthority(db),
        records: store,
        configuredMethods: () => [method],
      }),
      files,
    );

  beforeEach(() => {
    db = initializeDatabase(":memory:");
    store = createSqliteRecordStore(db);
    method = "strava";
    store.registerConnection({
      instance: INSTANCE,
      sourceId: SOURCE,
      method,
      label: "",
    });
  });
  afterEach(() => store.close());

  it("archives export rows, rebinds to strava-browser and fences old runs", () => {
    seedExport(store, ["a"]);
    const input = {
      instance: INSTANCE,
      expectedGeneration: 1,
      expectedWriteClock: store.transitionWriteClock(),
      snapshots: {
        [ACTIVITIES]: savedEnvelope(ACTIVITIES, {
          activities: [activity("a")],
        }),
      },
    };

    expect(store.transitionStravaToBrowser(input)).toMatchObject({
      method: "strava-browser",
      generation: 2,
    });
    // Replaying the same intent is a no-op, not a second archive.
    expect(store.transitionStravaToBrowser(input).generation).toBe(2);

    const archive = store.stravaTransition(INSTANCE)!.archiveInstance;
    expect(store.getRecord(INSTANCE, "activities", "a")).toBeUndefined();
    expect(store.getRecord(archive, "activities", "a")?.data.id).toBe("a");
    expect(store.listConnections(SOURCE)).toHaveLength(1);
    expect(() => seedExport(store, ["late"])).toThrow(
      "binding_generation_mismatch",
    );

    store.deleteConnection(INSTANCE);
    expect(store.stravaTransition(INSTANCE)).toBeNull();
    expect(store.getRecord(archive, "activities", "a")).toBeUndefined();
  });

  it("refuses a connection that is not the Strava export method", () => {
    store.registerConnection({
      instance: "other",
      sourceId: SOURCE,
      method: "strava-browser",
      label: "",
    });
    expect(() =>
      store.transitionStravaToBrowser({
        instance: "other",
        expectedGeneration: 1,
        expectedWriteClock: store.transitionWriteClock(),
        snapshots: {},
      }),
    ).toThrow("connection_conflict");
  });

  it("keeps the export until a completed browser run covers every saved id", async () => {
    seedExport(store, ["a", "b"]);
    await create().transition(INSTANCE, 1);
    method = "strava-browser";
    const { view, status } = create();
    const exportBody = { activities: [activity("a"), activity("b")] };

    // No browser run yet.
    expect(await view.readLatest(ACTIVITIES)).toMatchObject({
      kind: "canonical",
      envelope: { data: exportBody },
    });
    expect(await status(INSTANCE)).toBe("pending");

    // A partial run that covers every id still has no completion receipt.
    browserRun(store, ["a", "b", "c"], false);
    expect(await view.readLatest(ACTIVITIES)).toMatchObject({
      envelope: { data: exportBody },
    });
    expect(await status(INSTANCE)).toBe("pending");
  });

  it("keeps the export and reports a mismatch when a completed run misses saved ids", async () => {
    seedExport(store, ["a", "b"]);
    await create().transition(INSTANCE, 1);
    method = "strava-browser";
    const { view, status } = create();

    browserRun(store, ["x"], true);

    expect(await view.readLatest(ACTIVITIES)).toMatchObject({
      kind: "canonical",
      envelope: { data: { activities: [activity("a"), activity("b")] } },
    });
    expect(await status(INSTANCE)).toBe("account_mismatch");
    expect(store.stravaTransition(INSTANCE)?.activitiesCovered).toBe(false);
  });

  it("hands strava.activities to the browser once a completed run covers it", async () => {
    seedExport(store, ["a"]);
    await create().transition(INSTANCE, 1);
    method = "strava-browser";
    const { view, status } = create();

    browserRun(store, ["a", "new"], true);

    expect(await view.readLatest(ACTIVITIES)).toMatchObject({
      kind: "canonical",
      envelope: {
        data: { activities: [activity("a", "live"), activity("new", "live")] },
      },
    });
    expect(await status(INSTANCE)).toBe("covered");
    expect(store.stravaTransition(INSTANCE)?.activitiesCovered).toBe(true);
  });

  // Desktop publishes each served body as a legacy file. That newer export
  // file must not keep a covering browser run from taking over.
  it("takes over past a published export file", async () => {
    seedExport(store, ["a"]);
    const published = savedEnvelope(ACTIVITIES, {
      activities: [activity("a")],
    });
    db.prepare(
      "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
    ).run(
      "strava/activities/export.json",
      ACTIVITIES,
      "2026-10-21T00:00:00.000Z",
      1,
    );
    const withFile = () =>
      createStravaMethodTransition(
        store,
        createLegacyScopeView({
          authority: createLegacyScopeAuthority(db),
          records: store,
          configuredMethods: () => [method],
          readLegacyHead: async () => published,
        }),
        {
          findEntry: ({ scope }: { scope: string }) =>
            scope === ACTIVITIES
              ? { collectedAt: "2026-10-21T00:00:00.000Z" }
              : undefined,
          readEnvelope: async () => published,
        } as unknown as DataStoragePort,
      );
    await withFile().transition(INSTANCE, 1);
    method = "strava-browser";
    const { view, status } = withFile();

    browserRun(store, ["a"], true);

    expect(await view.readLatest(ACTIVITIES)).toMatchObject({
      kind: "canonical",
      envelope: { data: { activities: [activity("a", "live")] } },
    });
    expect(await status(INSTANCE)).toBe("covered");
  });

  it("refuses a saved export body whose activity ids cannot be read", async () => {
    seedExport(store, ["a"]);
    const unreadable = savedEnvelope(ACTIVITIES, { activities: [{ id: 1 }] });
    const withFile = createStravaMethodTransition(
      store,
      createLegacyScopeView({
        authority: createLegacyScopeAuthority(db),
        records: store,
        configuredMethods: () => [method],
        readLegacyHead: async () => unreadable,
      }),
      {
        findEntry: ({ scope }: { scope: string }) =>
          scope === ACTIVITIES ? { collectedAt: SAVED_AT } : undefined,
        readEnvelope: async () => unreadable,
      } as unknown as DataStoragePort,
    );
    db.prepare(
      "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
    ).run("strava/activities/export.json", ACTIVITIES, SAVED_AT, 1);

    await expect(withFile.transition(INSTANCE, 1)).rejects.toThrow(
      "strava_previous_data_not_readable",
    );
    expect(store.getInstanceBinding(INSTANCE).method).toBe("strava");
  });

  it("never counts unreadable saved ids as covered", async () => {
    seedExport(store, ["a"]);
    store.transitionStravaToBrowser({
      instance: INSTANCE,
      expectedGeneration: 1,
      expectedWriteClock: store.transitionWriteClock(),
      snapshots: { [ACTIVITIES]: savedEnvelope(ACTIVITIES, {}) },
    });
    method = "strava-browser";
    const { status } = create();

    browserRun(store, ["a"], true);

    expect(await status(INSTANCE)).toBe("account_mismatch");
    expect(store.stravaTransition(INSTANCE)?.activitiesCovered).toBe(false);
  });

  it("keeps saved coverage diagnostics readable as a frozen snapshot", async () => {
    seedExport(store, ["a"]);
    store.replaceStream({
      instance: INSTANCE,
      stream: "coverage_diagnostics",
      method: "strava",
      generation: 1,
      primaryKey: ["id"],
      emittedAt: SAVED_AT,
      sourceCollectedAt: SAVED_AT,
      envelopes: [
        {
          instance: INSTANCE,
          stream: "coverage_diagnostics",
          key: "activities:all",
          data: { id: "activities:all", status: "complete" },
          emitted_at: SAVED_AT,
        },
      ],
    });
    await create().transition(INSTANCE, 1);
    method = "strava-browser";
    const { view } = create();

    browserRun(store, ["a"], true);
    await view.readLatest(ACTIVITIES);

    expect(await view.readLatest(DIAGNOSTICS)).toMatchObject({
      kind: "canonical",
      envelope: {
        data: {
          coverage_diagnostics: [{ id: "activities:all", status: "complete" }],
        },
      },
    });
  });

  it("serves the transition only to the owner and reports its status", async () => {
    seedExport(store, ["a"]);
    const transition = create();
    const app = pdppInstanceBindingRoutes({
      store,
      ownerSubjectId: "0xowner",
      configuredMethods: new Map([[INSTANCE, ["strava"]]]),
      instancesForSubject: () => [INSTANCE],
      instancesForSource: () => [INSTANCE],
      auth: {
        resolveToken: async (token: string) =>
          token === "owner"
            ? {
                active: true,
                tokenKind: "owner",
                subjectId: "0xowner",
                sourceId: SOURCE,
              }
            : { active: false },
      } as never,
      transitionStrava: transition.transition,
      stravaTransitionStatus: transition.status,
    });
    const post = (token: string) =>
      app.request(`/pdpp/instances/${INSTANCE}/transition-strava-browser`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ expected_generation: 1 }),
      });
    const status = () =>
      app.request(`/pdpp/instances/${INSTANCE}/strava-browser-transition`, {
        headers: { authorization: "Bearer owner" },
      });

    expect(await (await status()).json()).toEqual({ status: "none" });
    expect((await post("not-owner")).status).toBe(401);
    expect(store.getInstanceBinding(INSTANCE).method).toBe("strava");

    const response = await post("owner");
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      method: "strava-browser",
      generation: 2,
    });
    expect(await (await status()).json()).toEqual({ status: "pending" });
  });
});
