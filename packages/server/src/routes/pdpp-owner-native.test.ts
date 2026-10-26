import { afterEach, describe, expect, it } from "vitest";
import Database from "better-sqlite3";
import {
  PDPP_DATA_ACCESS_TYPE,
  type DeclarationSnapshot,
  type SelectionRequest,
} from "@opendatalabs/personal-server-ts-core/pdpp";
import type { PdppAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import { liveSnapshotDigest } from "../storage/pdpp-stream-completion.js";
import { createSqliteRecordStore } from "../storage/pdpp-records-sqlite-store.js";
import { pdppConnectionRoutes } from "./pdpp-connections.js";

const OWNER = "0xowner";
const SOURCE = "https://registry.pdpp.dev/connectors/spotify";
const A = "conn_123e4567-e89b-42d3-a456-426614174000";
const B = "conn_223e4567-e89b-42d3-a456-426614174001";
const snapshot: DeclarationSnapshot = {
  source_id: SOURCE,
  source_kind: "connector",
  version: "2026-10-24",
  digest: "a".repeat(64),
  streams: [
    {
      name: "playlists",
      fields: ["id", "title", "created_at"],
      required_fields: ["id"],
      primary_key: ["id"],
      consent_time_field: "created_at",
    },
    {
      name: "artists",
      fields: ["id", "name"],
      required_fields: ["id"],
      primary_key: ["id"],
    },
  ],
};

describe("PDPP owner-native projections", () => {
  const db = new Database(":memory:");
  const store = createSqliteRecordStore(db);
  const auth: PdppAuthorizationService = {
    async resolveToken(token) {
      if (token === "wrong-owner") {
        return {
          active: true,
          tokenKind: "owner",
          subjectId: "0xother",
          sourceId: SOURCE,
        };
      }
      if (token === "owner") {
        return {
          active: true,
          tokenKind: "owner",
          subjectId: OWNER,
          sourceId: SOURCE,
          instanceIds: [A],
        };
      }
      if (token === "owner-wide") {
        return {
          active: true,
          tokenKind: "owner",
          subjectId: OWNER,
          sourceId: SOURCE,
          instanceIds: [A, B],
        };
      }
      return { active: false };
    },
  };
  const app = pdppConnectionRoutes({
    store,
    nativeStore: store,
    declarations: [snapshot],
    auth,
    ownerSubjectId: OWNER,
    connectionMethods: new Map([[SOURCE, ["spotify"]]]),
    configuredMethods: new Map(),
    canonicalSourceIds: new Set([SOURCE]),
    sourceIds: new Set([SOURCE]),
  });

  afterEach(() => {
    db.exec(
      "DELETE FROM pdpp_records; DELETE FROM pdpp_record_changes; DELETE FROM pdpp_record_first_added; DELETE FROM pdpp_additions_coverage; DELETE FROM pdpp_instance_binding;",
    );
  });

  function requestSelection(instanceIds?: string[]): SelectionRequest {
    return {
      type: PDPP_DATA_ACCESS_TYPE,
      source: { id: SOURCE },
      purpose_code: "https://example.test/purpose",
      access_mode: "single_use",
      streams: [
        {
          name: "playlists",
          fields: ["id", "title"],
          ...(instanceIds && { instance_ids: instanceIds }),
        },
      ],
    };
  }

  async function status(
    selection: SelectionRequest,
    extra: Record<string, unknown> = {},
    token = "owner",
  ) {
    return app.request("/pdpp/v1/selection-status", {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        selection,
        expected_declaration: {
          version: snapshot.version,
          digest: snapshot.digest,
        },
        ...extra,
      }),
    });
  }

  function connect(instance: string) {
    store.registerConnection({
      instance,
      sourceId: SOURCE,
      method: "spotify",
      label: "Personal",
    });
  }

  function ingest(instance: string, key: string, title: string) {
    return store.ingestBatch(
      [
        {
          instance,
          stream: "playlists",
          key,
          data: { id: key, title, created_at: "2026-10-24T00:00:00.000Z" },
          emitted_at: "2026-10-24T00:00:00.000Z",
        },
      ],
      () => "mutable_state",
      () => ["id"],
      { method: "spotify", generation: 1 },
    );
  }

  it("includes declared empty streams and current validated completion receipts in opt-in inventory", async () => {
    connect(A);
    expect(ingest(A, "one", "First").accepted).toBe(1);
    const at = new Date().toISOString();
    const receipt = {
      instance: A,
      stream: "playlists",
      sourceId: SOURCE,
      method: "spotify",
      generation: 1,
      sourceCollectedAt: at,
      collectionTimeBasis: "host_run_finished" as const,
      streams: [
        {
          stream: "playlists",
          coverage: "full_stream" as const,
          liveCount: 1,
          snapshotSha256: liveSnapshotDigest(
            {
              sourceId: SOURCE,
              instance: A,
              method: "spotify",
              generation: 1,
              stream: "playlists",
            },
            ["id"],
            [
              {
                recordKey: "one",
                dataJson:
                  '{"id":"one","title":"First","created_at":"2026-10-24T00:00:00.000Z"}',
              },
            ],
          ),
        },
      ],
    };
    store.completeStreams(receipt, () => ["id"]);
    const response = await app.request(
      `/pdpp/connections?source_id=${encodeURIComponent(SOURCE)}&include=streams`,
      { headers: { authorization: "Bearer owner" } },
    );
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body).toMatchObject({
      source: {
        id: SOURCE,
        source_declaration: {
          version: snapshot.version,
          digest: snapshot.digest,
        },
      },
      connections: [
        {
          connection_id: A,
          streams: [
            {
              name: "playlists",
              record_count: 1,
              completion: { status: "current", receipt: { live_count: 1 } },
            },
            {
              name: "artists",
              record_count: null,
              completion: { status: "missing", receipt: null },
            },
          ],
        },
      ],
    });
  });

  it("reports ready, not_ready, choice_required, and unknown selection states", async () => {
    connect(A);
    expect(ingest(A, "one", "First").accepted).toBe(1);
    const ready = await status(requestSelection(), {
      requirements: { playlists: { min_records: 1 } },
    });
    expect((await ready.json()).status).toBe("ready");

    const notReady = await status(requestSelection(), {
      requirements: { playlists: { min_records: 2 } },
    });
    expect((await notReady.json()).status).toBe("not_ready");

    connect(B);
    const choiceRequired = await status(requestSelection(), {}, "owner-wide");
    expect((await choiceRequired.json()).status).toBe("choice_required");

    const unknown = await status({
      ...requestSelection(),
      streams: [{ name: "missing", fields: ["id"] }],
    });
    expect((await unknown.json()).status).toBe("unknown");
  });

  it("counts only records inside resolved resources and time windows", async () => {
    connect(A);
    expect(ingest(A, "one", "First").accepted).toBe(1);
    expect(ingest(A, "two", "Second").accepted).toBe(1);
    const resourceSelection = requestSelection();
    resourceSelection.streams[0]!.resources = ["missing"];
    const resourceStatus = await status(resourceSelection, {
      requirements: { playlists: { min_records: 1 } },
    });
    expect(await resourceStatus.json()).toMatchObject({
      status: "not_ready",
      streams: [{ record_count: 0, count_exact: true }],
    });

    const timeSelection = requestSelection();
    timeSelection.streams[0]!.time_range = {
      since: "2026-10-25T00:00:00.000Z",
    };
    const timeStatus = await status(timeSelection, {
      requirements: { playlists: { min_records: 1 } },
    });
    expect(await timeStatus.json()).toMatchObject({
      status: "not_ready",
      streams: [{ record_count: 0, count_exact: true }],
    });
  });

  it("reports unknown when a stream has quarantined rows and no receipt", async () => {
    connect(A);
    expect(ingest(A, "visible", "Visible").accepted).toBe(1);
    expect(ingest(A, "held", "Quarantined").accepted).toBe(1);
    db.prepare(
      "INSERT INTO pdpp_replica_quarantined_keys VALUES (?, ?, ?, ?)",
    ).run(A, 1, "playlists", "held");
    const response = await status(requestSelection(), {
      requirements: { playlists: { min_records: 1 } },
    });
    expect(await response.json()).toMatchObject({
      status: "unknown",
      streams: [{ record_count: null, count_exact: false }],
    });
  });

  it("rejects non-string instance choices instead of widening the selection", async () => {
    connect(A);
    expect(ingest(A, "one", "First").accepted).toBe(1);
    const response = await status(requestSelection(), {
      instance_choices: { playlists: { playlists: 42 } },
    });
    expect(await response.json()).toMatchObject({
      status: "unknown",
      reasons: [{ code: "invalid_instance_choice" }],
    });
  });

  it("returns first-added metrics for the requested half-open interval", async () => {
    connect(A);
    const since = store.firstAddedCoverage([A])[0]?.trackedSince;
    if (!since) throw new Error("expected tracked additions coverage");
    const until = new Date(Date.now() + 60_000).toISOString();
    expect(ingest(A, "one", "First").accepted).toBe(1);
    const historical = await app.request(
      `/pdpp/v1/metrics/additions?source_id=${encodeURIComponent(SOURCE)}&since=2026-01-01T00:00:00.000Z&until=${encodeURIComponent(until)}`,
      { headers: { authorization: "Bearer owner" } },
    );
    expect(await historical.json()).toMatchObject({
      coverage: "partial",
      added: null,
      streams: [
        { name: "playlists", instance_id: A, added: null },
        { name: "artists", instance_id: A, added: null },
      ],
    });
    const response = await app.request(
      `/pdpp/v1/metrics/additions?source_id=${encodeURIComponent(SOURCE)}&since=${encodeURIComponent(since)}&until=${encodeURIComponent(until)}`,
      { headers: { authorization: "Bearer owner" } },
    );
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      coverage: "complete",
      tracked_since: expect.any(String),
      added: 1,
      streams: [
        { name: "playlists", instance_id: A, added: 1 },
        { name: "artists", instance_id: A, added: 0 },
      ],
    });
  });

  it("records first-added within the write interval and preserves it on update", () => {
    connect(A);
    const before = Date.now();
    expect(ingest(A, "one", "First").accepted).toBe(1);
    const after = Date.now();
    const firstAdded = () =>
      (
        db
          .prepare(
            "SELECT first_added_at FROM pdpp_record_first_added WHERE instance = ? AND stream = ? AND record_key = ?",
          )
          .get(A, "playlists", "one") as { first_added_at: string }
      ).first_added_at;
    const initial = firstAdded();
    expect(Date.parse(initial)).toBeGreaterThanOrEqual(before - 1000);
    expect(Date.parse(initial)).toBeLessThanOrEqual(after + 1000);
    expect(ingest(A, "one", "Updated").accepted).toBe(1);
    expect(firstAdded()).toBe(initial);
  });

  it("enforces owner identity and the token's instance ceiling on all new views", async () => {
    connect(A);
    const inventory = await app.request(
      `/pdpp/connections?source_id=${encodeURIComponent(SOURCE)}&include=streams`,
      { headers: { authorization: "Bearer wrong-owner" } },
    );
    expect(inventory.status).toBe(401);

    for (const path of [
      "/pdpp/v1/selection-status",
      "/pdpp/v1/metrics/additions?source_id=https%3A%2F%2Fregistry.pdpp.dev%2Fconnectors%2Fspotify&since=2026-10-23T00%3A00%3A00.000Z&until=2026-10-25T00%3A00%3A00.000Z",
    ]) {
      const response = await app.request(path, {
        method: path.includes("selection-status") ? "POST" : "GET",
        headers: {
          authorization: "Bearer wrong-owner",
          "content-type": "application/json",
        },
        ...(path.includes("selection-status")
          ? {
              body: JSON.stringify({
                selection: requestSelection(),
                expected_declaration: {
                  version: snapshot.version,
                  digest: snapshot.digest,
                },
              }),
            }
          : {}),
      });
      expect(response.status).toBe(401);
    }

    const since = "2026-10-23T00:00:00.000Z";
    const until = "2026-10-25T00:00:00.000Z";
    const metrics = await app.request(
      `/pdpp/v1/metrics/additions?source_id=${encodeURIComponent(SOURCE)}&instance_id=${encodeURIComponent(B)}&since=${since}&until=${until}`,
      { headers: { authorization: "Bearer owner" } },
    );
    expect(metrics.status).toBe(403);

    const deniedSelection = await status(requestSelection([B]));
    expect(deniedSelection.status).toBe(403);
  });
});
