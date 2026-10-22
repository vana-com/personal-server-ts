import Database from "better-sqlite3";
import { expect, it } from "vitest";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";

it("transitions an existing Claude connection without losing history, fences old runs and survives retries", () => {
  const db = new Database(":memory:");
  const store = createSqliteRecordStore(db);
  const instance = "claude:0xowner";
  const sourceId = "https://registry.pdpp.dev/sources/claude";
  store.registerConnection({
    instance,
    sourceId,
    method: "anthropic",
    label: "Work",
  });
  const row = {
    instance,
    stream: "conversations",
    key: "old",
    data: { id: "old" },
    emitted_at: "2026-10-21T00:00:00Z",
  };
  store.ingestBatch(
    [row],
    () => "mutable_state",
    () => ["id"],
    { method: "anthropic", generation: 1 },
  );
  const snapshot = {
    scope: "claude.conversations",
    collectedAt: row.emitted_at,
    data: { conversations: [{ id: "old" }] },
  };
  const input = {
    instance,
    expectedGeneration: 1,
    expectedWriteClock: 1,
    snapshots: { "claude.conversations": snapshot },
  };
  expect(store.transitionClaudeToLive(input).method).toBe("anthropic-live");
  expect(store.getInstanceBinding(instance)).toMatchObject({
    generation: 2,
    label: "Work",
    sourceId,
  });
  expect(store.listConnections(sourceId)).toHaveLength(1);
  expect(store.claudeTransition(instance)?.snapshots).toEqual(input.snapshots);
  expect(store.getRecord(instance, "conversations", "old")).toBeUndefined();
  expect(() =>
    store.ingestBatch(
      [row],
      () => "mutable_state",
      () => ["id"],
      { method: "anthropic", generation: 1 },
    ),
  ).toThrow("binding_generation_mismatch");
  store.ingestBatch(
    [{ ...row, key: "new", data: { id: "new" } }],
    () => "mutable_state",
    () => ["id"],
    { method: "anthropic-live", generation: 2 },
  );
  expect(store.transitionClaudeToLive(input).generation).toBe(2);
  expect(store.getRecord(instance, "conversations", "new")?.data.id).toBe(
    "new",
  );
  const archive = store.claudeTransition(instance)!.archiveInstance;
  expect(store.getRecord(archive, "conversations", "old")?.data.id).toBe("old");
  expect(() =>
    store.ingestBatch(
      [{ ...row, instance: archive }],
      () => "mutable_state",
      () => ["id"],
      { method: "anthropic", generation: 1 },
    ),
  ).toThrow("connection_required");
  store.clearClaudeTransitionScope("claude.conversations");
  expect(store.claudeTransition(instance)?.snapshots).toEqual({});
  expect(store.getRecord(archive, "conversations", "old")).toBeUndefined();
  store.deleteConnection(instance);
  expect(store.claudeTransition(instance)).toBeNull();
  expect(store.getRecord(archive, "conversations", "old")).toBeUndefined();
  store.close();
  db.close();
});

it("rejects a stale snapshot and rolls the transition back on database failure", () => {
  const db = new Database(":memory:");
  const store = createSqliteRecordStore(db);
  const instance = "claude:0xowner";
  store.registerConnection({
    instance,
    sourceId: "https://registry.pdpp.dev/sources/claude",
    method: "anthropic",
    label: "Work",
  });
  const input = {
    instance,
    expectedGeneration: 1,
    expectedWriteClock: 0,
    snapshots: {},
  };
  store.ingestBatch(
    [
      {
        instance,
        stream: "conversations",
        key: "old",
        data: { id: "old" },
        emitted_at: "2026-10-21T00:00:00Z",
      },
    ],
    () => "mutable_state",
    () => ["id"],
    { method: "anthropic", generation: 1 },
  );
  expect(() => store.transitionClaudeToLive(input)).toThrow(
    "binding_generation_mismatch",
  );
  db.exec(
    "CREATE TRIGGER fail_transition BEFORE UPDATE ON pdpp_instance_binding BEGIN SELECT RAISE(ABORT, 'injected disk failure'); END",
  );
  expect(() =>
    store.transitionClaudeToLive({ ...input, expectedWriteClock: 1 }),
  ).toThrow("injected disk failure");
  expect(store.getInstanceBinding(instance)).toMatchObject({
    method: "anthropic",
    generation: 1,
  });
  expect(store.getRecord(instance, "conversations", "old")?.data.id).toBe(
    "old",
  );
  expect(store.claudeTransition(instance)).toBeNull();
  store.close();
  db.close();
});

import { createLegacyScopeView } from "@opendatalabs/personal-server-ts-core/storage/legacy-scope-view";
import { createLegacyScopeAuthority } from "./legacy-scope-authority.js";
import { initializeDatabase } from "./index-schema.js";
import { createClaudeMethodTransition } from "./claude-method-transition.js";
import type { DataStoragePort } from "@opendatalabs/personal-server-ts-core/ports";
import type { DataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import { pdppInstanceBindingRoutes } from "../routes/pdpp-instance-bindings.js";

it("preserves the readable baseline through an authenticated transition, incomplete live import and restart", async () => {
  const db = initializeDatabase(":memory:");
  const store = createSqliteRecordStore(db);
  const instance = "claude:0xowner";
  const source = "https://registry.pdpp.dev/sources/claude";
  store.registerConnection({
    instance,
    sourceId: source,
    method: "anthropic",
    label: "Team",
  });
  const saved = {
    scope: "claude.conversations",
    collectedAt: "2026-10-20T00:00:00Z",
    data: {
      organizationId: "team",
      conversations: [
        { id: "old", messages: [{ id: "msg", content: "Existing message" }] },
      ],
    },
  } as unknown as DataFileEnvelope;
  const files = {
    findEntry: ({ scope }: { scope: string }) =>
      scope === saved.scope ? { collectedAt: saved.collectedAt } : undefined,
    readEnvelope: async () => structuredClone(saved),
  } as unknown as DataStoragePort;
  let method = "anthropic";
  const create = () =>
    createClaudeMethodTransition(
      store,
      createLegacyScopeView({
        authority: createLegacyScopeAuthority(db),
        records: store,
        configuredMethods: () => [method],
      }),
      files,
    );
  const transition = create();
  const app = pdppInstanceBindingRoutes({
    store,
    ownerSubjectId: "0xowner",
    configuredMethods: new Map([[instance, ["anthropic"]]]),
    instancesForSubject: () => [instance],
    instancesForSource: () => [instance],
    auth: {
      resolveToken: async (token: string) =>
        token === "owner"
          ? {
              active: true,
              tokenKind: "owner",
              subjectId: "0xowner",
              sourceId: source,
            }
          : { active: false },
    },
    transitionClaude: transition.transition,
  });
  const request = (token: string) =>
    app.request(`/pdpp/instances/${instance}/transition-claude-live`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ expected_generation: 1 }),
    });
  expect((await request("not-owner")).status).toBe(401);
  expect(store.getInstanceBinding(instance).method).toBe("anthropic");
  expect((await request("owner")).status).toBe(200);
  method = "anthropic-live";
  const restarted = create();
  expect(await restarted.view.readLatest(saved.scope)).toMatchObject({
    kind: "canonical",
    envelope: saved,
  });
  store.ingestBatch(
    [
      {
        instance,
        stream: "conversations",
        key: "new",
        data: { id: "new", title: "Partial new import" },
        emitted_at: "2026-10-21T00:00:00Z",
      },
    ],
    () => "mutable_state",
    () => ["id"],
    { method, generation: 2 },
  );
  expect(await restarted.view.readLatest(saved.scope)).toMatchObject({
    kind: "canonical",
    envelope: saved,
  });
  expect((await request("owner")).status).toBe(200);
  store.confirmClaudeTransition(instance, 2);
  expect((await restarted.view.readLatest(saved.scope)).kind).toBe("refused");
  store.deleteConnection(instance);
  expect((await restarted.view.readLatest(saved.scope)).kind).not.toBe(
    "canonical",
  );
  expect((await request("owner")).status).toBe(409);
  store.close();
  db.close();
});
