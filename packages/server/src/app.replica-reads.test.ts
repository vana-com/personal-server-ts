import { createHash } from "node:crypto";
import pino from "pino";
import { afterEach, describe, expect, it } from "vitest";
import { createFixtureAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth.test-utils";
import {
  binding,
  registration,
  upsert,
} from "@opendatalabs/personal-server-ts-core/replication/fixtures";
import { createStreamDeclarationRegistry } from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { createLegacyScopeView } from "@opendatalabs/personal-server-ts-core/storage/legacy-scope-view";
import { createApp, type AppDeps } from "./app.js";
import { legacyScopeRecords } from "./pdpp/records-bootstrap.js";
import { createIndexManager } from "./storage/index-manager.js";
import { initializeDatabase } from "./storage/index-schema.js";
import { createLegacyScopeAuthority } from "./storage/legacy-scope-authority.js";
import { createSqliteRecordStore } from "./storage/pdpp-records-sqlite-store.js";
import { createReplicaReceiver } from "./storage/pdpp-replication-receiver.js";

// The host composes an enabled receiver with the real app. Every
// canonical-derived HTTP response must come from the reader the token selects.
const owner = "owner-a";
const sourceId = "https://registry.pdpp.dev/sources/oura";
const method = "oura";
const instance = "conn_a";
const stream = "activity";
const declaration = { ...binding, stream };
const ids = {
  owner,
  sourceId,
  methodId: method,
  connectionId: instance,
  generation: 1 as const,
};

const closers: (() => void)[] = [];
afterEach(() => {
  while (closers.length) closers.pop()!();
});

function host() {
  const db = initializeDatabase(":memory:");
  const store = createSqliteRecordStore(db);
  store.registerConnection({ instance, sourceId, method, label: "A" });
  const declarations = [
    { sourceId, binding: declaration, validateData: () => true },
  ];
  store.replication.beginBaseline({ owner, declarations });
  // The durable source-conflict fact table belongs to the synthesis lane.
  db.exec(
    "CREATE TABLE pdpp_replica_binding_conflicts (instance TEXT PRIMARY KEY)",
  );
  const receiver = createReplicaReceiver({
    db,
    store,
    owner,
    enabled: true,
    authenticate: () => owner,
    declarations: () => declarations,
  });
  const auth = createFixtureAuthorizationService({
    owner: {
      active: true,
      tokenKind: "owner",
      subjectId: owner,
      instanceIds: [instance],
    },
    app: {
      active: true,
      tokenKind: "client",
      subjectId: owner,
      grant: {
        version: "0.1.0",
        grant_id: "grant",
        issued_at: "2026-01-01T00:00:00Z",
        subject: { id: owner },
        client: { client_id: "client" },
        source: { kind: "provider_native", id: sourceId },
        source_declaration: { version: "1" },
        purpose_code: "test",
        access_mode: "continuous",
        streams: [
          {
            name: stream,
            instance_ids: [instance],
            fields: ["id", "day", "score", "blob_ref"],
          },
        ],
      },
    },
  });
  const pdpp = {
    store,
    bindingStore: store,
    configuredMethods: new Map([[sourceId, [method]]]),
    auth,
    declarations: createStreamDeclarationRegistry([
      {
        name: stream,
        semantics: declaration.semantics,
        primaryKey: ["id"],
        cursorField: "emitted_at",
        requiredFields: ["id"],
      },
    ]),
    instancesForSubject: () => [instance],
    readBlobBytes: async (id: string) => store.getBlobBytes(id),
    resource: "http://localhost:8080",
    // The host-owned reader capability, selected per authenticated token.
    reads: (reader: "owner" | "grant") => receiver.readStore({ reader }),
  };
  const indexManager = createIndexManager(db);
  const app = createApp({
    logger: pino({ level: "silent" }),
    version: "test",
    startedAt: new Date(),
    indexManager,
    hierarchyOptions: { dataDir: "/nonexistent-replica-reads-test" },
    serverOrigin: "http://localhost:8080",
    serverOwner: owner,
    devToken: "legacy-owner",
    gateway: {} as AppDeps["gateway"],
    accessLogWriter: { write: async () => {} },
    accessLogReader: {
      read: async () => ({ logs: [], total: 0, limit: 50, offset: 0 }),
    },
    pdpp,
    // Composed exactly as bootstrap composes it.
    legacyScopeView: createLegacyScopeView({
      authority: createLegacyScopeAuthority(db),
      records: legacyScopeRecords(pdpp),
      configuredMethods: () => [method],
    }),
  } as AppDeps);
  closers.push(() => store.close());
  const get = async (token: string, path: string, method = "GET") => {
    const res = await app.request(path, {
      method,
      headers: { Authorization: `Bearer ${token}` },
    });
    const text = await res.text();
    return {
      status: res.status,
      body:
        text && res.headers.get("content-type")?.includes("json")
          ? JSON.parse(text)
          : text,
    };
  };
  const envelope = (batchId: string, operations: unknown[]) => ({
    format: "vana-pdpp-replica",
    version: 1,
    owner,
    batchId,
    operations,
  });
  const bytes = new TextEncoder().encode("activity attachment");
  const blobId = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
  const blob = {
    blobId,
    sha256: blobId,
    mimeType: "text/plain",
    sizeBytes: bytes.length,
  };
  const row = (operationId: string, counter: number, key: string) => ({
    ...upsert(operationId, counter),
    ...ids,
    declaration,
    recordKey: key,
    blobs: [blob],
    data: {
      id: key,
      day: "2026-08-01",
      score: 80,
      steps: 1000,
      contributors: {},
      blob_ref: { blob_id: blobId, mime_type: blob.mimeType, size_bytes: 19 },
    },
  });
  // A blob-backed upsert needs a claim for its bytes in the same envelope.
  const claim = (operationId: string, counter: number) => ({
    ...ids,
    kind: "blob-claim",
    blob,
    revision: { counter, writerId: "device-a", operationId },
  });
  return {
    db,
    receiver,
    get,
    envelope,
    row,
    claim,
    bytes,
    blobId,
    registration: { ...registration, ...ids },
  };
}

describe("createApp with an enabled replica receiver", () => {
  it("serves an owner pending row on every owner surface and none to the grant", async () => {
    const h = host();
    h.receiver.stage({
      credential: "x",
      id: "pending",
      envelope: h.envelope("pending", [
        h.registration,
        h.claim("pending-claim", 4),
        h.row("pending", 5, "pending-key"),
      ]),
      blobs: [{ blobId: h.blobId, bytes: h.bytes }],
    });

    const point = await h.get(
      "owner",
      `/v1/streams/${stream}/records/pending-key`,
    );
    expect(point.status).toBe(200);
    expect(point.body).toMatchObject({
      id: "pending-key",
      confirmation: "not yet confirmed",
    });
    const page = await h.get("owner", `/v1/streams/${stream}/records`);
    expect(page.body.data.map((r: { id: string }) => r.id)).toEqual([
      "pending-key",
    ]);
    const streams = await h.get("owner", "/v1/streams");
    expect(streams.body.data).toEqual([
      expect.objectContaining({ name: stream, record_count: 1 }),
    ]);
    const blob = await h.get("owner", `/v1/blobs/${h.blobId}`);
    expect(blob).toEqual({ status: 200, body: "activity attachment" });

    expect(
      (await h.get("app", `/v1/streams/${stream}/records/pending-key`)).status,
    ).toBe(404);
    expect(
      (await h.get("app", `/v1/streams/${stream}/records`)).body.data,
    ).toEqual([]);
    expect((await h.get("app", "/v1/streams")).body.data).toEqual([]);
    expect(
      (await h.get("app", `/v1/streams/${stream}/records?changes_since=`)).body
        .data,
    ).toEqual([]);
    expect((await h.get("app", `/v1/blobs/${h.blobId}`)).status).toBe(404);

    // `empty` is the binding/reset precondition the store enforces, not
    // visible existence: a pending-only connection holds no canonical row.
    expect(
      (await h.get("owner", `/pdpp/instances/${instance}/binding`)).body,
    ).toMatchObject({ empty: true });
  });

  it("hides a received row under a source conflict from both readers on every surface", async () => {
    const h = host();
    h.receiver.import({
      credential: "x",
      envelope: h.envelope("confirmed", [
        h.registration,
        h.claim("claim", 2),
        h.row("confirmed", 3, "a1"),
      ]),
      blobs: [{ blobId: h.blobId, bytes: h.bytes }],
    });
    // Control: before the fact, both readers see the confirmed row.
    expect(
      (await h.get("app", `/v1/streams/${stream}/records/a1`)).status,
    ).toBe(200);
    expect((await h.get("app", `/v1/blobs/${h.blobId}`)).status).toBe(200);

    h.db
      .prepare("INSERT INTO pdpp_replica_binding_conflicts VALUES (?)")
      .run(instance);

    for (const token of ["app", "owner"]) {
      expect(
        (await h.get(token, `/v1/streams/${stream}/records/a1`)).status,
      ).toBe(404);
      expect(
        (await h.get(token, `/v1/streams/${stream}/records`)).body.data,
      ).toEqual([]);
      expect((await h.get(token, "/v1/streams")).body.data).toEqual([]);
      expect((await h.get(token, `/v1/blobs/${h.blobId}`)).status).toBe(404);
      expect((await h.get(token, `/v1/blobs/${h.blobId}`, "HEAD")).status).toBe(
        404,
      );
    }
    expect(
      (await h.get("app", `/v1/streams/${stream}/records?changes_since=`)).body
        .data,
    ).toEqual([]);
  });

  it("does not project a received-only conflicted row into /v1/data", async () => {
    const h = host();
    h.receiver.import({
      credential: "x",
      envelope: h.envelope("remote", [
        h.registration,
        {
          ...h.row("remote", 2, "a1"),
          blobs: [],
          data: {
            id: "a1",
            day: "2026-08-01",
            score: 80,
            steps: 1000,
            contributors: {},
          },
        },
      ]),
    });
    // Control: the confirmed row lists and projects before the fact exists.
    expect((await h.get("legacy-owner", "/v1/data")).body.scopes).toEqual([
      expect.objectContaining({ scope: "oura.activity" }),
    ]);
    const before = await h.get("legacy-owner", "/v1/data/oura.activity");
    expect(before.status).toBe(200);
    expect(before.body.data.days.map((d: { id: string }) => d.id)).toEqual([
      "a1",
    ]);

    h.db
      .prepare("INSERT INTO pdpp_replica_binding_conflicts VALUES (?)")
      .run(instance);
    expect((await h.get("legacy-owner", "/v1/data")).body.scopes).toEqual([]);
    const after = await h.get("legacy-owner", "/v1/data/oura.activity");
    expect(JSON.stringify(after.body)).not.toContain("2026-08-01");
    expect(after).toMatchObject({
      status: 503,
      body: { status: "unavailable", reason: "no_synced_data" },
    });
  });
});
