import { createHash } from "node:crypto";
import Database from "better-sqlite3";
import { expect, it } from "vitest";
import { createFixtureAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth.test-utils";
import { createStreamDeclarationRegistry } from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import {
  binding,
  identity,
  registration,
  upsert,
} from "@opendatalabs/personal-server-ts-core/replication/fixtures";
import { createSqliteRecordStore } from "../storage/pdpp-records-sqlite-store.js";
import { createReplicaReceiver } from "../storage/pdpp-replication-receiver.js";
import {
  pdppRecordsRoutes,
  type PdppRecordsRouteDeps,
} from "./pdpp-records.js";

import { pdppBlobsRoutes, type PdppBlobsRouteDeps } from "./pdpp-blobs.js";

it("serves owner pending markers while the same grant sees nothing until promotion", async () => {
  const db = new Database(":memory:");
  try {
    const store = createSqliteRecordStore(db);
    store.registerConnection({
      instance: identity.connectionId,
      sourceId: identity.sourceId,
      method: identity.methodId,
      label: "test",
    });
    store.replication.beginBaseline({
      owner: identity.owner,
      declarations: [{ sourceId: identity.sourceId, binding }],
    });
    const receiver = createReplicaReceiver({
      db,
      store,
      owner: identity.owner,
      enabled: true,
      authenticate: (c) => (c === "replica" ? identity.owner : undefined),
      declarations: () => [
        { sourceId: identity.sourceId, binding, validateData: () => true },
      ],
    });
    const declarations = createStreamDeclarationRegistry([
      {
        name: binding.stream,
        semantics: binding.semantics,
        primaryKey: ["id"],
        cursorField: "emitted_at",
        requiredFields: ["id"],
      },
    ]);
    const auth = createFixtureAuthorizationService({
      owner: {
        active: true,
        tokenKind: "owner",
        subjectId: identity.owner,
        instanceIds: [identity.connectionId],
      },
      app: {
        active: true,
        tokenKind: "client",
        subjectId: identity.owner,
        grant: {
          version: "0.1.0",
          grant_id: "grant",
          issued_at: "2026-01-01T00:00:00Z",
          subject: { id: identity.owner },
          client: { client_id: "client" },
          source: { kind: "provider_native", id: identity.sourceId },
          source_declaration: { version: "1" },
          purpose_code: "test",
          access_mode: "continuous",
          streams: [
            {
              name: binding.stream,
              instance_ids: [identity.connectionId],
              fields: ["id", "text", "blob_ref"],
            },
          ],
        },
      },
    });
    const deps = {
      store,
      auth,
      declarations,
      bindingStore: store,
      instancesForSubject: () => [identity.connectionId],
      replicaReads: (reader: "owner" | "grant") =>
        receiver.readStore({ reader }),
    };
    const app = pdppRecordsRoutes(deps as PdppRecordsRouteDeps);
    let confirmedBlobReads = 0;
    const blobs = pdppBlobsRoutes({
      ...deps,
      readBlobBytes: async (id: string) => {
        confirmedBlobReads++;
        return store.getBlobBytes(id);
      },
    } as PdppBlobsRouteDeps);
    const bytes = new TextEncoder().encode("pending binary");
    const blobId = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
    const blob = {
      blobId,
      sha256: blobId,
      mimeType: "application/octet-stream",
      sizeBytes: bytes.length,
    };
    const record = upsert("pending", 5);
    record.blobs = [blob];
    record.data.blob_ref = {
      blob_id: blobId,
      mime_type: blob.mimeType,
      size_bytes: bytes.length,
    };
    const readBlob = (token: string) =>
      blobs.request(`/${blobId}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
    const read = async (token: string, suffix = "") => {
      const res = await app.request(`/streams/messages/records${suffix}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      return { status: res.status, body: await res.json() };
    };
    receiver.stage({
      id: "batch",
      credential: "replica",
      blobs: [{ blobId, bytes }],
      envelope: {
        format: "vana-pdpp-replica",
        version: 1,
        owner: identity.owner,
        batchId: "batch",
        operations: [
          registration,
          {
            ...identity,
            kind: "blob-claim",
            blob,
            revision: {
              counter: 4,
              writerId: "device-a",
              operationId: "claim",
            },
          },
          record,
        ],
      },
    });
    const owner = await read("owner");
    expect(owner.status).toBe(200);
    expect(owner.body.data).toEqual([
      expect.objectContaining({
        id: "same-key",
        confirmation: "not yet confirmed",
        data: expect.objectContaining({ id: "same-key", text: "pending" }),
      }),
    ]);
    expect((await read("owner", "/same-key")).body.confirmation).toBe(
      "not yet confirmed", // copy-assertion-ok: User-required data-model confirmation value.
    );
    expect((await read("app")).body.data).toEqual([]);
    expect((await read("app", "/same-key")).status).toBe(404);
    expect((await readBlob("app")).status).toBe(404);
    const ownerBlob = await readBlob("owner");
    expect(ownerBlob.status).toBe(200);
    expect(new Uint8Array(await ownerBlob.arrayBuffer())).toEqual(bytes);
    receiver.promote({ id: "batch", credential: "replica" });
    const appBlob = await readBlob("app");
    expect(appBlob.status).toBe(200);
    expect(confirmedBlobReads).toBe(1);
    expect(new Uint8Array(await appBlob.arrayBuffer())).toEqual(bytes);
    expect((await read("app")).body.data).toEqual([
      expect.objectContaining({
        id: "same-key",
        data: expect.objectContaining({ id: "same-key", text: "pending" }),
      }),
    ]);
    expect((await read("owner", "/same-key")).body).not.toHaveProperty(
      "confirmation",
    );
    // Every pending removal must stay distinguishable from confirmed absence.
    for (const kind of [
      "delete",
      "connection-reset",
      "connection-delete",
    ] as const) {
      const revision = {
        counter: 100,
        writerId: "device-b",
        operationId: kind,
      };
      const removal =
        kind === "delete"
          ? {
              ...identity,
              kind,
              revision,
              declaration: binding,
              recordKey: "same-key",
              emittedAt: "2026-10-21T00:00:00Z",
              deletedAt: "2026-10-21T00:00:00Z",
            }
          : kind === "connection-reset"
            ? {
                ...identity,
                kind,
                revision,
                generation: 2,
                previousGeneration: 1,
              }
            : { ...identity, kind, revision };
      receiver.stage({
        id: kind,
        credential: "replica",
        envelope: {
          format: "vana-pdpp-replica",
          version: 1,
          owner: identity.owner,
          batchId: kind,
          operations: [removal],
        },
      });
      const summary = await app.request("/streams", {
        headers: { Authorization: "Bearer owner" },
      });
      expect((await summary.json()).data).toMatchObject([
        {
          name: "messages",
          record_count: 0,
          confirmation: "not yet confirmed",
        },
      ]);
      const pendingPoint = await read("owner", "/same-key");
      expect(pendingPoint.status).toBe(200);
      expect(pendingPoint.body).toMatchObject({
        deleted: true,
        confirmation: "not yet confirmed",
      });
      expect(pendingPoint.body).not.toHaveProperty("data");
      expect((await read("owner")).body.data).toMatchObject([
        { deleted: true, confirmation: "not yet confirmed" },
      ]);
      expect((await read("app", "/same-key")).body).toMatchObject({
        data: { text: "pending" },
      });
      expect((await readBlob("owner")).status).toBe(404);
      expect((await readBlob("app")).status).toBe(200);
      receiver.quarantine({
        id: kind,
        credential: "replica",
        reason: "finalized mismatch",
      });
      expect((await read("owner", "/same-key")).body).toMatchObject({
        data: { text: "pending" },
      });
      expect((await read("owner", "/same-key")).body).not.toHaveProperty(
        "confirmation",
      );
    }
    const finalRemoval = {
      ...identity,
      kind: "delete",
      revision: {
        counter: 101,
        writerId: "device-b",
        operationId: "final-delete",
      },
      declaration: binding,
      recordKey: "same-key",
      emittedAt: "2026-10-21T00:00:00Z",
      deletedAt: "2026-10-21T00:00:00Z",
    };
    receiver.stage({
      id: "final-delete",
      credential: "replica",
      envelope: {
        format: "vana-pdpp-replica",
        version: 1,
        owner: identity.owner,
        batchId: "final-delete",
        operations: [finalRemoval],
      },
    });
    receiver.promote({ id: "final-delete", credential: "replica" });
    expect((await read("owner", "/same-key")).status).toBe(404);
    expect((await read("app", "/same-key")).status).toBe(404);
    expect((await read("owner")).body.data).toEqual([]);
    expect((await read("app")).body.data).toEqual([]);
  } finally {
    db.close();
  }
});

it("keeps the visible row's instance when rebinding a multi-connection page cursor", async () => {
  const db = new Database(":memory:");
  try {
    const store = createSqliteRecordStore(db);
    const ids = ["conn_a", "conn_b", "conn_c"];
    for (const instance of ids)
      store.registerConnection({
        instance,
        sourceId: identity.sourceId,
        method: identity.methodId,
        label: instance,
      });
    store.replication.beginBaseline({
      owner: identity.owner,
      declarations: [{ sourceId: identity.sourceId, binding }],
    });
    for (const instance of ids)
      store.ingestBatch(
        [
          {
            instance,
            stream: binding.stream,
            key: "same-key",
            data: { id: "same-key", instance },
            emitted_at: "2026-10-21T00:00:00.000Z",
          },
        ],
        () => binding.semantics,
        () => ["id"],
        { method: identity.methodId, generation: 1 },
      );
    const receiver = createReplicaReceiver({
      db,
      store,
      owner: identity.owner,
      enabled: true,
      authenticate: () => identity.owner,
      declarations: () => [
        { sourceId: identity.sourceId, binding, validateData: () => true },
      ],
    });
    const auth = createFixtureAuthorizationService({
      owner: {
        active: true,
        tokenKind: "owner",
        subjectId: identity.owner,
        instanceIds: ids,
      },
    });
    const declarations = createStreamDeclarationRegistry([
      {
        name: binding.stream,
        semantics: binding.semantics,
        primaryKey: ["id"],
        cursorField: "emitted_at",
        requiredFields: ["id"],
      },
    ]);
    const app = pdppRecordsRoutes({
      store,
      auth,
      declarations,
      bindingStore: store,
      instancesForSubject: () => ids,
      replicaReads: (reader) => receiver.readStore({ reader }),
    });
    const seen: string[] = [];
    let cursor: string | undefined;
    do {
      const response = await app.request(
        `/streams/messages/records?limit=1&order=asc${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`,
        { headers: { Authorization: "Bearer owner" } },
      );
      expect(response.status).toBe(200);
      const page = await response.json();
      seen.push(
        ...page.data.map(
          (row: { data: { instance: string } }) => row.data.instance,
        ),
      );
      cursor = page.next_cursor;
    } while (cursor);
    expect(seen).toEqual(ids);
  } finally {
    db.close();
  }
});

it("uses local journal values for conflicted owners and hides the whole connection from apps", async () => {
  const db = new Database(":memory:");
  try {
    const store = createSqliteRecordStore(db);
    // The hardening lane owns migration 18 and its monotone fact writer.
    db.exec(
      "CREATE TABLE IF NOT EXISTS pdpp_replica_binding_conflicts(instance TEXT PRIMARY KEY); CREATE INDEX IF NOT EXISTS local_journal_lookup ON pdpp_mutation_journal(connection_id,generation,stream,record_key,sequence DESC)",
    );
    store.registerConnection({
      instance: identity.connectionId,
      sourceId: identity.sourceId,
      method: identity.methodId,
      label: "B",
    });
    store.replication.beginBaseline({
      owner: identity.owner,
      declarations: [{ sourceId: identity.sourceId, binding }],
    });
    const bytes = new TextEncoder().encode("known local bytes");
    const blob = store.storeBlobBytesForInstance({
      instance: identity.connectionId,
      method: identity.methodId,
      generation: 1,
      bytes,
      mimeType: "application/octet-stream",
    });
    const at = "2026-10-21T00:00:00.000Z";
    const putLocal = (key: string, text: string) =>
      store.ingestBatch(
        [
          {
            instance: identity.connectionId,
            stream: binding.stream,
            key,
            emitted_at: at,
            data: {
              id: key,
              text,
              blob_ref: {
                blob_id: blob.blobId,
                sha256: blob.sha256,
                mime_type: blob.mimeType,
                size_bytes: blob.sizeBytes,
              },
            },
          },
        ],
        () => binding.semantics,
        () => ["id"],
        { method: identity.methodId, generation: 1 },
      );
    putLocal("local-live", "local B");
    putLocal("local-deleted", "old local B");
    store.deleteRecord(
      identity.connectionId,
      binding.stream,
      "local-deleted",
      at,
      binding.semantics,
    );
    const receiver = createReplicaReceiver({
      db,
      store,
      owner: identity.owner,
      enabled: true,
      authenticate: () => identity.owner,
      declarations: () => [
        { sourceId: identity.sourceId, binding, validateData: () => true },
      ],
    });
    const remote = (key: string, counter: number) => ({
      ...upsert(`received-${key}`, counter),
      recordKey: key,
      data: { id: key, text: "received B" },
    });
    receiver.import({
      credential: "replica",
      envelope: {
        format: "vana-pdpp-replica",
        version: 1,
        owner: identity.owner,
        batchId: "received-B",
        operations: [
          registration,
          remote("local-live", 100),
          remote("local-deleted", 101),
          remote("received-only", 102),
        ],
      },
    });
    receiver.stage({
      credential: "replica",
      id: "pending-B",
      envelope: {
        format: "vana-pdpp-replica",
        version: 1,
        owner: identity.owner,
        batchId: "pending-B",
        operations: [remote("pending-only", 103)],
      },
    });
    const auth = createFixtureAuthorizationService({
      owner: {
        active: true,
        tokenKind: "owner",
        subjectId: identity.owner,
        instanceIds: [identity.connectionId],
      },
      app: {
        active: true,
        tokenKind: "client",
        subjectId: identity.owner,
        grant: {
          version: "0.1.0",
          grant_id: "conflict-grant",
          issued_at: at,
          subject: { id: identity.owner },
          client: { client_id: "app" },
          source: { kind: "provider_native", id: identity.sourceId },
          source_declaration: { version: "1" },
          purpose_code: "test",
          access_mode: "continuous",
          streams: [
            {
              name: binding.stream,
              instance_ids: [identity.connectionId],
              fields: ["id", "text", "blob_ref"],
            },
          ],
        },
      },
    });
    const declarations = createStreamDeclarationRegistry([
      {
        name: binding.stream,
        semantics: binding.semantics,
        primaryKey: ["id"],
        cursorField: "emitted_at",
        requiredFields: ["id"],
      },
    ]);
    const deps = {
      store,
      auth,
      declarations,
      bindingStore: store,
      instancesForSubject: () => [identity.connectionId],
      replicaReads: (reader: "owner" | "grant") =>
        receiver.readStore({ reader }),
    };
    const app = pdppRecordsRoutes(deps);
    const blobs = pdppBlobsRoutes({
      ...deps,
      readBlobBytes: async (id) => store.getBlobBytes(id),
    });
    const read = async (token: string, path: string) => {
      const response = await app.request(path, {
        headers: { Authorization: `Bearer ${token}` },
      });
      return { status: response.status, body: await response.json() };
    };
    const readBlob = (token: string) =>
      blobs.request(`/${blob.blobId}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
    const oldFeeds = await Promise.all(
      ["owner", "app"].map(async (token) => ({
        token,
        page: await read(
          token,
          "/streams/messages/records?changes_since=&limit=1",
        ),
        session: await read(token, "/streams/messages/records?changes_since="),
        list: await read(token, "/streams/messages/records?limit=1&order=asc"),
      })),
    );
    for (const old of oldFeeds) {
      expect(old.page.body.next_cursor).toBeDefined();
      expect(old.session.body.next_changes_since).toBeDefined();
      expect(old.list.body.next_cursor).toBeDefined();
      expect(
        old.session.body.data.some(
          (row: { id: string }) => row.id === "pending-only",
        ),
      ).toBe(false);
    }
    const before = db
      .prepare("SELECT * FROM pdpp_records ORDER BY record_key")
      .all();
    const history = db
      .prepare("SELECT COUNT(*) AS n FROM pdpp_record_changes")
      .get();
    // Simulate the agreed external fact writer and its existing cursor fence.
    db.transaction(() => {
      db.prepare("INSERT INTO pdpp_replica_binding_conflicts VALUES (?)").run(
        identity.connectionId,
      );
      db.prepare("UPDATE pdpp_write_clock SET value=value+1 WHERE id=1").run();
      db.prepare(
        "UPDATE pdpp_instance_binding SET reset_clock=(SELECT value FROM pdpp_write_clock WHERE id=1) WHERE instance=?",
      ).run(identity.connectionId);
    })();
    for (const old of oldFeeds) {
      expect(
        (await read(old.token, "/streams/messages/records?changes_since=")).body
          .data,
      ).toEqual([]);
      expect(
        (
          await read(
            old.token,
            `/streams/messages/records?changes_since=&cursor=${encodeURIComponent(old.page.body.next_cursor)}`,
          )
        ).status,
      ).toBe(410);
      expect(
        (
          await read(
            old.token,
            `/streams/messages/records?changes_since=${encodeURIComponent(old.session.body.next_changes_since)}`,
          )
        ).status,
      ).toBe(410);
      expect(
        (
          await read(
            old.token,
            `/streams/messages/records?limit=1&order=asc&cursor=${encodeURIComponent(old.list.body.next_cursor)}`,
          )
        ).status,
      ).toBe(410);
    }
    const owner = await read("owner", "/streams/messages/records?order=asc");
    expect(owner.status).toBe(200);
    expect(owner.body.data).toEqual([
      expect.objectContaining({
        id: "local-live",
        data: expect.objectContaining({ text: "local B" }),
        visibility: "conflicted",
        status: "account conflict",
      }),
    ]);
    expect(
      (await read("owner", "/streams/messages/records/local-live")).body,
    ).toMatchObject({
      data: { text: "local B" },
      visibility: "conflicted",
      status: "account conflict",
    });
    for (const key of ["local-deleted", "received-only", "pending-only"])
      expect(
        (await read("owner", `/streams/messages/records/${key}`)).status,
      ).toBe(404);
    expect((await read("app", "/streams/messages/records")).body.data).toEqual(
      [],
    );
    expect((await read("app", "/streams")).body.data).toEqual([]);
    expect(
      (await read("app", "/streams/messages/records/local-live")).status,
    ).toBe(404);
    expect((await readBlob("app")).status).toBe(404);
    const ownerBlob = await readBlob("owner");
    expect(ownerBlob.status).toBe(200);
    expect(new Uint8Array(await ownerBlob.arrayBuffer())).toEqual(bytes);
    expect((await read("owner", "/streams")).body.data).toMatchObject([
      {
        name: "messages",
        record_count: 1,
        visibility: "conflicted",
        status: "account conflict",
      },
    ]);
    expect(
      db.prepare("SELECT * FROM pdpp_records ORDER BY record_key").all(),
    ).toEqual(before);
    expect(
      db.prepare("SELECT COUNT(*) AS n FROM pdpp_record_changes").get(),
    ).toEqual(history);
    // Corruption quarantine overrides even the owner's known local projection.
    db.prepare(
      "INSERT INTO pdpp_replica_quarantined_keys VALUES (?,?,?,?)",
    ).run(identity.connectionId, 1, binding.stream, "local-live");
    expect(
      (await read("owner", "/streams/messages/records/local-live")).status,
    ).toBe(404);
    expect(
      (await read("owner", "/streams/messages/records")).body.data,
    ).toEqual([]);
    expect((await readBlob("owner")).status).toBe(404);
  } finally {
    db.close();
  }
});
