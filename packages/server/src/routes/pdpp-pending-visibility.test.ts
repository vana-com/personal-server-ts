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
    const blobs = pdppBlobsRoutes({
      ...deps,
      readBlobBytes: async (id: string) => store.getBlobBytes(id),
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
  } finally {
    db.close();
  }
});
