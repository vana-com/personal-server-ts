import { afterEach, expect, it } from "vitest";
import pino from "pino";
import { createHash } from "node:crypto";
import { createFixtureAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth.test-utils";
import {
  binding,
  identity,
  registration,
  upsert,
} from "@opendatalabs/personal-server-ts-core/replication/fixtures";
import { createStreamDeclarationRegistry } from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { createApp, type AppDeps } from "../app.js";
import { copyReadFixture } from "../storage/pdpp-replica-copy-reads.test-utils.js";
import { initializeDatabase } from "../storage/index-schema.js";
import { createIndexManager } from "../storage/index-manager.js";

const close: (() => void)[] = [];
afterEach(() => {
  while (close.length) close.pop()!();
});
function host(f: ReturnType<typeof copyReadFixture>, capability = true) {
  const index = createIndexManager(initializeDatabase(":memory:"));
  close.push(() => index.close());
  const auth = createFixtureAuthorizationService({
    owner: {
      active: true,
      tokenKind: "owner",
      subjectId: identity.owner,
      instanceIds: [identity.connectionId],
    },
    foreign: {
      active: true,
      tokenKind: "owner",
      subjectId: "another-owner",
      instanceIds: [identity.connectionId],
    },
    narrow: {
      active: true,
      tokenKind: "owner",
      subjectId: identity.owner,
      instanceIds: ["another-connection"],
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
            name: "messages",
            instance_ids: [identity.connectionId],
            fields: ["id", "text", "blob_ref"],
          },
        ],
      },
    },
  });
  const app = createApp({
    logger: pino({ level: "silent" }),
    version: "test",
    startedAt: new Date(),
    indexManager: index,
    hierarchyOptions: { dataDir: "/nonexistent-copy-conflicts" },
    serverOrigin: "http://localhost:8080",
    serverOwner: identity.owner,
    gateway: {} as AppDeps["gateway"],
    accessLogWriter: { write: async () => {} },
    accessLogReader: {
      read: async () => ({ logs: [], total: 0, limit: 50, offset: 0 }),
    },
    pdpp: {
      store: f.store,
      bindingStore: f.store,
      auth,
      resource: "http://localhost:8080",
      instancesForSubject: () => [identity.connectionId, "another-connection"],
      declarations: createStreamDeclarationRegistry([
        {
          name: "messages",
          semantics: binding.semantics,
          primaryKey: ["id"],
          cursorField: "emitted_at",
          requiredFields: ["id"],
        },
      ]),
      reads: capability
        ? (reader) => f.receiver.readStore({ reader })
        : () => f.store,
    },
  } as AppDeps);
  return async (token: string, path: string, method = "GET") => {
    const res = await app.request(path, {
      method,
      headers: { Authorization: `Bearer ${token}` },
    });
    return {
      status: res.status,
      body:
        method === "HEAD"
          ? ""
          : res.headers.get("content-type")?.includes("json")
            ? await res.json()
            : await res.text(),
    };
  };
}

it("createApp serves bounded owner copy diagnostics and summary, never values or conflict bytes to grants, before and after finality/restart", async () => {
  const f = copyReadFixture();
  const bytes = Buffer.from("copy-private-bytes");
  const blobId = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
  const blob = {
    blobId,
    sha256: blobId,
    mimeType: "application/octet-stream",
    sizeBytes: bytes.length,
  };
  const record = {
    ...upsert("A", 11),
    recordKey: "a",
    blobs: [blob],
    data: {
      id: "a",
      text: "copy-A",
      blob_ref: {
        blob_id: blobId,
        mime_type: blob.mimeType,
        size_bytes: bytes.length,
      },
    },
  };
  const claim = {
    ...identity,
    kind: "blob-claim" as const,
    blob,
    revision: { counter: 10, writerId: "device-a", operationId: "claim" },
  };
  const a = f.copy("A", 1, [registration, claim, record]),
    b = f.copy("B", 2);
  f.stage(a, [{ blobId, bytes }]);
  f.stage(b);
  const path = `/v1/replica/copy-conflicts/${encodeURIComponent(a.id)}`;
  let get = host(f);
  const check = async () => {
    const res = await get("owner", path);
    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      object: "list",
      data: [a.copyKey, b.copyKey]
        .sort()
        .map((copyKey) => ({
          copyKey,
          reason: "copy_conflict",
          visibility: "conflicted",
          status: "copy conflict",
          values: [copyKey === a.copyKey ? record : b.record],
        })),
    });
    expect((await get("app", path)).status).toBe(403);
    expect((await get("foreign", path)).status).toBe(403);
    expect((await get("narrow", path)).body).toEqual({
      object: "list",
      data: [],
    });
    expect((await get("owner", "/v1/streams")).body.data).toEqual([
      {
        object: "stream",
        name: "messages",
        record_count: 0,
        last_updated: null,
        copy_conflicts: 2,
      },
    ]);
    expect((await get("app", "/v1/streams")).body.data).toEqual([]);
    for (const token of ["app", "owner"]) {
      expect((await get(token, `/v1/blobs/${blobId}`)).status).toBe(404);
      expect((await get(token, `/v1/blobs/${blobId}`, "HEAD")).status).toBe(
        404,
      );
    }
  };
  await check();
  f.reopen();
  get = host(f);
  await check();
  f.prove(b);
  f.receiver.copies.promote({
    credential: "test",
    id: b.id,
    copyKey: b.copyKey,
  });
  for (const token of ["owner", "app"]) {
    expect(
      (await get(token, "/v1/streams/messages/records/a")).body.data.text,
    ).toBe("B");
    expect((await get(token, `/v1/blobs/${blobId}`)).status).toBe(404);
  }
  expect((await get("owner", path)).body.data).toHaveLength(1);
  expect((await get("app", "/v1/streams")).body.data[0]).not.toHaveProperty(
    "copy_conflicts",
  );
  f.receiver.copies.terminate({
    credential: "test",
    id: b.id,
    reason: "finalized_conflict",
  });
  const terminal = async () => {
    expect((await get("owner", path)).body.data).toEqual(
      [a.copyKey, b.copyKey]
        .sort()
        .map((copyKey) => ({
          copyKey,
          reason: "finalized_conflict",
          visibility: "conflicted",
          status: "integrity conflict",
        })),
    );
    for (const token of ["owner", "app"])
      expect(
        (await get(token, "/v1/streams/messages/records")).body.data,
      ).toEqual([]);
  };
  await terminal();
  f.reopen();
  get = host(f);
  await terminal();
  expect((await host(f, false)("owner", path)).status).toBe(404);
});

it("createApp refuses an over-limit diagnostic as 413 without partial values", async () => {
  const f = copyReadFixture();
  const a = f.copy("A".repeat(300_000), 1);
  f.stage(a);
  f.stage(f.copy("B", 2));
  const get = host(f);
  const path = `/v1/replica/copy-conflicts/${encodeURIComponent(a.id)}`;
  const res = await get("owner", path);
  expect(res.status).toBe(413);
  expect(res.body.error).toMatchObject({
    code: "invalid_request",
    message: "Copy conflict diagnostics exceed the read limit",
  });
  expect(res.body).not.toHaveProperty("data");
  expect(
    (await get("app", `${path}?reader=owner&include_pending=true`)).status,
  ).toBe(403);
});
