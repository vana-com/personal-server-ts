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
    wide: {
      active: true,
      tokenKind: "owner",
      subjectId: identity.owner,
      instanceIds: [identity.connectionId, "another-connection"],
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
      configuredMethods: new Map(),
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
      has_more: false,
      data: [a.copyKey, b.copyKey].sort().map((copyKey) => ({
        id: a.id,
        copyKey,
        connections: [identity.connectionId],
        streams: ["messages"],
        reason: "copy_conflict",
        visibility: "conflicted",
        status: "copy conflict",
        values:
          copyKey === a.copyKey ? a.envelope.operations : b.envelope.operations,
      })),
    });
    expect((await get("app", path)).status).toBe(403);
    expect((await get("foreign", path)).status).toBe(403);
    expect((await get("narrow", path)).body).toEqual({
      object: "list",
      has_more: false,
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
      [a.copyKey, b.copyKey].sort().map((copyKey) => ({
        id: a.id,
        copyKey,
        connections: [identity.connectionId],
        streams: ["messages"],
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

it("returns an oversized copy as an explicit marker without hiding its sibling", async () => {
  const f = copyReadFixture();
  const a = f.copy("large", 1, [
      registration,
      {
        ...upsert("large", 10),
        data: { id: "a", text: "x".repeat(5 * 1024 * 1024) },
      },
    ]),
    b = f.copy("small", 2);
  f.stage(a);
  f.stage(b);
  const get = host(f),
    path = `/v1/replica/copy-conflicts/${encodeURIComponent(a.id)}`;
  const res = await get("owner", path);
  expect(res.status).toBe(200);
  expect(
    res.body.data.find(
      (copy: { copyKey: string }) => copy.copyKey === a.copyKey,
    ),
  ).toMatchObject({ valuesOmitted: true, valuesOmittedReason: "byte_limit" });
  expect(
    res.body.data.find(
      (copy: { copyKey: string }) => copy.copyKey === b.copyKey,
    ).values,
  ).toEqual(b.envelope.operations);
  expect(
    (await get("app", `${path}?reader=owner&include_pending=true`)).status,
  ).toBe(403);
});

it("lets a scoped owner discover conflicting batch ids through bounded keyset pages", async () => {
  const f = copyReadFixture();
  const a = f.copy("A", 1),
    b = f.copy("B", 2);
  f.stage(a);
  f.stage(b);
  const get = host(f);
  const path = `/v1/replica/copy-conflicts?connection=${encodeURIComponent(identity.connectionId)}&stream=messages&limit=1`;
  const first = await get("owner", path);
  expect(first.status).toBe(200);
  expect(first.body.data).toHaveLength(1);
  expect(first.body.has_more).toBe(true);
  expect(first.body.data[0]).toMatchObject({
    id: a.id,
    reason: "copy_conflict",
    status: "copy conflict",
    connections: [identity.connectionId],
    streams: ["messages"],
  });
  expect(first.body.data[0]).not.toHaveProperty("values");
  const second = await get("owner", `${path}&cursor=${first.body.next_cursor}`);
  expect(second.status).toBe(200);
  expect(second.body.data).toHaveLength(1);
  expect(second.body.has_more).toBe(false);
  expect(second.body.data[0].copyKey).not.toBe(first.body.data[0].copyKey);
  expect((await get("app", path)).status).toBe(403);
  expect((await get("foreign", path)).status).toBe(403);
  expect((await get("narrow", path)).body.data).toEqual([]);
});

it("uses the same token scope for counts, discovery and complete values", async () => {
  const f = copyReadFixture(),
    other = "another-connection";
  f.store.registerConnection({
    instance: other,
    sourceId: identity.sourceId,
    method: identity.methodId,
    label: other,
  });
  const a = f.copy("local", 1),
    b = f.copy("cross", 2, [
      ...f.copy("cross", 2).envelope.operations,
      { ...registration, connectionId: other },
    ]);
  f.stage(a);
  f.stage(b);
  const get = host(f);
  const path = `/v1/replica/copy-conflicts/${encodeURIComponent(a.id)}`;
  for (const [token, n] of [
    ["owner", 1],
    ["wide", 2],
  ] as const) {
    expect((await get(token, "/v1/streams")).body.data[0].copy_conflicts).toBe(
      n,
    );
    expect(
      (await get(token, "/v1/replica/copy-conflicts?stream=messages")).body
        .data,
    ).toHaveLength(n);
    expect((await get(token, path)).body.data).toHaveLength(n);
  }
  expect((await get("narrow", "/v1/streams")).body.data).toEqual([]);
  expect((await get("narrow", "/v1/replica/copy-conflicts")).body.data).toEqual(
    [],
  );
});

it("accepts a copy key and batch-id digest reference alongside the full id with the same owner scope", async () => {
  const f = copyReadFixture(),
    batch = "batch-" + "x".repeat(2000);
  const a = f.copy("A", 1, undefined, batch),
    b = f.copy("B", 2, undefined, batch);
  f.stage(a);
  f.stage(b);
  const get = host(f),
    idDigest = createHash("sha256").update(a.id).digest("hex");
  const catalog = await get("owner", "/v1/replica/copy-conflicts");
  expect(
    catalog.body.data.every(
      (row: { id: string; idTruncated?: true }) =>
        row.id === idDigest && row.idTruncated,
    ),
  ).toBe(true);
  const path = `/v1/replica/copy-conflicts/${idDigest}?copyKey=${a.copyKey}`;
  const result = await get("owner", path);
  expect(result.status).toBe(200);
  expect(result.body.data).toEqual([
    expect.objectContaining({
      id: idDigest,
      idTruncated: true,
      copyKey: a.copyKey,
      values: a.envelope.operations,
    }),
  ]);
  expect(
    (
      await get(
        "owner",
        `/v1/replica/copy-conflicts/${encodeURIComponent(a.id)}`,
      )
    ).body.data,
  ).toHaveLength(2);
  expect((await get("narrow", path)).body.data).toEqual([]);
  expect((await get("app", path)).status).toBe(403);
  expect(
    (
      await get(
        "owner",
        `/v1/replica/copy-conflicts/${"0".repeat(64)}?copyKey=${a.copyKey}`,
      )
    ).body.data,
  ).toEqual([]);
  expect(
    (
      await get(
        "owner",
        `/v1/replica/copy-conflicts/${idDigest}?copyKey=invalid`,
      )
    ).status,
  ).toBe(400);
  expect(
    (
      await get(
        "owner",
        `/v1/replica/copy-conflicts/invalid?copyKey=${a.copyKey}`,
      )
    ).status,
  ).toBe(400);
  f.prove(b);
  f.receiver.copies.promote({
    credential: "test",
    id: b.id,
    copyKey: b.copyKey,
  });
  expect((await get("owner", path)).body.data).toHaveLength(1);
  expect(
    (
      await get(
        "owner",
        `/v1/replica/copy-conflicts/${idDigest}?copyKey=${b.copyKey}`,
      )
    ).body.data,
  ).toEqual([]);
  f.receiver.copies.terminate({
    credential: "test",
    id: b.id,
    reason: "finalized_conflict",
  });
  f.reopen();
  const terminal = await host(f)("owner", path);
  expect(terminal.body.data).toEqual([
    expect.objectContaining({
      id: idDigest,
      idTruncated: true,
      copyKey: a.copyKey,
      status: "integrity conflict",
    }),
  ]);
  expect(terminal.body.data[0]).not.toHaveProperty("values");
});

it("uses the server-owner gate for both stream counts and discovery", async () => {
  const f = copyReadFixture();
  f.stage(f.copy("A", 1));
  f.stage(f.copy("B", 2));
  const get = host(f);
  expect((await get("owner", "/v1/streams")).body.data[0].copy_conflicts).toBe(
    2,
  );
  const foreign = await get("foreign", "/v1/streams");
  expect(foreign.status).toBe(200);
  expect(foreign.body.data).toEqual([]);
  expect((await get("foreign", "/v1/replica/copy-conflicts")).status).toBe(403);
  expect(
    (
      await get(
        "foreign",
        `/v1/replica/copy-conflicts/${encodeURIComponent(f.copy("A", 1).id)}`,
      )
    ).status,
  ).toBe(403);
});

it("reports malformed references as invalid requests", async () => {
  const f = copyReadFixture();
  const a = f.copy("A", 1);
  f.stage(a);
  f.stage(f.copy("B", 2));
  const get = host(f);
  const digest = createHash("sha256").update(a.id).digest("hex");
  for (const reference of [
    `${digest}?copyKey=invalid`,
    `invalid?copyKey=${a.copyKey}`,
    `${encodeURIComponent(a.id)}?copyKey=${a.copyKey}`,
  ]) {
    const response = await get(
      "owner",
      `/v1/replica/copy-conflicts/${reference}`,
    );
    expect(response.status).toBe(400);
    expect(response.body.error.code).toBe("invalid_request");
  }
});

it("reports expired copy cursors without changes_since text", async () => {
  const f = copyReadFixture();
  f.stage(f.copy("A", 1));
  f.stage(f.copy("B", 2));
  const get = host(f);
  const first = await get("owner", "/v1/replica/copy-conflicts?limit=1");
  const cursor = JSON.parse(
    Buffer.from(first.body.next_cursor, "base64url").toString("utf8"),
  );
  cursor.schema = 0;
  const expired = await get(
    "owner",
    `/v1/replica/copy-conflicts?limit=1&cursor=${Buffer.from(JSON.stringify(cursor)).toString("base64url")}`,
  );
  expect(expired.status).toBe(410);
  expect(expired.body.error.message).toBe("Copy conflict cursor has expired");
});
