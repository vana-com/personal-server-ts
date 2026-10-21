/**
 * A response in flight stops when its grant is revoked mid-delivery.
 *
 * Bearers resolve through the real AS token and grant store (SQLite), and
 * revocation goes through the same store the owner's revoke route uses.
 */
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { AddressInfo } from "node:net";
import { Hono } from "hono";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  openPdppAuthStore,
  PdppTokenService,
  type Grant,
  type PdppAuthStore,
} from "@opendatalabs/personal-server-ts-core/pdpp";
import {
  createMemoryRecordStore,
  createStreamDeclarationRegistry,
  type PdppRecordStore,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { coLocatedAuthorizationService } from "../pdpp/records-bootstrap.js";
import type { PdppAuthRouteDeps } from "./pdpp-auth.js";
import { pdppBlobsRoutes } from "./pdpp-blobs.js";
import { pdppRecordsRoutes } from "./pdpp-records.js";
import { listenHttpServer, type NodeServer } from "../listen.js";

const declarations = createStreamDeclarationRegistry([
  {
    name: "media",
    semantics: "append_only",
    primaryKey: ["id"],
    cursorField: "emitted_at",
    requiredFields: ["id"],
  },
]);

const GRANT: Grant = {
  version: "0.1.0",
  grant_id: "grt_lease",
  issued_at: "2026-01-01T00:00:00Z",
  subject: { id: "sub_1" },
  client: { client_id: "client_1" },
  source: { kind: "provider_native", id: "src_1" },
  source_declaration: { version: "1" },
  purpose_code: "test",
  access_mode: "continuous",
  streams: [
    { name: "media", instance_ids: ["inst_1"], fields: ["id", "blob_ref"] },
  ],
};
const TOKEN = "pdpp_at_lease_test";

let dir: string;
let authStore: PdppAuthStore;
let records: PdppRecordStore;
let auth: ReturnType<typeof coLocatedAuthorizationService>;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "pdpp-read-lease-"));
  authStore = openPdppAuthStore(join(dir, "auth.db"));
  authStore.insertGrant({
    grant: GRANT,
    subjectId: "sub_1",
    reviewDigest: "t",
  });
  expect(
    authStore.issueAccessToken({
      token: TOKEN,
      grantId: GRANT.grant_id,
      subjectId: "sub_1",
      clientId: "client_1",
      tokenKind: "client",
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      consumeSingleUse: false,
    }),
  ).toBe(true);
  auth = coLocatedAuthorizationService({
    tokens: new PdppTokenService(authStore),
  } as PdppAuthRouteDeps);
  records = createMemoryRecordStore();
});

afterEach(async () => {
  records.close();
  authStore.close();
  await rm(dir, { recursive: true, force: true });
});

function seedBlob(sizeBytes: number) {
  const bytes = new Uint8Array(sizeBytes).fill(7);
  records.putBlobMeta({
    blobId: "blob_1",
    mimeType: "application/octet-stream",
    sizeBytes,
    sha256: "unused",
  });
  records.ingestBatch(
    [
      {
        instance: "inst_1",
        stream: "media",
        key: "media_1",
        data: { id: "media_1", blob_ref: { blob_id: "blob_1" } },
        emitted_at: "2026-04-01T00:00:00.000Z",
      },
    ],
    () => "append_only",
    () => ["id"],
  );
  return pdppBlobsRoutes({
    store: records,
    auth,
    declarations,
    instancesForSubject: () => ["inst_1"],
    readBlobBytes: async () => bytes,
  });
}

describe("a blob download whose grant is revoked mid-transfer", () => {
  it("aborts the body at the next chunk and never ends cleanly", async () => {
    const size = 1024 * 1024;
    const app = seedBlob(size);
    const response = await app.request("/blob_1", {
      headers: { Authorization: `Bearer ${TOKEN}` },
    });
    expect(response.status).toBe(200);
    expect(response.headers.get("Content-Length")).toBe(String(size));
    const reader = response.body!.getReader();

    const first = await reader.read();
    expect(first.done).toBe(false);
    let received = first.value!.byteLength;
    expect(received).toBeLessThan(size);

    // The owner revokes the grant while the client is still downloading.
    expect(authStore.revokeGrant(GRANT.grant_id)).toBe(true);

    let failure: unknown;
    try {
      for (;;) {
        const next = await reader.read();
        if (next.done) break;
        received += next.value.byteLength;
      }
    } catch (err) {
      failure = err;
    }
    expect(failure).toMatchObject({ code: "grant_revoked" });
    expect(received).toBeLessThan(size);
  });

  it("over a real socket, the client sees a failed, truncated transfer", async () => {
    // Larger than loopback socket buffers, so the revoke lands mid-transfer.
    const size = 64 * 1024 * 1024;
    const app = new Hono();
    app.route("/v1/blobs", seedBlob(size));
    let bound: AddressInfo | undefined;
    const server: NodeServer = await listenHttpServer({
      fetch: app.fetch,
      port: 0,
      hostname: "127.0.0.1",
      onListening: (info) => {
        bound = info;
      },
    });
    try {
      const response = await fetch(
        `http://127.0.0.1:${bound!.port}/v1/blobs/blob_1`,
        { headers: { Authorization: `Bearer ${TOKEN}` } },
      );
      expect(response.status).toBe(200);
      const reader = response.body!.getReader();
      let received = (await reader.read()).value?.byteLength ?? 0;
      expect(authStore.revokeGrant(GRANT.grant_id)).toBe(true);
      let failed = false;
      try {
        for (;;) {
          const next = await reader.read();
          if (next.done) break;
          received += next.value.byteLength;
        }
      } catch {
        failed = true;
      }
      expect(failed).toBe(true);
      expect(received).toBeLessThan(size);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});

describe("a multi-page list whose grant is revoked between pages", () => {
  it("refuses the next page; each page is its own fully buffered response", async () => {
    records.ingestBatch(
      ["m1", "m2", "m3"].map((id, index) => ({
        instance: "inst_1",
        stream: "media",
        key: id,
        data: { id },
        emitted_at: `2026-04-0${index + 1}T00:00:00.000Z`,
      })),
      () => "append_only",
      () => ["id"],
    );
    const app = pdppRecordsRoutes({
      store: records,
      auth,
      declarations,
      ownerSubjectId: "sub_1",
      instancesForSubject: () => ["inst_1"],
    });
    const headers = { Authorization: `Bearer ${TOKEN}` };
    const page1 = await app.request(
      "/streams/media/records?limit=1&order=asc",
      { headers },
    );
    expect(page1.status).toBe(200);
    const body = await page1.json();
    expect(body.data).toHaveLength(1);
    expect(body.next_cursor).toBeTruthy();

    expect(authStore.revokeGrant(GRANT.grant_id)).toBe(true);

    const page2 = await app.request(
      `/streams/media/records?limit=1&order=asc&cursor=${encodeURIComponent(body.next_cursor)}`,
      { headers },
    );
    expect(page2.status).toBe(403);
    expect((await page2.json()).error.code).toBe("grant_revoked");
  });
});
