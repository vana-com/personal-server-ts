import { createHash } from "node:crypto";
import {
  mkdtemp,
  readFile,
  rm,
  writeFile,
  unlink,
  readdir,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import type {
  Builder,
  GatewayClient,
  GatewayGrantResponse,
} from "@opendatalabs/vana-sdk/node";
import { recoverServerOwner } from "@opendatalabs/vana-sdk/node";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import {
  buildWeb3SignedHeader,
  createTestWallet,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import { WRITE_SIGNATURE_HEADER } from "@opendatalabs/personal-server-ts-core/write";
import { createServer, type ServerContext } from "./bootstrap.js";
import { createNodeDataStorage } from "./storage/node-data-storage.js";

const KNOWN_SIG =
  "0xedbb7743cce459345238442dcfb291f234a321d253485eaa58251aa0f28ea8f1410ab988bae2657b689cd24417b41e315efc22ba333024f4a6269c424ded8d361b";
const SCOPE = "example.profile";
let root: string;
let server: ServerContext | undefined;

function provenance(data: Record<string, unknown>) {
  return {
    projector_version: "1",
    declaration_digest: "sha256:declaration",
    inputs: [{ stream: "profile", changes_since_token: "opaque-token" }],
    payload_sha256: createHash("sha256")
      .update(JSON.stringify(data))
      .digest("hex"),
  };
}

async function post(
  data: Record<string, unknown>,
  headers: Record<string, string> = {},
) {
  const response = await server!.app.request(`/v1/data/${SCOPE}`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${server!.devToken}`,
      "content-type": "application/json",
      ...headers,
    },
    body: JSON.stringify(data),
  });
  return { status: response.status, body: await response.json() };
}

async function deleteScope() {
  const response = await server!.app.request(`/v1/data/${SCOPE}`, {
    method: "DELETE",
    headers: { authorization: `Bearer ${server!.devToken}` },
  });
  return { status: response.status, body: await response.json() };
}

function rows() {
  const db = new Database(join(root, "index.db"), { readonly: true });
  try {
    return db
      .prepare(
        "SELECT path, version, cas_revision, producer, producer_provenance FROM data_files WHERE scope = ? ORDER BY cas_revision",
      )
      .all(SCOPE) as Array<{
      path: string;
      version: number;
      cas_revision: number;
      producer: string | null;
      producer_provenance: string | null;
    }>;
  } finally {
    db.close();
  }
}

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "pdpp-legacy-cas-"));
  vi.stubEnv("VANA_MASTER_KEY_SIGNATURE", KNOWN_SIG);
  server = await createServer(
    ServerConfigSchema.parse({ tunnel: { enabled: false } }),
    { serverDir: root, dataDir: join(root, "data") },
  );
});

afterEach(async () => {
  await server?.cleanup();
  server = undefined;
  await rm(root, { recursive: true, force: true });
  vi.unstubAllEnvs();
});

describe("P9: conditional attributed legacy writes on a real server", () => {
  it("creates only when absent and reports the winner on a failed If-None-Match", async () => {
    const first = await post({ id: "first" }, { "if-none-match": "*" });
    expect(first.status).toBe(201);
    const losing = await post({ id: "loser" }, { "if-none-match": "*" });
    expect(losing.status).toBe(412);
    expect(losing.body).toMatchObject({
      error: "PRECONDITION_FAILED",
      current_version: 1,
      current_producer: null,
    });
    expect(rows()).toHaveLength(1);
    const scopeDir = join(root, "data", "example");
    expect(
      (await readdir(scopeDir)).filter((name) => name.includes(".pending.")),
    ).toEqual([]);
  });

  it("reports an absent current version when If-Match has no target", async () => {
    const result = await post({ id: "missing" }, { "if-match": '"1"' });
    expect(result.status).toBe(412);
    expect(result.body).toMatchObject({
      error: "PRECONDITION_FAILED",
      current_version: null,
      current_producer: null,
    });
    expect(rows()).toHaveLength(0);
  });

  it("stops the R2 overwrite race when a manual write lands after version read", async () => {
    const initial = { id: "projected" };
    const source = provenance(initial);
    const projected = await post(initial, {
      "if-none-match": "*",
      "vana-producer": "pdpp-projector",
      "vana-producer-provenance": Buffer.from(JSON.stringify(source)).toString(
        "base64url",
      ),
    });
    expect(projected.status).toBe(201);
    const manual = await post({ id: "manual" });
    expect(manual.status).toBe(201);
    const lateProjector = await post({ id: "late" }, { "if-match": '"1"' });
    expect(lateProjector.status).toBe(412);
    expect(lateProjector.body).toMatchObject({
      current_version: 2,
      current_producer: null,
    });
    expect(rows().map((row) => row.cas_revision)).toEqual([1, 2]);
    const latest = rows()[1]!;
    const file = JSON.parse(
      await readFile(join(root, "data", latest.path), "utf8"),
    );
    expect(file.data).toEqual({ id: "manual" });
  });

  it("does not let a stale If-Match overwrite a manual recreate after delete", async () => {
    const projected = await post(
      { id: "projected" },
      {
        "if-none-match": "*",
        "vana-producer": "pdpp-projector",
        "vana-producer-provenance": Buffer.from(
          JSON.stringify(provenance({ id: "projected" })),
        ).toString("base64url"),
      },
    );
    expect(projected.status).toBe(201);

    const deleted = await deleteScope();
    expect(deleted.status).toBe(200);
    expect(rows()).toHaveLength(0);

    const manual = await post({ id: "manual" });
    expect(manual.status).toBe(201);
    expect(rows().map((row) => row.cas_revision)).toEqual([2]);

    const staleProjector = await post({ id: "stale" }, { "if-match": '"1"' });
    expect(staleProjector.status).toBe(412);
    expect(staleProjector.body).toMatchObject({
      current_version: 2,
      current_producer: null,
    });

    const latest = rows()[0]!;
    const file = JSON.parse(
      await readFile(join(root, "data", latest.path), "utf8"),
    );
    expect(file.data).toEqual({ id: "manual" });
  });

  it("replaces exactly the matched version and preserves previous versions", async () => {
    expect((await post({ id: "first" })).status).toBe(201);
    const next = { id: "next" };
    const result = await post(next, {
      "if-match": '"1"',
      "vana-producer": "pdpp-import-projection",
      "vana-producer-provenance": Buffer.from(
        JSON.stringify(provenance(next)),
      ).toString("base64url"),
    });
    expect(result.status).toBe(201);
    expect(rows().map((row) => [row.cas_revision, row.producer])).toEqual([
      [1, null],
      [2, "pdpp-import-projection"],
    ]);
  });

  it("stores producer metadata outside grantee data and exposes it in versions", async () => {
    const data = { id: "owned" };
    const source = provenance(data);
    const result = await post(data, {
      "vana-producer": "pdpp-projector",
      "vana-producer-provenance": Buffer.from(JSON.stringify(source)).toString(
        "base64url",
      ),
    });
    expect(result.status).toBe(201);
    const row = rows()[0]!;
    expect(row.producer).toBe("pdpp-projector");
    expect(JSON.parse(row.producer_provenance!)).toEqual(source);
    const envelope = JSON.parse(
      await readFile(join(root, "data", row.path), "utf8"),
    );
    expect(envelope.data).toEqual(data);
    expect(envelope.producer).toBe("pdpp-projector");
    expect(envelope.producer_provenance).toEqual(source);
    const syncEnvelope = await createNodeDataStorage({
      indexManager: server!.indexManager,
      hierarchyOptions: { dataDir: join(root, "data") },
    }).readEnvelope(SCOPE, envelope.collectedAt);
    expect(syncEnvelope).toMatchObject({
      producer: "pdpp-projector",
      producer_provenance: source,
    });
    const versions = await server!.app.request(`/v1/data/${SCOPE}/versions`, {
      headers: { authorization: `Bearer ${server!.devToken}` },
    });
    expect(versions.status).toBe(200);
    expect((await versions.json()).versions[0]).toMatchObject({
      version: 1,
      producer: "pdpp-projector",
      producer_provenance: source,
    });
  });

  it.each([
    [{ "if-none-match": "*", "if-match": '"1"' }, "INVALID_PRECONDITION"],
    [{ "if-match": "1" }, "INVALID_PRECONDITION"],
    [{ "if-none-match": '"*"' }, "INVALID_PRECONDITION"],
    [{ "vana-producer": "unknown" }, "INVALID_PRODUCER"],
    [{ "vana-producer-provenance": "e30" }, "INVALID_PRODUCER"],
    [
      {
        "vana-producer": "pdpp-projector",
        "vana-producer-provenance": "not+base64",
      },
      "INVALID_PROVENANCE",
    ],
  ])(
    "rejects invalid header %j with %s without mutating storage",
    async (headers, code) => {
      const result = await post({ id: "bad" }, headers);
      expect(result.status).toBe(400);
      expect(result.body.error.errorCode).toBe(code);
      expect(rows()).toHaveLength(0);
    },
  );

  it("rejects a provenance hash mismatch before writing", async () => {
    const source = provenance({ id: "different" });
    const result = await post(
      { id: "actual" },
      {
        "vana-producer": "pdpp-projector",
        "vana-producer-provenance": Buffer.from(
          JSON.stringify(source),
        ).toString("base64url"),
      },
    );
    expect(result.status).toBe(400);
    expect(result.body.error.errorCode).toBe("PAYLOAD_HASH_MISMATCH");
    expect(rows()).toHaveLength(0);
  });

  it("rejects a producer asserted by a real delegated write session", async () => {
    const builder = createTestWallet(0);
    const owner = await recoverServerOwner(KNOWN_SIG);
    const grantId = "grant-write-p9";
    const builderId = "builder-write-p9";
    const grant: GatewayGrantResponse = {
      id: grantId,
      grantorAddress: owner,
      granteeId: builderId,
      scopes: [`write:${SCOPE}`],
      status: "confirmed",
      addedAt: "2026-01-21T10:00:00.000Z",
      expiresAt: null,
      expired: false,
      revokedAt: null,
      revocationSignature: null,
      paymentStatus: "paid",
      paidAt: null,
      paidBy: null,
      grantVersion: "1",
      settleTxHash: null,
      settleSubmittedAt: null,
      revocationTxHash: null,
      fee: {
        asset: "0x0000000000000000000000000000000000000000",
        registrationFee: "0",
        dataAccessFee: "0",
        totalDue: "0",
      },
    };
    const gateway = {
      getBuilder: vi.fn().mockResolvedValue({
        id: builderId,
        ownerAddress: owner,
        granteeAddress: builder.address,
        publicKey: "0x04key",
        appUrl: "https://app.example.com",
        addedAt: "2026-01-21T10:00:00.000Z",
      } satisfies Builder),
      getGrant: vi.fn().mockResolvedValue(grant),
    } as unknown as GatewayClient;
    await server!.cleanup();
    server = await createServer(
      ServerConfigSchema.parse({ tunnel: { enabled: false } }),
      { serverDir: root, dataDir: join(root, "data"), gatewayClient: gateway },
    );
    const origin = server.config.server.origin;
    const session = await server.app.request("/v1/write/session", {
      method: "POST",
      headers: {
        authorization: await buildWeb3SignedHeader({
          wallet: builder,
          aud: origin,
          method: "POST",
          uri: "/v1/write/session",
          grantId,
        }),
      },
    });
    expect(session.status).toBe(200);
    const { access_token } = await session.json();
    const body = JSON.stringify({ id: "builder" });
    const response = await server.app.request(`/v1/data/${SCOPE}`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${access_token}`,
        "content-type": "application/json",
        "vana-producer": "pdpp-projector",
        [WRITE_SIGNATURE_HEADER]: await buildWeb3SignedHeader({
          wallet: builder,
          aud: origin,
          method: "POST",
          uri: `/v1/data/${SCOPE}`,
          body: new TextEncoder().encode(body),
          grantId,
        }),
      },
      body,
    });
    expect(response.status).toBe(403);
    expect((await response.json()).error.errorCode).toBe("NOT_OWNER");
    expect(rows()).toHaveLength(0);
  });

  it("checks payload_sha256 over canonical JSON independent of key order", async () => {
    const source = provenance({ a: 1, z: 2 });
    const result = await post(
      { z: 2, a: 1 },
      {
        "vana-producer": "pdpp-projector",
        "vana-producer-provenance": Buffer.from(
          JSON.stringify(source),
        ).toString("base64url"),
      },
    );
    expect(result.status).toBe(201);
    expect(rows()).toHaveLength(1);
  });

  it("recovers a committed stage and removes an unindexed stage on boot", async () => {
    expect((await post({ id: "committed" })).status).toBe(201);
    const row = rows()[0]!;
    const finalPath = join(root, "data", row.path);
    const stagePath = `${finalPath}.pending.recovery`;
    await writeFile(stagePath, await readFile(finalPath));
    await unlink(finalPath);
    const lostStage = join(
      root,
      "data",
      "example",
      "unindexed.json.pending.loser",
    );
    await writeFile(lostStage, "{}", "utf8");
    await server!.cleanup();
    server = await createServer(
      ServerConfigSchema.parse({ tunnel: { enabled: false } }),
      { serverDir: root, dataDir: join(root, "data") },
    );
    expect(JSON.parse(await readFile(finalPath, "utf8")).data).toEqual({
      id: "committed",
    });
    expect(
      (await readdir(join(root, "data", "example"))).filter((name) =>
        name.includes(".pending."),
      ),
    ).toEqual([]);
  });

  it("never publishes an uncommitted stage over an existing committed file", async () => {
    expect((await post({ id: "committed" })).status).toBe(201);
    const row = rows()[0]!;
    const finalPath = join(root, "data", row.path);
    const stagePath = `${finalPath}.pending.uncommitted`;
    const staged = JSON.parse(await readFile(finalPath, "utf8"));
    staged.data = { id: "uncommitted" };
    await writeFile(stagePath, JSON.stringify(staged));

    await server!.cleanup();
    server = await createServer(
      ServerConfigSchema.parse({ tunnel: { enabled: false } }),
      { serverDir: root, dataDir: join(root, "data") },
    );
    expect(JSON.parse(await readFile(finalPath, "utf8")).data).toEqual({
      id: "committed",
    });
    expect(
      (await readdir(join(root, "data", "example"))).filter((name) =>
        name.includes(".pending."),
      ),
    ).toEqual([]);
  });

  it("keeps the newest legacy read when an older sync row arrives late", async () => {
    expect((await post({ id: "new" })).status).toBe(201);
    const latest = rows()[0]!;
    const oldAt = "2020-01-01T00:00:00Z";
    const oldPath = "example/profile/2020-01-01T00-00-00Z.json";
    const oldEnvelope = JSON.parse(
      await readFile(join(root, "data", latest.path), "utf8"),
    );
    oldEnvelope.collectedAt = oldAt;
    oldEnvelope.data = { id: "old" };
    await writeFile(join(root, "data", oldPath), JSON.stringify(oldEnvelope));
    server!.indexManager.insert({
      fileId: null,
      path: oldPath,
      scope: SCOPE,
      collectedAt: oldAt,
      sizeBytes: JSON.stringify(oldEnvelope).length,
    });

    const response = await server!.app.request(`/v1/data/${SCOPE}`, {
      headers: { authorization: `Bearer ${server!.devToken}` },
    });
    expect(response.status).toBe(200);
    expect((await response.json()).data).toEqual({ id: "new" });
    expect(server!.indexManager.findLatestByScope(SCOPE)?.casRevision).toBe(1);
  });

  it("re-indexes producer and provenance from finalized envelopes after index loss", async () => {
    const data = { id: "recovered" };
    const source = provenance(data);
    expect(
      (
        await post(data, {
          "vana-producer": "pdpp-projector",
          "vana-producer-provenance": Buffer.from(
            JSON.stringify(source),
          ).toString("base64url"),
        })
      ).status,
    ).toBe(201);
    await server!.cleanup();
    await unlink(join(root, "index.db"));
    server = await createServer(
      ServerConfigSchema.parse({ tunnel: { enabled: false } }),
      { serverDir: root, dataDir: join(root, "data") },
    );
    expect(rows()).toMatchObject([
      {
        cas_revision: 2,
        producer: "pdpp-projector",
        producer_provenance: JSON.stringify(source),
      },
    ]);
  });

  it("fences a stale CAS token after an index rebuild", async () => {
    expect((await post({ id: "projected" })).status).toBe(201);
    expect((await deleteScope()).status).toBe(200);
    expect((await post({ id: "manual" })).status).toBe(201);
    await server!.cleanup();
    await unlink(join(root, "index.db"));
    server = await createServer(
      ServerConfigSchema.parse({ tunnel: { enabled: false } }),
      { serverDir: root, dataDir: join(root, "data") },
    );
    expect(rows().map((row) => row.cas_revision)).toEqual([3]);
    const stale = await post({ id: "stale" }, { "if-match": '"1"' });
    expect(stale.status).toBe(412);
    expect(stale.body.current_version).toBe(3);
    const response = await server!.app.request(`/v1/data/${SCOPE}`, {
      headers: { authorization: `Bearer ${server!.devToken}` },
    });
    expect((await response.json()).data).toEqual({ id: "manual" });
  });
});
