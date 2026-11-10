import { createHash } from "node:crypto";
import { access, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { privateKeyToAccount } from "viem/accounts";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { createMemoryModeRecordStore } from "@opendatalabs/personal-server-ts-core/sync/account-mode";
import { createStreamSyncKeyPorts } from "../../core/src/stream-sync/crypto.js";
import { remoteFixture } from "./localdb/apply-fixture.js";
import { createServer, type ServerContext } from "./bootstrap.js";

const contexts: ServerContext[] = [];
const directories: string[] = [];
afterEach(async () => {
  for (const context of contexts.splice(0)) await context.cleanup();
  for (const directory of directories.splice(0))
    await rm(directory, { recursive: true, force: true });
  vi.unstubAllEnvs();
});
const config = ServerConfigSchema.parse({
  tunnel: { enabled: false },
  sync: { enabled: false },
  logging: { level: "fatal", pretty: false },
});
async function boot(
  rootPath: string,
  store = createMemoryModeRecordStore(),
  remote?: Awaited<ReturnType<typeof remoteFixture>>,
  serverConfig = config,
) {
  vi.stubEnv("PS_ACCESS_TOKEN", "node-database-fixture");
  vi.stubEnv("VANA_OWNER_PRIVATE_KEY", "");
  const ownerSignature = await signature();
  const context = await createServer(serverConfig, {
    rootPath,
    ownerSignature,
    accountModeStore: store,
    ...(remote
      ? { streamSyncRegistry: remote.registry, streamSyncBlobs: remote.storage }
      : {}),
  });
  contexts.push(context);
  return context;
}
const signature = () =>
  privateKeyToAccount(`0x${"11".repeat(32)}`).signMessage({
    message: "Disposable Node database fixture",
  });
const headers = { Authorization: "Bearer node-database-fixture" };
async function directory() {
  const root = await mkdtemp(join(tmpdir(), "node-localdb-"));
  directories.push(root);
  return root;
}

describe("Node database composition", () => {
  it("boots with sync disabled and opens no database before Account says On", async () => {
    const root = await directory();
    const context = await boot(root);
    await expect(access(join(root, "localdb"))).rejects.toThrow();
    const response = await context.app.request("/v1/data/fixture.items", {
      headers,
    });
    expect(response.status).toBe(503);
    expect((await response.json()).error.errorCode).toBe(
      "ACCOUNT_MODE_UNKNOWN",
    );
    for (const path of ["/v1/sync/status", "/v1/stream-sync/read-status"]) {
      expect((await context.app.request(path, { headers })).status).toBe(503);
    }
    await expect(context.getLocalSync!()).rejects.toMatchObject({
      errorCode: "ACCOUNT_MODE_UNKNOWN",
    });
    await context.accountModeAuthority.submitEvidence({
      owner: context.serverOwner!,
      state: "off",
    });
    await expect(context.getLocalSync!()).rejects.toThrow("not enabled");
    await expect(access(join(root, "localdb"))).rejects.toThrow();
  });

  it("serves a retained SQLite image through the database resolver across restart", async () => {
    const root = await directory();
    const store = createMemoryModeRecordStore();
    const remote = await remoteFixture(
      createStreamSyncKeyPorts(await signature()),
    );
    const head = await remote.head(
      "items",
      [{ id: "item", value: "database" }],
      { f: 42 },
    );
    const get = vi.spyOn(remote.storage, "get");
    let context = await boot(root, store, remote);
    await context.accountModeAuthority.submitEvidence({
      owner: context.serverOwner!,
      state: "on",
    });
    // The download hook discovers connections and installs the remote image.
    // Reads then use the same real P06 boundary, including after process restart.
    await (await context.getLocalSync!()).apply();
    for (let attempt = 0; attempt < 2; attempt++) {
      const response = await context.app.request(
        "/v1/data/pdpp.fixture-source.items",
        { headers },
      );
      expect(response.status).toBe(200);
      expect(response.headers.get("X-Vana-Data-Source")).toBe("stream-sync");
      expect(await response.json()).toMatchObject({
        data: { records: [{ id: "item", value: "database" }] },
      });
      const first = await context.getLocalSync!();
      expect(await context.getLocalSync!()).toBe(first);
      await context.cleanup();
      contexts.splice(contexts.indexOf(context), 1);
      if (attempt === 0) context = await boot(root, store, remote);
    }
    expect(
      get.mock.calls.filter(([key]) => key.includes("/g1-p-")),
    ).toHaveLength(head.parts.length);
  });
  it("accepts real HTTP intake from a pinned artifact and stores retry progress in SQLite", async () => {
    const root = await directory();
    const declaration = JSON.stringify({
      source_id: "https://example.test/fixture-source",
      source_kind: "connector",
      version: "1",
      streams: [
        {
          name: "items",
          fields: ["id"],
          required_fields: ["id"],
          primary_key: ["id"],
        },
      ],
    });
    const manifest = JSON.stringify({
      connector_key: "fixture-source",
      version: "1",
      streams: [
        { name: "items", semantics: "mutable_state", primary_key: ["id"] },
      ],
    });
    const declarationPath = join(root, "declaration.json");
    const manifestPath = join(root, "manifest.json");
    await writeFile(declarationPath, declaration);
    await writeFile(manifestPath, manifest);
    const digest = createHash("sha256").update(manifest).digest("hex");
    const remote = await remoteFixture(
      createStreamSyncKeyPorts(await signature()),
    );
    const context = await boot(
      root,
      createMemoryModeRecordStore(),
      remote,
      ServerConfigSchema.parse({
        ...config,
        streamSync: { write: true },
        pdpp: {
          enabled: true,
          declarationPaths: [declarationPath],
          methods: [
            {
              method_id: "fixture-source",
              declaration_path: declarationPath,
              manifest_path: manifestPath,
              manifest_sha256: digest,
            },
          ],
        },
      }),
    );
    await context.accountModeAuthority.submitEvidence({
      owner: context.serverOwner!,
      state: "on",
    });
    const send = (path: string, method: string, value: unknown) =>
      context.app.request(path, {
        method,
        headers: { ...headers, "Content-Type": "application/json" },
        body: JSON.stringify(value),
      });
    const begin = await send("/v1/stream-sync/runs/intake", "PUT", {
      connector: "fixture-source",
      artifactDigest: digest,
      owner: { address: context.serverOwner!, leaseId: null },
      observedAt: 42,
    });
    expect(begin.status).toBe(200);
    expect(await begin.json()).toMatchObject({
      status: "collecting",
      start: { collection_mode: "full_refresh" },
    });
    const batch = await send("/v1/stream-sync/runs/intake/batches", "POST", {
      batch: 0,
      records: [{ stream: "items", data: { id: "from-intake" } }],
    });
    expect(batch.status).toBe(200);
    expect(await batch.json()).toMatchObject({ accepted: 1 });
    const end = await send("/v1/stream-sync/runs/intake/end", "POST", {
      outcome: "retry_pending",
      coveredStreams: [],
      lastBatch: 0,
      checkpointCandidate: { items: "C1" },
    });
    expect(end.status).toBe(200);
    expect(await end.json()).toMatchObject({ result: "queued" });
    const rows = await (
      await context.getLocalSync!()
    ).query.listRecords({
      connectionId: "pdpp.fixture-source~",
      stream: "items",
      limit: 10,
    });
    expect(rows.records.map((r) => r.recordKey)).toEqual(["from-intake"]);
    const resumed = await send("/v1/stream-sync/runs/resumed", "PUT", {
      connector: "fixture-source",
      artifactDigest: digest,
      owner: { address: context.serverOwner!, leaseId: null },
    });
    expect(resumed.status).toBe(200);
    expect(await resumed.json()).toMatchObject({
      start: { collection_mode: "incremental", state: { items: "C1" } },
    });
    // Finish the resumed increment, then prove a full snapshot through the
    // same Node HTTP port and real P03/P05/P06/P09 database composition.
    await send("/v1/stream-sync/runs/resumed/batches", "POST", {
      batch: 0,
      records: [{ stream: "items", data: { id: "from-resume" } }],
    });
    expect(
      (
        await send("/v1/stream-sync/runs/resumed/end", "POST", {
          outcome: "succeeded",
          coveredStreams: ["items"],
          provenFullStreams: ["items"],
          lastBatch: 0,
        })
      ).status,
    ).toBe(200);
    expect(
      (
        await send("/v1/stream-sync/runs/zz-full", "PUT", {
          connector: "fixture-source",
          artifactDigest: digest,
          owner: { address: context.serverOwner!, leaseId: null },
          wantFull: true,
          observedAt: Date.now() + 100,
        })
      ).status,
    ).toBe(200);
    expect(
      (
        await send("/v1/stream-sync/runs/zz-full/batches", "POST", {
          batch: 0,
          records: [{ stream: "items", data: { id: "live-full" } }],
        })
      ).status,
    ).toBe(200);
    expect(
      (
        await send("/v1/stream-sync/runs/zz-full/end", "POST", {
          outcome: "succeeded",
          coveredStreams: ["items"],
          provenFullStreams: ["items"],
          lastBatch: 0,
        })
      ).status,
    ).toBe(200);
    remote.registry.post = async (post) => {
      const prior = remote.reads.get(post.scope);
      const version = prior?.found ? prior.version + 1 : 1;
      if (String(version) !== post.expectedVersion)
        return { kind: "conflict", latestVersion: String(version - 1) };
      remote.reads.set(post.scope, {
        found: true,
        version,
        dataHash: post.dataHash,
        metadataHash: post.metadataHash,
        deleted: false,
      });
      return { kind: "committed" };
    };
    const report = await (await context.getLocalSync!()).cycle();
    expect(report.connections.map((c) => c.error)).toEqual([null]);
    const read = await context.app.request(
      "/v1/data/pdpp.fixture-source.items",
      { headers },
    );
    expect(read.status).toBe(200);
    expect(await read.json()).toMatchObject({
      data: { records: [{ id: "live-full" }] },
    });
    const deletion = await context.app.request(
      "/v1/owner/connectors/fixture-source",
      { method: "DELETE", headers },
    );
    expect(deletion.status).toBe(202);
    expect((await deletion.json()).deleteId).toBeTruthy();
    expect(
      await (await context.getLocalSync!()).deleter.resumeDeletes(),
    ).toEqual([]);
    expect(
      (
        await context.app.request("/v1/data/pdpp.fixture-source.items", {
          headers,
        })
      ).status,
    ).toBe(410);
  });
});
