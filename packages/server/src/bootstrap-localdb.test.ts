import { createHash } from "node:crypto";
import {
  link,
  mkdir,
  readdir,
  symlink,
  access,
  mkdtemp,
  rm,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { privateKeyToAccount } from "viem/accounts";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { createMemoryModeRecordStore } from "@opendatalabs/personal-server-ts-core/sync/account-mode";
import { endRequest } from "@opendatalabs/personal-server-ts-core/test-utils";
import { createStreamSyncKeyPorts } from "../../core/src/stream-sync/crypto.js";
import { remoteFixture } from "./localdb/apply-fixture.test-utils.js";
import { createServer, type ServerContext } from "./bootstrap.js";
import * as legacyImport from "./localdb/legacy-store-import.js";

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
  it("creates an importer for Desktop and equivalent and external data paths", async () => {
    const root = await directory();
    const external = await directory();
    const runner = vi.spyOn(legacyImport, "createLegacyStoreRunner");
    vi.stubEnv("PS_ACCESS_TOKEN", "node-database-fixture");
    vi.stubEnv("VANA_OWNER_PRIVATE_KEY", "");
    for (const dataDir of [undefined, `${root}/data/../data`, external]) {
      const context = await createServer(config, {
        rootPath: root,
        dataDir,
        ownerSignature: await signature(),
        accountModeStore: createMemoryModeRecordStore(),
      });
      contexts.push(context);
      expect(runner).toHaveBeenLastCalledWith(
        expect.objectContaining({
          root,
          dataDir: dataDir === external ? external : join(root, "data"),
        }),
      );
      await context.cleanup();
      contexts.pop();
    }
    expect(runner).toHaveBeenCalledTimes(3);
  });
  describe.each([
    [
      "publishWhileCollecting",
      "streamSyncPublishWhileCollecting",
      "PS_PUBLISH_WHILE_COLLECTING",
    ],
    [
      "progressiveFirstLoad",
      "streamSyncProgressiveFirstLoad",
      "PS_STREAM_SYNC_PROGRESSIVE_FIRST_LOAD",
    ],
  ] as const)("design flag %s", (flag, option, env) => {
    async function depsOf(options: Record<string, boolean>) {
      const root = await directory();
      const runner = vi.spyOn(legacyImport, "createLegacyStoreRunner");
      vi.stubEnv("PS_ACCESS_TOKEN", "node-database-fixture");
      vi.stubEnv("VANA_OWNER_PRIVATE_KEY", "");
      const context = await createServer(config, {
        rootPath: root,
        ownerSignature: await signature(),
        accountModeStore: createMemoryModeRecordStore(),
        ...options,
      });
      contexts.push(context);
      await context.accountModeAuthority.submitEvidence({
        owner: context.serverOwner!,
        state: "on",
      });
      return runner.mock.calls.at(-1)![0].getDeps();
    }
    it("is off by default", async () => {
      const deps = await depsOf({});
      expect(deps[flag] ?? false).toBe(false);
    });
    it("reaches the sync deps from the bootstrap option", async () => {
      const deps = await depsOf({ [option]: true });
      expect(deps).toMatchObject({ [flag]: true });
    });
    it("reaches the sync deps from the environment", async () => {
      vi.stubEnv(env, "true");
      const deps = await depsOf({});
      expect(deps).toMatchObject({ [flag]: true });
    });
    it("lets an explicit false option override the environment", async () => {
      vi.stubEnv(env, "true");
      const deps = await depsOf({ [option]: false });
      expect(deps[flag] ?? false).toBe(false);
    });
  });
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
    await remote.head("items", [{ id: "item", value: "database" }]);
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
    // The log's one segment is fetched once; the restart reads the retained image.
    expect(
      get.mock.calls.filter(([key]) => /\/s-[0-9a-f]+$/.test(key)),
    ).toHaveLength(1);
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
        {
          name: "items",
          semantics: "mutable_state",
          primary_key: ["id"],
          coverage_strategy: "full_inventory",
        },
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
      join: true,
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
      records: [],
    });
    expect(batch.status).toBe(200);
    expect(await batch.json()).toMatchObject({ accepted: 0 });
    // A connector that asked to be retried before it sent records keeps its cursor.
    const end = await send(
      "/v1/stream-sync/runs/intake/end",
      "POST",
      endRequest({
        lastBatch: 0,
        streams: ["items"],
        retry: true,
        checkpoints: { items: "C1" },
      }),
    );
    expect(end.status).toBe(200);
    expect(await end.json()).toMatchObject({
      result: "checkpoint_only",
      outcome: "retry_pending",
      coveredStreams: [],
    });
    const resumed = await send("/v1/stream-sync/runs/resumed", "PUT", {
      connector: "fixture-source",
      artifactDigest: digest,
      join: true,
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
        await send(
          "/v1/stream-sync/runs/resumed/end",
          "POST",
          endRequest({
            lastBatch: 0,
            live: ["items"],
            provenFullStreams: ["items"],
          }),
        )
      ).status,
    ).toBe(200);
    expect(
      (
        await send("/v1/stream-sync/runs/zz-full", "PUT", {
          connector: "fixture-source",
          artifactDigest: digest,
          join: true,
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
        await send(
          "/v1/stream-sync/runs/zz-full/end",
          "POST",
          endRequest({
            lastBatch: 0,
            live: ["items"],
            provenFullStreams: ["items"],
          }),
        )
      ).status,
    ).toBe(200);
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

  it("starts local sync without an alias spool when the spool's startup sweep fails", async () => {
    const root = await directory();
    // A spool root that is a symbolic link makes the sweep throw.
    await mkdir(join(root, "elsewhere"));
    await symlink(join(root, "elsewhere"), join(root, "alias-spool"));
    const remote = await remoteFixture(
      createStreamSyncKeyPorts(await signature()),
    );
    await remote.head("items", [{ id: "item", value: "database" }]);
    const context = await boot(root, createMemoryModeRecordStore(), remote);
    await context.accountModeAuthority.submitEvidence({
      owner: context.serverOwner!,
      state: "on",
    });
    const sync = await context.getLocalSync!();
    await sync.apply();
    const response = await context.app.request(
      "/v1/data/pdpp.fixture-source.items",
      { headers },
    );
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      data: { records: [{ id: "item", value: "database" }] },
    });
  });

  it("tells the caller a database file with a second hard link cannot be opened", async () => {
    const root = await directory();
    const store = createMemoryModeRecordStore();
    let context = await boot(root, store);
    await context.accountModeAuthority.submitEvidence({
      owner: context.serverOwner!,
      state: "on",
    });
    await context.getLocalSync!(); // creates the database file
    await context.cleanup();
    contexts.splice(contexts.indexOf(context), 1);

    const files = (await readdir(join(root, "localdb"))).filter((name) =>
      name.endsWith(".sqlite"),
    );
    expect(files).toHaveLength(1);
    await link(
      join(root, "localdb", files[0]!),
      join(root, "localdb", "second-name.sqlite"),
    );

    context = await boot(root, store);
    await expect(context.getLocalSync!()).rejects.toMatchObject({
      code: "SQLITE_DATABASE_HARD_LINKED",
      message: expect.stringContaining("second hard link"),
    });
  });
});
