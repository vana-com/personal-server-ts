import { createHash } from "node:crypto";
import { access, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";
import { privateKeyToAccount } from "viem/accounts";
import { afterEach, expect, it, vi } from "vitest";
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
  const temporary = join(homedir(), ".tmp");
  await mkdir(temporary, { recursive: true });
  const root = await mkdtemp(join(temporary, "node-seed-"));
  directories.push(root);
  return root;
}

it("stages and imports an old file through the real switched-owner bootstrap", async () => {
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
  const status = await context.app.request(
    "/v1/stream-sync/seed/fixture-source",
    { headers },
  );
  expect(status.status).toBe(200);
  expect(await status.json()).toMatchObject({ targetKnown: true, streams: {} });
  const refused = await context.app.request(
    "/v1/stream-sync/seed/fixture-source/items",
    {
      method: "PUT",
      headers,
      body:
        JSON.stringify({
          primaryKey: ["unverified"],
          profile: { key: "fixture-source", version: "1" },
          records: 0,
        }) + "\n",
    },
  );
  expect(refused.status).toBe(400);
  expect((await refused.json()).error.errorCode).toBe("SEED_BAD_DESCRIPTOR");
  const uploaded = await context.app.request(
    "/v1/stream-sync/seed/fixture-source/items",
    {
      method: "PUT",
      headers: { ...headers, "Content-Type": "application/x-ndjson" },
      body: [
        JSON.stringify({
          primaryKey: ["id"],
          profile: { key: "fixture-source", version: "1" },
          records: 1,
        }),
        JSON.stringify({ id: "old-file-row" }),
        "",
      ].join("\n"),
    },
  );
  expect(uploaded.status).toBe(202);
  const completed = await context.app.request(
    "/v1/stream-sync/seed/fixture-source",
    { headers },
  );
  expect(await completed.json()).toMatchObject({
    streams: { items: { state: "merged" } },
  });
  const rows = await (
    await context.getLocalSync!()
  ).query.listRecords({
    connectionId: "pdpp.fixture-source~",
    stream: "items",
    limit: 10,
  });
  expect(rows.records.map((r) => r.recordKey)).toEqual(["old-file-row"]);
  const retried = await context.app.request(
    "/v1/stream-sync/seed/fixture-source/items",
    {
      method: "PUT",
      headers,
      body: "must not be read",
    },
  );
  expect(retried.status).toBe(200);
  expect(await retried.json()).toEqual({ state: "merged" });
  await context.cleanup();
  contexts.splice(contexts.indexOf(context), 1);
  const restarted = await boot(root, undefined, remote, context.config);
  await restarted.accountModeAuthority.submitEvidence({
    owner: restarted.serverOwner!,
    state: "on",
  });
  const afterRestart = await restarted.app.request(
    "/v1/stream-sync/seed/fixture-source",
    { headers },
  );
  expect(await afterRestart.json()).toMatchObject({
    streams: { items: { state: "merged" } },
  });
  const deletion = await restarted.app.request(
    "/v1/owner/connectors/fixture-source",
    { method: "DELETE", headers },
  );
  expect(deletion.status).toBe(202);
  const afterDelete = await restarted.app.request(
    "/v1/stream-sync/seed/fixture-source",
    { headers },
  );
  expect(afterDelete.status).toBe(410);
  const retryDeleted = await restarted.app.request(
    "/v1/stream-sync/seed/fixture-source/items",
    { method: "PUT", headers, body: "must not be read" },
  );
  expect(retryDeleted.status).toBe(410);
});

it("seed admission follows Account mode before creating a database", async () => {
  const root = await directory();
  const context = await boot(root);
  const get = () =>
    context.app.request("/v1/stream-sync/seed/fixture-source", { headers });
  expect((await get()).status).toBe(503);
  await context.accountModeAuthority.submitEvidence({
    owner: context.serverOwner!,
    state: "off",
  });
  expect((await get()).status).toBe(409);
  await expect(access(join(root, "localdb"))).rejects.toThrow();
});
