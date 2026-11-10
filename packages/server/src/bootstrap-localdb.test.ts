import { access, mkdtemp, rm } from "node:fs/promises";
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
) {
  vi.stubEnv("PS_ACCESS_TOKEN", "node-database-fixture");
  vi.stubEnv("VANA_OWNER_PRIVATE_KEY", "");
  const ownerSignature = await signature();
  const context = await createServer(config, {
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
});
