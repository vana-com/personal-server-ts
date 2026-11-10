import { access, mkdir, mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { privateKeyToAccount } from "viem/accounts";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { createMemoryModeRecordStore } from "@opendatalabs/personal-server-ts-core/sync/account-mode";
import {
  localDatabaseName,
  openLocalDb,
} from "../../core/src/localdb/index.js";
import { applyConnection } from "../../core/src/localdb/apply.js";
import { streamSyncNetwork } from "@opendatalabs/personal-server-ts-core/stream-sync";
import { openBetterSqlite3 } from "./localdb/better-sqlite3-driver.js";
import { createServer, type ServerContext } from "./bootstrap.js";

// P06 is built in another lane. Keep its boundary explicit; Node opens the
// real driver and the real database resolver/query, not a fake read service.
vi.mock(
  "@opendatalabs/personal-server-ts-core/localdb",
  async () => import("../../core/src/localdb/index.js"),
);
vi.mock("../../core/src/localdb/apply.js", () => ({
  applyConnection: vi.fn(async () => []),
  applyStream: vi.fn(),
}));

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
async function boot(rootPath: string, store = createMemoryModeRecordStore()) {
  vi.stubEnv("PS_ACCESS_TOKEN", "node-database-fixture");
  vi.stubEnv("VANA_OWNER_PRIVATE_KEY", "");
  const ownerSignature = await privateKeyToAccount(
    `0x${"11".repeat(32)}`,
  ).signMessage({ message: "Disposable Node database fixture" });
  const context = await createServer(config, {
    rootPath,
    ownerSignature,
    accountModeStore: store,
  });
  contexts.push(context);
  return context;
}
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
    let context = await boot(root, store);
    const network = streamSyncNetwork(config.gateway);
    await mkdir(join(root, "localdb"), { recursive: true });
    const driver = openBetterSqlite3(
      join(
        root,
        "localdb",
        encodeURIComponent(localDatabaseName(context.serverOwner!, network)) +
          ".sqlite",
      ),
    );
    try {
      await openLocalDb(driver, {
        owner: context.serverOwner!,
        network,
        deviceId: context.serverAccount!.address,
      });
      await driver.batch([
        {
          sql: `INSERT INTO connections (connection_id,connector,ns,generation,control_state,control_version)
          VALUES ('pdpp.fixture-source~','fixture-source','',1,'active',1)`,
        },
        {
          sql: `INSERT INTO stream_state (connection_id,stream,primary_key,semantics,incremental,complete,
          head_version,head_generation,head_data_hash,head_blob)
          VALUES ('pdpp.fixture-source~','items','["id"]','mutable_state',1,1,1,1,'fixture-hash','fixture-head')`,
        },
        {
          sql: `INSERT INTO stream_versions VALUES ('pdpp.fixture-source~','items',1,1,'fixture-head',4,1,1000,1,'applied')`,
        },
        {
          sql: `INSERT INTO records (connection_id,stream,pk_hash,record_key,stamp_o,stamp_r,body,body_sha256)
          VALUES ('pdpp.fixture-source~','items',?,'item',1000,'fixture',?,'fixture-hash')`,
          params: [
            "a".repeat(64),
            JSON.stringify({ id: "item", value: "database" }),
          ],
        },
      ]);
    } finally {
      await driver.close();
    }
    await context.accountModeAuthority.submitEvidence({
      owner: context.serverOwner!,
      state: "on",
    });
    for (let attempt = 0; attempt < 2; attempt++) {
      const response = await context.app.request(
        "/v1/data/pdpp.fixture-source.items",
        { headers },
      );
      expect(response.status).toBe(200);
      expect(applyConnection).toHaveBeenCalledWith(
        expect.anything(),
        "pdpp.fixture-source~",
      );
      expect(response.headers.get("X-Vana-Data-Source")).toBe("stream-sync");
      expect(await response.json()).toMatchObject({
        data: { records: [{ id: "item", value: "database" }] },
      });
      const first = await context.getLocalSync!();
      expect(await context.getLocalSync!()).toBe(first);
      await context.cleanup();
      contexts.splice(contexts.indexOf(context), 1);
      if (attempt === 0) context = await boot(root, store);
    }
  });
});
