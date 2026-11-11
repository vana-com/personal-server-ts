import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  handlePersonalServerDataRequest,
  type PersonalServerDataApiDeps,
} from "../../../core/src/api/index.js";
import { parseDataScopeContract } from "../../../core/src/contracts/data.js";
import type { LocalSyncDeps } from "../../../core/src/localdb/deps.js";
import type { SqlDriver } from "../../../core/src/localdb/driver.js";
import { createLocalHistory } from "../../../core/src/localdb/history.js";
import { openLocalDb } from "../../../core/src/localdb/open.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const OWNER = "0x0000000000000000000000000000000000000001";
const SCOPE = "pdpp.github-browser.repositories";
const OBSERVED = Date.parse("2025-02-03T04:05:06.000Z");

describe("GET /v1/data/:scope/versions with a logical stream name", () => {
  const dirs: string[] = [];
  const drivers: SqlDriver[] = [];

  afterEach(async () => {
    for (const driver of drivers.splice(0)) await driver.close();
    for (const dir of dirs.splice(0))
      rmSync(dir, { recursive: true, force: true });
  });

  async function fresh(mode: "switched" | "unswitched" = "switched") {
    const dir = mkdtempSync(join(process.cwd(), ".versions-route-"));
    dirs.push(dir);
    const driver = openBetterSqlite3(join(dir, "db.sqlite"));
    drivers.push(driver);
    const db = await openLocalDb(driver, {
      owner: "0xabc",
      network: "test",
      deviceId: "versions-route-test",
    });
    const poison = new Proxy(
      {},
      {
        get() {
          throw new Error("unexpected access");
        },
      },
    );
    const history = createLocalHistory(
      {
        db,
        queue: { run: async (_id, _kind, fn) => fn() },
        ownerAddress: "0xabc",
        registry: poison,
        blobs: poison,
        keys: poison,
        signer: poison,
        logger: { info() {}, warn() {} },
        now: () => OBSERVED,
        newOp: () => "op",
      } as LocalSyncDeps,
      { olderVersionReads: () => true },
    );
    const deps: PersonalServerDataApiDeps = {
      auth: {
        authorizeOwner: vi.fn(async () => undefined),
        authorizeBuilderList: vi.fn(async () => undefined),
        authorizeBuilderRead: vi.fn(async () => ({ grantId: "owner" })),
      },
      history,
      serverOwner: OWNER,
      accountMode: { read: () => mode },
      accountStorageMode: { read: () => mode },
      storage: new Proxy({} as PersonalServerDataApiDeps["storage"], {
        get: () => {
          throw new Error("Unexpected legacy storage access");
        },
      }),
      accessLogWriter: { write: vi.fn(async () => undefined) },
      now: () => new Date(OBSERVED),
      createLogId: () => "log",
    } as unknown as PersonalServerDataApiDeps;
    return { db, deps };
  }

  async function seed(db: SqlDriver, withVersion: boolean) {
    await db.batch([
      {
        sql: "INSERT INTO connections(connection_id, connector, ns, generation, control_state) VALUES ('c1', 'github-browser', '', 1, 'active')",
      },
      {
        sql: "INSERT INTO stream_state(connection_id, stream, primary_key, semantics, incremental, head_version, head_generation, head_blob, last_delete_version) VALUES ('c1', 'repositories', '[]', 'mutable_state', 0, ?, 1, ?, 0)",
        params: [withVersion ? 3 : 0, withVersion ? "blob-3" : null],
      },
      ...(withVersion
        ? [
            {
              sql: "INSERT INTO stream_versions(connection_id, stream, version, generation, head_blob, head_format, record_count, observed_at, complete, kind) VALUES ('c1', 'repositories', 3, 1, 'blob-3', 1, 0, ?, 1, 'published')",
              params: [OBSERVED],
            },
          ]
        : []),
    ]);
  }

  const get = (
    deps: PersonalServerDataApiDeps,
    path: string,
    init?: RequestInit,
  ) =>
    handlePersonalServerDataRequest(
      new Request(`https://server.example/v1/data${path}`, init),
      deps,
      { basePath: "/v1/data" },
    );

  it("lists the published version of a hyphenated connector", async () => {
    const { db, deps } = await fresh();
    await seed(db, true);
    const response = await get(deps, `/${SCOPE}/versions?limit=200&offset=0`);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      scope: SCOPE,
      versions: [
        {
          fileId: "blob-3",
          schemaId: null,
          collectedAt: new Date(OBSERVED).toISOString(),
          version: 3,
          producer: null,
          producer_provenance: null,
        },
      ],
      total: 1,
      limit: 200,
      offset: 0,
      nextCursor: null,
    });
  });

  it("answers the physical alias with the logical name", async () => {
    const { db, deps } = await fresh();
    await seed(db, true);
    const response = await get(
      deps,
      "/pdpp.github-browser~.repositories/versions",
    );
    expect(response.status).toBe(200);
    expect((await response.json()).scope).toBe(SCOPE);
  });

  it("returns an empty page when no version is visible", async () => {
    const { db, deps } = await fresh();
    await seed(db, true);
    await db.batch([
      { sql: "UPDATE stream_state SET last_delete_version = 3" },
    ]);
    const response = await get(deps, `/${SCOPE}/versions`);
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ versions: [], total: 0 });
  });

  it.each([
    ["a slash", "pdpp.github-browser.repo%2Fsitories"],
    ["whitespace", "pdpp.github-browser.repo%20sitories"],
    ["a control character", "pdpp.github-browser.repo%07sitories"],
    ["a misplaced tilde", "pdpp.github-browser~~.repositories"],
    ["a malformed identity", "pdpp.github-browser~xyz.repositories"],
  ])("still refuses a name with %s", async (_label, name) => {
    const { db, deps } = await fresh();
    await seed(db, true);
    const response = await get(deps, `/${name}/versions`);
    expect(response.status).toBe(400);
  });

  it("keeps write, delete and import strict for the logical name", async () => {
    expect(parseDataScopeContract(SCOPE).ok).toBe(false);
    const { deps } = await fresh("unswitched");
    for (const method of ["POST", "DELETE"]) {
      const response = await get(deps, `/${SCOPE}`, {
        method,
        body: method === "POST" ? "{}" : undefined,
      });
      expect(response.status, method).toBe(400);
    }
    const imported = await get(deps, `/${SCOPE}/imports/${"a".repeat(64)}`, {
      method: "PUT",
      body: "{}",
    });
    expect(imported.status).toBe(400);
  });
});
