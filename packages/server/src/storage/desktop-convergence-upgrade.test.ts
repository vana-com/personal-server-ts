import { afterEach, describe, expect, it, vi } from "vitest";
import Database from "better-sqlite3";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import type {
  DataFileEnvelope,
  GatewayClient,
} from "@opendatalabs/vana-sdk/node";
import { recoverServerOwner } from "@opendatalabs/vana-sdk/node";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import {
  buildWeb3SignedHeader,
  createTestWallet,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import {
  createLegacyScopeView,
  type LegacyScopeListing,
} from "@opendatalabs/personal-server-ts-core/storage/legacy-scope-view";
import { createServer, type ServerContext } from "../bootstrap.js";
import { initializeDatabase } from "./index-schema.js";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import { createLegacyScopeAuthority } from "./legacy-scope-authority.js";

type Value = string | number | null | { hex: string };
interface Scenario {
  name: string;
  instance: string;
  method: string;
  rows: Record<string, Record<string, Value>[]>;
  files: Record<string, string>;
  hashes: Record<string, string>;
  archiveBlobs: { blobId: string; text: string }[];
  listingBefore: Record<string, LegacyScopeListing>;
  expected: Record<
    string,
    {
      kind: "file" | "canonical" | "refused";
      envelope?: DataFileEnvelope;
      reason?: string;
    }
  >;
  expectedListing: Record<string, LegacyScopeListing>;
}
const fixtures = new URL("./__fixtures__/desktop-b-upgrade/", import.meta.url);
const schema = await readFile(new URL("schema.sql", fixtures), "utf8");
const scenarios = JSON.parse(
  await readFile(new URL("cases.json", fixtures), "utf8"),
) as Scenario[];
const scopes = ["oura.sleep", "oura.readiness", "oura.activity"];
const source = "https://registry.pdpp.dev/sources/oura";
const signature =
  "0xedbb7743cce459345238442dcfb291f234a321d253485eaa58251aa0f28ea8f1410ab988bae2657b689cd24417b41e315efc22ba333024f4a6269c424ded8d361b";
const ownerToken = "desktop-upgrade-owner";
const grantId = `0x${"11".repeat(32)}`;
const builder = createTestWallet(0);

function rows(db: Database.Database) {
  const tables = db
    .prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND (name NOT LIKE 'sqlite_%' OR name = 'sqlite_sequence') AND name != 'pdpp_schema_version' ORDER BY name",
    )
    .all() as { name: string }[];
  return Object.fromEntries(
    tables.map(({ name }) => [
      name,
      db.prepare(`SELECT * FROM "${name}" ORDER BY rowid`).all(),
    ]),
  );
}
function seed(db: Database.Database, scenario: Scenario) {
  db.pragma("foreign_keys = OFF");
  db.exec(schema);
  db.transaction(() => {
    for (const [table, records] of Object.entries(scenario.rows)) {
      if (table === "sqlite_sequence") db.exec("DELETE FROM sqlite_sequence");
      for (const record of records) {
        const columns = Object.keys(record);
        db.prepare(
          `INSERT INTO "${table}" (${columns.map((c) => `"${c}"`).join(",")}) VALUES (${columns.map(() => "?").join(",")})`,
        ).run(
          ...Object.values(record).map((value) =>
            value !== null && typeof value === "object"
              ? Buffer.from(value.hex, "hex")
              : value,
          ),
        );
      }
    }
  })();
  db.pragma("foreign_keys = ON");
}

function blobState(db: Database.Database) {
  return Object.fromEntries(
    [
      "pdpp_blobs",
      "pdpp_blob_bytes",
      "pdpp_blob_claims",
      "pdpp_claude_transition",
    ].map((table) => [
      table,
      db.prepare(`SELECT * FROM "${table}" ORDER BY rowid`).all(),
    ]),
  );
}

let dir: string | undefined;
let context: ServerContext | undefined;
let openDb: Database.Database | undefined;
afterEach(async () => {
  await context?.cleanup();
  context = undefined;
  if (openDb?.open) openDb.close();
  if (dir) await rm(dir, { recursive: true, force: true });
  dir = undefined;
  vi.unstubAllEnvs();
});

async function fileHashes(scenario: Scenario) {
  return Object.fromEntries(
    await Promise.all(
      Object.keys(scenario.files).map(async (path) => [
        path,
        createHash("sha256")
          .update(await readFile(join(dir!, "data", path)))
          .digest("hex"),
      ]),
    ),
  );
}
async function boot(scenario: Scenario) {
  vi.stubEnv("VANA_MASTER_KEY_SIGNATURE", signature);
  vi.stubEnv("PS_ACCESS_TOKEN", ownerToken);
  const owner = (await recoverServerOwner(signature)).toLowerCase();
  const manifest = JSON.parse(
    await readFile(
      new URL(
        "../__fixtures__/oura-14ec4e7e1/oura-browser.manifest.json",
        import.meta.url,
      ),
      "utf8",
    ),
  ) as {
    version: string;
    streams: {
      name: string;
      primary_key: string[];
      schema: { properties: Record<string, unknown>; required: string[] };
    }[];
  };
  const declarationPath = join(dir!, "oura.json");
  await writeFile(
    declarationPath,
    JSON.stringify({
      source_id: source,
      source_kind: "connector",
      version: manifest.version,
      streams: manifest.streams.map((s) => ({
        name: s.name,
        fields: Object.keys(s.schema.properties),
        required_fields: s.schema.required,
        primary_key: s.primary_key,
      })),
    }),
  );
  const gateway = {
    getBuilder: vi.fn().mockResolvedValue({
      id: "upgrade-builder",
      ownerAddress: owner,
      granteeAddress: builder.address,
      publicKey: "0x04key",
      appUrl: "https://app.example.com",
      addedAt: "2026-01-21T10:00:00.000Z",
    }),
    getGrant: vi.fn().mockResolvedValue({
      id: grantId,
      grantorAddress: owner,
      granteeId: "upgrade-builder",
      scopes: ["oura.*"],
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
      revocationSubmittedAt: null,
      fee: {
        asset: "0x0000000000000000000000000000000000000000",
        registrationFee: "0",
        dataAccessFee: "0",
        totalDue: "0",
      },
    }),
  } as unknown as GatewayClient;
  return createServer(
    ServerConfigSchema.parse({
      tunnel: { enabled: false },
      payment: { enabled: false },
      pdpp: {
        enabled: true,
        declarationPaths: [declarationPath],
        methods: [
          { method_id: scenario.method, declaration_path: declarationPath },
        ],
        optInMethods: [],
      },
    }),
    { serverDir: dir!, dataDir: join(dir!, "data"), gatewayClient: gateway },
  );
}

// Oura/Claude state uses actual B runtime modules and expected reads come from
// B's view. Cancelled-import/reset rows are synthetic SQL seeds. Test execution
// needs no Git checkout. sqlite_sequence preserves retired file-id high water.
describe("B-written Desktop profile convergence", () => {
  it.each(scenarios)(
    "preserves $name ownership, exact replacement, history and owner/builder reads across upgrade and restart",
    async (scenario) => {
      dir = await mkdtemp(join(tmpdir(), "desktop-b-upgrade-"));
      const path = join(dir, "index.db");
      openDb = new Database(path);
      seed(openDb, scenario);
      expect(openDb.pragma("user_version", { simple: true })).toBe(15);
      expect(
        openDb.prepare("SELECT version FROM pdpp_schema_version").get(),
      ).toEqual({ version: 14 });
      const original = rows(openDb);
      openDb.close();
      for (const [path, bytes] of Object.entries(scenario.files)) {
        await mkdir(dirname(join(dir, "data", path)), { recursive: true });
        await writeFile(join(dir, "data", path), bytes);
      }
      for (let restart = 0; restart < 2; restart++) {
        openDb = initializeDatabase(path);
        const store = createSqliteRecordStore(openDb);
        if (restart === 0) expect(rows(openDb)).toEqual(original);
        if (restart === 0 && scenario.name === "stale-nonhead") {
          openDb.exec("SAVEPOINT sequence_probe");
          try {
            const probe = openDb
              .prepare(
                "INSERT INTO data_files(scope,path,collected_at) VALUES ('probe.scope','probe/retired-id.json','2026-10-24T00:00:00Z')",
              )
              .run();
            // B used and retired id 4; a later file must never reuse it.
            expect(Number(probe.lastInsertRowid)).toBe(5);
          } finally {
            openDb.exec("ROLLBACK TO sequence_probe; RELEASE sequence_probe");
          }
          expect(rows(openDb)).toEqual(original);
        }
        expect(openDb.pragma("user_version", { simple: true })).toBe(17);
        expect(
          openDb.prepare("SELECT version FROM pdpp_schema_version").get(),
        ).toEqual({ version: 15 });
        const index = openDb
          .prepare(
            "SELECT sql FROM sqlite_master WHERE name='idx_pdpp_record_changes_blob_ref'",
          )
          .get() as { sql: string };
        expect(index.sql.replace(/\s+/g, " ").trim()).toBe(
          "CREATE INDEX idx_pdpp_record_changes_blob_ref ON pdpp_record_changes (CAST(CASE WHEN json_valid(data) THEN json_extract(data, '$.blob_ref.blob_id') END AS TEXT))",
        );
        for (const blob of scenario.archiveBlobs)
          expect(Buffer.from(store.getBlobBytes(blob.blobId)!)).toEqual(
            Buffer.from(blob.text),
          );
        const view = createLegacyScopeView({
          authority: createLegacyScopeAuthority(openDb),
          records: store,
          configuredMethods: (id) => (id === source ? [scenario.method] : []),
          readLegacyHead: async (head) =>
            JSON.parse(
              await readFile(join(dir!, "data", head.path), "utf8"),
            ) as DataFileEnvelope,
        });
        if (restart === 0)
          for (const scope of scopes)
            expect(view.listingFor(scope)).toEqual(
              scenario.listingBefore[scope],
            );
        for (const scope of scopes) {
          const read = await view.readLatest(scope);
          expect(read.kind).toBe(scenario.expected[scope]!.kind);
          if (read.kind === "canonical")
            expect(read.envelope).toEqual(scenario.expected[scope]!.envelope);
          expect(view.listingFor(scope)).toEqual(
            scenario.expectedListing[scope],
          );
        }
        const recordVersions = openDb
          .prepare(
            "SELECT instance,stream,record_key,version,data,deleted FROM pdpp_records ORDER BY instance,stream,record_key",
          )
          .all();
        const history = openDb
          .prepare("SELECT * FROM pdpp_record_changes ORDER BY id")
          .all();
        const archivedBlobs = blobState(openDb);
        store.close();
        expect(await fileHashes(scenario)).toEqual(scenario.hashes);
        context = await boot(scenario);
        const requirements = await context.app.request(
          "/v1/import/oura-browser/requirements",
          { headers: { authorization: `Bearer ${ownerToken}` } },
        );
        expect(requirements.status, await requirements.clone().text()).toBe(
          200,
        );
        expect(await requirements.json()).toMatchObject({
          since: "2026-09-01",
        });
        for (const scope of scopes) {
          const expected = scenario.expected[scope]!;
          for (const role of ["owner", "builder"]) {
            const uri = `/v1/data/${scope}`;
            const authorization =
              role === "owner"
                ? `Bearer ${ownerToken}`
                : await buildWeb3SignedHeader({
                    wallet: builder,
                    aud: context.config.server.origin,
                    method: "GET",
                    uri,
                    grantId,
                  });
            const response = await context.app.request(uri, {
              headers: { authorization },
            });
            if (expected.kind === "refused") {
              expect(response.status).toBe(503);
              expect(await response.json()).toMatchObject({
                reason: expected.reason,
              });
            } else {
              expect(response.status, await response.clone().text()).toBe(200);
              expect(response.headers.get("X-Vana-Data-Source")).toBe(
                expected.kind === "file" ? "legacy" : "canonical",
              );
              expect(await response.json()).toEqual(expected.envelope);
            }
            const listUri = "/v1/data";
            const listAuth =
              role === "owner"
                ? `Bearer ${ownerToken}`
                : await buildWeb3SignedHeader({
                    wallet: builder,
                    aud: context.config.server.origin,
                    method: "GET",
                    uri: listUri,
                    grantId,
                  });
            const listed = await context.app.request(listUri, {
              headers: { authorization: listAuth },
            });
            expect(listed.status, await listed.clone().text()).toBe(200);
            const listedScopes = (await listed.json()).scopes.map(
              (entry: { scope: string }) => entry.scope,
            ) as string[];
            expect(listedScopes.includes(scope)).toBe(
              expected.kind !== "refused",
            );
          }
        }
        if (["fewer", "disjoint", "empty", "parity"].includes(scenario.name)) {
          const retained = scenario.rows.pdpp_records!.filter(
            (row) => row.instance === scenario.instance && row.deleted === 0,
          );
          const at =
            scenario.name === "parity"
              ? "2026-10-01T12:00:00.000Z"
              : "2026-10-21T12:00:00.000Z";
          const retry = await context.app.request("/v1/import/oura-browser", {
            method: "POST",
            headers: {
              authorization: `Bearer ${ownerToken}`,
              "content-type": "application/json",
            },
            body: JSON.stringify({
              collectedAt: at,
              selection: { streams: scopes.map((name) => ({ name })) },
              records: retained.map((row) => ({
                stream: row.stream,
                data: JSON.parse(String(row.data)),
              })),
              completion: {
                streams: scopes.map((scope) => ({
                  stream: scope.slice(5),
                  status: "complete",
                  recordCount: retained.filter(
                    (row) => row.stream === scope.slice(5),
                  ).length,
                })),
              },
            }),
          });
          // Same-time parity still sees retained deleted identities. A fresh
          // fewer/disjoint/empty replacement is safe, but its same-time retry
          // is refused against that history. The parity retry must succeed.
          if (scenario.name === "parity") expect(retry.status).toBe(200);
          else {
            expect(retry.status).toBe(409);
            expect(await retry.json()).toMatchObject({
              ok: false,
              reason: "missing_entity",
            });
          }
        }
        await context.cleanup();
        context = undefined;
        openDb = new Database(path);
        expect(
          openDb
            .prepare(
              "SELECT instance,stream,record_key,version,data,deleted FROM pdpp_records ORDER BY instance,stream,record_key",
            )
            .all(),
        ).toEqual(recordVersions);
        expect(
          openDb.prepare("SELECT * FROM pdpp_record_changes ORDER BY id").all(),
        ).toEqual(history);
        expect(blobState(openDb)).toEqual(archivedBlobs);
        expect(openDb.pragma("integrity_check", { simple: true })).toBe("ok");
        openDb.close();
        expect(await fileHashes(scenario)).toEqual(scenario.hashes);
      }
    },
    60000,
  );

  it("rolls back a failed PDPP v15 migration without losing history, then retries exactly once", async () => {
    dir = await mkdtemp(join(tmpdir(), "desktop-b-migration-fault-"));
    const path = join(dir, "index.db");
    openDb = new Database(path);
    seed(
      openDb,
      scenarios.find((s) => s.name === "fewer")!,
    );
    const original = rows(openDb);
    openDb.close();
    openDb = initializeDatabase(path);
    openDb.exec(
      "CREATE TEMP TRIGGER fail_pdpp_upgrade BEFORE UPDATE ON pdpp_schema_version BEGIN SELECT RAISE(ABORT, 'injected upgrade failure'); END",
    );
    expect(() => createSqliteRecordStore(openDb!)).toThrow(
      "injected upgrade failure",
    );
    expect(
      openDb.prepare("SELECT version FROM pdpp_schema_version").get(),
    ).toEqual({ version: 14 });
    expect(
      openDb
        .prepare(
          "SELECT name FROM sqlite_master WHERE name='idx_pdpp_record_changes_blob_ref'",
        )
        .get(),
    ).toBeUndefined();
    expect(rows(openDb)).toEqual(original);
    openDb.exec("DROP TRIGGER fail_pdpp_upgrade");
    const store = createSqliteRecordStore(openDb);
    expect(rows(openDb)).toEqual(original);
    expect(
      openDb.prepare("SELECT version FROM pdpp_schema_version").get(),
    ).toEqual({ version: 15 });
    store.close();
  });
});
