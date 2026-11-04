import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { createLegacyScopeView } from "@opendatalabs/personal-server-ts-core/storage/legacy-scope-view";
import { handlePersonalServerDataRequest } from "@opendatalabs/personal-server-ts-core/api";
import { initializeDatabase } from "./index-schema.js";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import { createLegacyScopeAuthority } from "./legacy-scope-authority.js";
import { trackLegacyScopeMutations } from "./legacy-scope-revalidation-state.js";
import { createNodeDataStorage } from "./node-data-storage.js";
import { createIndexManager } from "./index-manager.js";

const scope = "oura.activity";
const instance = "boot-synthetic";
const stamp = "2026-09-01T00:00:00.000Z";

it.each(["tracker-free downgrade", "PDPP disabled"] as const)(
  "invalidates a surviving clean proof after a %s process writes",
  async (mode) => {
    const root = await mkdtemp(join(homedir(), ".tmp", "swr-boot-"));
    const path = join(root, "index.db");
    await mkdir(join(root, "data"));
    let raw = initializeDatabase(path);
    try {
      let state = trackLegacyScopeMutations(raw, {
        ceilingMs: 2000,
        now: () => 1000,
      });
      let store = createSqliteRecordStore(state.db);
      store.registerConnection({
        instance,
        sourceId: "https://registry.pdpp.dev/sources/oura",
        method: "oura",
        label: "Synthetic",
      });
      store.ingestBatch(
        [
          {
            instance,
            stream: "activity",
            key: "a",
            data: { id: "a", day: "2026-09-01", score: 80 },
            emitted_at: stamp,
          },
        ],
        () => "mutable_state",
        () => ["id"],
        { method: "oura", generation: 1 },
      );
      let authority = createLegacyScopeAuthority(state.db, state);
      const original = await createLegacyScopeView({
        authority,
        records: store,
        configuredMethods: () => ["oura"],
      }).readLatest(scope);
      if (original.kind !== "canonical") throw Error("synthetic projection");
      state.db
        .prepare(
          "INSERT INTO data_files(path,scope,collected_at,size_bytes) VALUES ('legacy.json',?,?,1)",
        )
        .run(scope, stamp);
      state.observePolicy("unchanged policy", 1000);
      let view = createLegacyScopeView({
        authority,
        records: store,
        configuredMethods: () => ["oura"],
        readLegacyHead: async () => original.envelope,
      });
      expect((await view.readLatest(scope)).kind).toBe("canonical");
      expect((await view.readLatest(scope)).kind).toBe("canonical");
      expect(state.status(instance, scope)?.dirty_since).toBeNull();
      const revision = state.revision(instance);
      store.close();

      // This separate process writes the migrated DB without a tracker. The
      // disabled arm boots the real server composition with PDPP disabled.
      const child = `
        import { createSqliteRecordStore } from ${JSON.stringify(new URL("../../dist/storage/pdpp-records-sqlite-store.js", import.meta.url).href)};
        let db, context;
        if (${JSON.stringify(mode)} === 'PDPP disabled') {
          const { createServer } = await import(${JSON.stringify(new URL("../../dist/bootstrap.js", import.meta.url).href)});
          const { ServerConfigSchema } = await import(${JSON.stringify(new URL("../../../core/dist/schemas/server-config.js", import.meta.url).href)});
          const { indexDatabase } = await import(${JSON.stringify(new URL("../../dist/storage/index-manager.js", import.meta.url).href)});
          context = await createServer(ServerConfigSchema.parse({ pdpp: { enabled: false }, tunnel: { enabled: false }, payment: { enabled: false } }), { rootPath: process.argv[1], gatewayClient: { getServerByOwnerAddress: async () => ({ server: null }) } });
          if (context.config.pdpp.enabled) throw Error('PDPP must be disabled');
          db = indexDatabase(context.indexManager);
        } else {
          const { initializeDatabase } = await import(${JSON.stringify(new URL("../../dist/storage/index-schema.js", import.meta.url).href)});
          db = initializeDatabase(process.argv[1] + '/index.db');
        }
        const store = createSqliteRecordStore(db);
        store.deleteRecord(${JSON.stringify(instance)}, 'activity', 'a', '2026-09-02T00:00:00.000Z', 'mutable_state');
        if (context) await context.cleanup(); else store.close();
      `;
      execFileSync(
        process.execPath,
        ["--input-type=module", "-e", child, root],
        {
          timeout: 20000,
          stdio: ["ignore", "pipe", "pipe"],
          env: { ...process.env, PERSONAL_SERVER_ROOT_PATH: root },
        },
      );
      raw = initializeDatabase(path);
      // Demonstrate the marker gap before installing this boot's tracker.
      expect(
        raw
          .prepare(
            "SELECT dirty_since FROM legacy_scope_revalidation_scopes WHERE instance=? AND scope=?",
          )
          .pluck()
          .get(instance, scope),
      ).toBeNull();
      state = trackLegacyScopeMutations(raw, {
        ceilingMs: 2000,
        now: () => 2000,
      });
      state.observePolicy("unchanged policy", 2000);
      expect.soft(state.status(instance, scope)?.dirty_since).toBe(2000);
      expect.soft(state.revision(instance)).toBeGreaterThan(revision);
      store = createSqliteRecordStore(state.db);
      authority = createLegacyScopeAuthority(state.db, state);
      view = createLegacyScopeView({
        authority,
        records: store,
        configuredMethods: () => ["oura"],
        readLegacyHead: async () => original.envelope,
      });
      const response = await handlePersonalServerDataRequest(
        new Request(`http://localhost/v1/data/${scope}`),
        {
          storage: createNodeDataStorage({
            indexManager: createIndexManager(state.db),
            hierarchyOptions: { dataDir: join(root, "data") },
          }),
          legacyScopeView: view,
          auth: {
            authorizeOwner: async () => {},
            authorizeBuilderList: async () => {},
            authorizeBuilderRead: async () => ({ grantId: "owner" }),
          },
          accessLogWriter: { write: async () => {} },
        },
        { basePath: "/v1/data" },
      );
      expect(response.status).toBe(503);
      const body = await response.json();
      expect(body).toMatchObject({
        error: "CANONICAL_VIEW_UNAVAILABLE",
        retryable: false,
      });
      expect(JSON.stringify(body)).not.toContain('"score":80');
      expect(view.listingFor(scope).kind).toBe("refused");
    } finally {
      if (raw.open) raw.close();
      await rm(root, { recursive: true, force: true });
    }
  },
);
