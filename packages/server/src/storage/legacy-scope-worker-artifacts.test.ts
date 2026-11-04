import { Worker } from "node:worker_threads";
import Database from "better-sqlite3";
import { createRequire } from "node:module";
import { mkdir, mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { createLegacyScopeView } from "@opendatalabs/personal-server-ts-core/storage/legacy-scope-view";
import { initializeDatabase } from "./index-schema.js";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import { createLegacyScopeAuthority } from "./legacy-scope-authority.js";
import { trackLegacyScopeMutations } from "./legacy-scope-revalidation-state.js";

const closers: (() => Promise<void>)[] = [];
afterEach(async () => {
  while (closers.length) await closers.pop()!();
});

describe("real coverage Worker in shipped artifacts", () => {
  it.each([
    ["tsc", "../../dist/storage/legacy-scope-evaluation.js", false],
    ["bundle", "../../dist/bundle/enclave-main.mjs", false],
    [
      "tsc with concurrent writer",
      "../../dist/storage/legacy-scope-evaluation.js",
      true,
    ],
    [
      "bundle with concurrent writer",
      "../../dist/bundle/enclave-main.mjs",
      true,
    ],
  ] as const)(
    "%s evaluates two jobs without starting a server",
    async (_mode, entry, concurrentWriter) => {
      const parent = join(homedir(), ".tmp");
      await mkdir(parent, { recursive: true });
      const root = await mkdtemp(join(parent, "swr-worker-artifact-"));
      const dataDir = join(root, "data");
      const bootstrapRoot = join(root, "forbidden-server-root");
      await mkdir(dataDir);
      await mkdir(bootstrapRoot);
      const raw = initializeDatabase(join(root, "index.db"));
      const state = trackLegacyScopeMutations(raw, { ceilingMs: 1_800_000 });
      const store = createSqliteRecordStore(state.db);
      closers.push(async () => {
        store.close();
        await rm(root, { recursive: true, force: true });
      });
      const source = "https://registry.pdpp.dev/sources/oura";
      const scope = "oura.activity";
      store.registerConnection({
        instance: "artifact-instance",
        sourceId: source,
        method: "oura",
        label: "Synthetic",
      });
      function put(score: number) {
        expect(
          store.ingestBatch(
            [
              {
                instance: "artifact-instance",
                stream: "activity",
                key: "a",
                data: { id: "a", day: "2026-09-01", score },
                emitted_at: "2026-09-01T00:00:00Z",
              },
            ],
            () => "mutable_state",
            () => ["id"],
            { method: "oura", generation: 1 },
          ).rejected,
        ).toEqual([]);
      }
      put(80);
      const authority = createLegacyScopeAuthority(state.db, state);
      const config = {
        authority,
        records: store,
        configuredMethods: () => ["oura"],
      };
      const initial = await createLegacyScopeView(config).readLatest(scope);
      expect(initial.kind).toBe("canonical");
      if (initial.kind !== "canonical") throw Error("synthetic fixture");
      await writeFile(
        join(dataDir, "legacy.json"),
        JSON.stringify(initial.envelope),
      );
      state.db
        .prepare(
          "INSERT INTO data_files(path,scope,collected_at,size_bytes) VALUES ('legacy.json',?,'2026-10-01',1)",
        )
        .run(scope);
      const view = createLegacyScopeView({
        ...config,
        readLegacyHead: async () => initial.envelope,
      });
      expect((await view.readLatest(scope)).kind).toBe("canonical");

      // Preload observes forbidden startup effects without replacing Worker,
      // storage, projection, the compiled entry or its parentPort protocol.
      const guard = join(root, "startup-guard.mjs");
      await writeFile(
        guard,
        `
      import fs from 'node:fs';
      import net from 'node:net';
      import { syncBuiltinESMExports } from 'node:module';
      import { parentPort } from 'node:worker_threads';
      import { createRequire } from 'node:module';
      const Database = createRequire(import.meta.url)(${JSON.stringify(createRequire(import.meta.url).resolve("better-sqlite3"))});
      // Observe the real native error before the production job boundary
      // replaces it with its public generic failure. Never alter its outcome.
      const transaction = Database.prototype.transaction;
      function observe(execute) {
        return function (...args) {
          try { return execute.apply(this, args); }
          catch (error) {
            if (error.code === 'SQLITE_BUSY') parentPort.postMessage({ sqliteFailure: error.message });
            throw error;
          }
        };
      }
      Database.prototype.transaction = function (...args) {
        const native = transaction.apply(this, args);
        const wrapped = observe(native);
        for (const mode of ['deferred', 'immediate', 'exclusive'])
          wrapped[mode] = observe(native[mode]);
        wrapped.default = wrapped;
        wrapped.database = this;
        return wrapped;
      };
      const pragma = Database.prototype.pragma;
      Database.prototype.pragma = function (sql, ...args) {
        const result = pragma.call(this, sql, ...args);
        if (/^(busy_timeout|journal_mode|synchronous|foreign_keys)\\s*(?:=|$)/i.test(sql)) {
          const connectionPragmas = Object.fromEntries(['busy_timeout','journal_mode','synchronous','foreign_keys']
            .map(name => [name, pragma.call(this, name, { simple: true })]));
          parentPort.postMessage({ connectionPragmas });
        }
        return result;
      };
      const forbidden = process.env.PERSONAL_SERVER_ROOT_PATH;
      const fail = (effect) => {
        parentPort.postMessage({ forbiddenStartup: effect });
        throw Error('Evaluation Worker attempted server startup: ' + effect);
      };
      net.Server.prototype.listen = function () { fail('listen'); };
      for (const name of ['mkdir', 'readFile', 'writeFile', 'open', 'access']) {
        const original = fs.promises[name];
        fs.promises[name] = function (path, ...args) {
          if (String(path).startsWith(forbidden)) fail('bootstrap filesystem');
          return original.call(this, path, ...args);
        };
      }
      syncBuiltinESMExports();
    `,
      );
      const worker = new Worker(new URL(entry!, import.meta.url), {
        workerData: {
          legacyScopeEvaluation: true,
          epoch: new SharedArrayBuffer(4),
        },
        execArgv: ["--import", pathToFileURL(guard).href],
        env: {
          ...process.env,
          PERSONAL_SERVER_ROOT_PATH: bootstrapRoot,
          ENCLAVE_MODE: "false",
        },
        stdout: true,
        stderr: true,
      });
      closers.push(async () => {
        await worker.terminate();
      });
      const forbidden: string[] = [];
      const sqliteFailures: string[] = [];
      let connectionPragmas: Record<string, unknown> | undefined;
      let output = "";
      worker.stdout!.on("data", (chunk) => {
        output += String(chunk);
      });
      worker.stderr!.on("data", (chunk) => {
        output += String(chunk);
      });
      worker.on("message", (message) => {
        if (message.forbiddenStartup) forbidden.push(message.forbiddenStartup);
        if (message.sqliteFailure) sqliteFailures.push(message.sqliteFailure);
        if (message.connectionPragmas)
          connectionPragmas = message.connectionPragmas;
      });
      const job = {
        database: raw.name,
        dataDir,
        owner: "0x1111111111111111111111111111111111111111",
        replication: false,
        declarations: [],
        configuredMethods: [[source, ["oura"]]],
        optInMethods: [],
        instance: "artifact-instance",
        scopes: [scope],
        epoch: 0,
      };
      async function evaluate() {
        return new Promise<{
          wallMs: number;
          peakRssKiB: number;
          refused: string[];
        }>((resolve, reject) => {
          const timeout = setTimeout(
            () => finish(Error("Worker job did not reply")),
            10_000,
          );
          function finish(
            error?: Error,
            result?: { wallMs: number; peakRssKiB: number; refused: string[] },
          ) {
            clearTimeout(timeout);
            worker!.off("error", onError);
            worker!.off("exit", onExit);
            worker!.off("message", onMessage);
            if (error) reject(error);
            else resolve(result!);
          }
          const onError = (error: Error) => finish(error);
          const onExit = (code: number) =>
            finish(Error(`Worker exited before reply: ${code}`));
          const onMessage = (message: {
            error?: string;
            forbiddenStartup?: string;
            sqliteFailure?: string;
            connectionPragmas?: Record<string, unknown>;
            wallMs: number;
            peakRssKiB: number;
            refused: string[];
          }) => {
            if (message.sqliteFailure || message.connectionPragmas) return;
            if (message.error || message.forbiddenStartup)
              finish(
                Error(
                  [
                    message.error ?? message.forbiddenStartup,
                    ...sqliteFailures,
                  ].join(": "),
                ),
              );
            else finish(undefined, message);
          };
          worker!.once("error", onError);
          worker!.once("exit", onExit);
          worker!.on("message", onMessage);
          worker!.postMessage(job);
        });
      }
      expect(await evaluate()).toMatchObject({
        refused: [],
        wallMs: expect.any(Number),
        peakRssKiB: expect.any(Number),
      });
      expect(state.status(job.instance, scope)?.dirty_since).toBeNull();
      put(1);
      expect(state.status(job.instance, scope)?.dirty_since).not.toBeNull();
      const locker = concurrentWriter ? new Database(raw.name) : undefined;
      const ingest = locker ? createSqliteRecordStore(locker) : undefined;
      locker?.exec("BEGIN IMMEDIATE");
      if (ingest)
        expect(
          ingest.ingestBatch(
            [
              {
                instance: job.instance,
                stream: "activity",
                key: "a",
                data: { id: "a", day: "2026-09-01", score: 1 },
                emitted_at: "2026-09-01T00:00:00Z",
              },
            ],
            () => "mutable_state",
            () => ["id"],
            { method: "oura", generation: 1 },
          ).rejected,
        ).toEqual([]);
      // The Worker is already running after its first real reply. Its next
      // confirmation must wait for this other connection's brief writer lock.
      const unlock = setTimeout(() => locker?.exec("COMMIT"), 250);
      try {
        const result = await evaluate();
        // An overlapping ingest may defeat confirmation's snapshot fence;
        // it must return a result, not fail opening its writer transaction.
        expect(result.refused).toEqual([
          `${scope}:${concurrentWriter ? "store_inconsistent_read" : "canonical_view_incomplete"}`,
        ]);
      } finally {
        clearTimeout(unlock);
        if (locker?.inTransaction) locker.exec("ROLLBACK");
        locker?.close();
      }
      if (concurrentWriter)
        expect((await evaluate()).refused).toEqual([
          `${scope}:canonical_view_incomplete`,
        ]);
      expect(sqliteFailures).toEqual([]);
      expect(connectionPragmas).toEqual(
        Object.fromEntries(
          ["busy_timeout", "journal_mode", "synchronous", "foreign_keys"].map(
            (name) => [name, raw.pragma(name, { simple: true })],
          ),
        ),
      );
      expect(view.verdictFor(scope)[0]?.verdict).toBe("not_covered");
      expect(view.listingFor(scope).kind).toBe("refused");
      expect(forbidden).toEqual([]);
      expect(await readdir(bootstrapRoot)).toEqual([]);
      expect(output).not.toMatch(
        /Server started|Loopback auth listener|PDPP Authorization Server mounted/,
      );
    },
    30_000,
  );
});
