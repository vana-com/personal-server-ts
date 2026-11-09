/**
 * Stream-sync e2e on real services: the same hops as the walking skeleton
 * (`npm run e2e:stream-sync-skeleton`), but the registry is the real
 * data-gateway on Postgres, storage is a blob-store process, the full server
 * listens on a real port and reads go over HTTP, and the phone side is the
 * PS-Lite sync manager and runtime (the code the mobile app runs).
 *
 * Start the stack first:
 *   GATEWAY_DIR=<data-gateway checkout> bash scripts/stream-sync-real/up.sh
 * Run:
 *   npm run e2e:stream-sync-real
 * Stop the stack:
 *   bash scripts/stream-sync-real/down.sh
 *
 * How a connector run reaches a writer: the full server's run is still a
 * fixture that calls its writer in-process (a stub); PS-Lite's run goes through
 * its run intake, the same code the phone app calls.
 *
 * Prints counts and truncated hashes only, never record bodies or ids.
 */

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { privateKeyToAccount } from "viem/accounts";
import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
import { createGatewayClient } from "@opendatalabs/vana-sdk/node";
import {
  canonicalJson,
  type JsonValue,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  documentDigest,
  manifestArtifactResolver,
  manifestStreamLister,
  type StreamSyncWriter,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import { createServerSigner } from "@opendatalabs/personal-server-ts-core/signing";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { createIndexedDbStreamSyncFiles } from "../packages/lite/src/index.js";
import { createPsLiteSyncManager } from "../packages/lite/src/sync.js";
import { createPsLiteRuntime } from "../packages/lite/src/runtime.js";
import { loadOrCreatePsLiteServerIdentity } from "../packages/lite/src/state.js";
import {
  createMemoryPsLiteAccessLogStore,
  createMemoryPsLiteStateStore,
  createMemoryPsLiteStorage,
  createMemoryPsLiteTokenStore,
} from "../packages/lite/src/test-support/memory.js";
import { createServer } from "../packages/server/src/bootstrap.js";
import { listenHttpServer } from "../packages/server/src/listen.js";
import {
  OWNER,
  OWNER_KEY,
  OWNER_SIGNATURE,
  SERVER_KEY,
  SHAPE,
} from "../packages/server/src/stream-sync/oracle.test-utils.js";

const CONNECTOR = "realsync";
const STREAM = "items";
const SCOPE = `pdpp.${CONNECTOR}.${STREAM}`;
const TOKEN = "stream-sync-real-owner-token";
const SERVER_PORT = Number(process.env.STREAM_SYNC_REAL_SERVER_PORT ?? 55453);
const CHAIN = 14800;

interface Hop {
  name: string;
  pass: boolean;
  detail: string;
}

const hash = (value: unknown): string =>
  createHash("sha256").update(canonicalJson(value)).digest("hex").slice(0, 12);
const sortedHashes = (records: readonly unknown[]): string[] =>
  records.map(hash).sort();

function stackEnv(): { gatewayUrl: string; storageUrl: string; pg: string } {
  const file = join(
    process.env.STACK_DIR ??
      join(process.env.HOME ?? "", ".tmp/stream-sync-real-stack"),
    "env",
  );
  const fromFile: Record<string, string> = {};
  try {
    for (const line of readFileSync(file, "utf8").split("\n")) {
      const at = line.indexOf("=");
      if (at > 0) fromFile[line.slice(0, at)] = line.slice(at + 1);
    }
  } catch {
    // the stack env file is optional when the variables are set directly
  }
  const get = (k: string): string => {
    const v = process.env[k] ?? fromFile[k];
    if (!v)
      throw new Error(`${k} is not set: run scripts/stream-sync-real/up.sh`);
    return v;
  };
  return {
    gatewayUrl: get("STREAM_SYNC_REAL_GATEWAY_URL"),
    storageUrl: get("STREAM_SYNC_REAL_STORAGE_URL"),
    pg: get("STREAM_SYNC_REAL_PG_NAME"),
  };
}

// The fixture connector's manifest document. PS-Lite resolves the run's digest
// through the shared resolver, from the bytes of this document.
const INTAKE_MANIFEST = JSON.stringify({
  connector_key: CONNECTOR,
  version: "1.0.0",
  streams: [{ name: STREAM, semantics: "mutable_state", primary_key: ["id"] }],
});
const INTAKE_DIGEST = `sha256:${documentDigest(INTAKE_MANIFEST)}`;

const stubs = new Map<string, string>();
const stub = (name: string, removedBy: string) => stubs.set(name, removedBy);

/**
 * STUB (run intake lane): one fixture connector run of one stream through the
 * writer in the process that owns it. The real path is the intake adapter
 * (`PUT begin / POST batches / POST end`); swap this function when it lands.
 */
async function fixtureRun(
  writer: StreamSyncWriter,
  runId: string,
  observedAt: number,
  records: readonly Record<string, unknown>[],
): Promise<void> {
  stub("run driver (writer called in-process)", "run intake lane (P6)");
  await writer.beginRun({
    runId,
    connector: CONNECTOR,
    userConnect: false,
    observedAt,
    checkpointUsed: null,
  });
  await writer.declareStream(runId, STREAM, SHAPE);
  for (const record of records) await writer.append(runId, STREAM, record);
  await writer.finishRun(runId, {
    checkpointCandidate: { cursor: runId } as JsonValue,
  });
}

async function main(): Promise<number> {
  const env = stackEnv();
  const psql = (sql: string) =>
    execFileSync(
      "docker",
      [
        "exec",
        "-i",
        env.pg,
        "psql",
        "-U",
        "gateway",
        "-d",
        "gateway",
        "-tAq",
        "-c",
        sql,
      ],
      { stdio: ["ignore", "pipe", "pipe"] },
    );
  // A fresh registry for every run (disposable dev database only).
  psql(
    "truncate data_points, data_point_versions, servers, builders, grants cascade;",
  );

  const root = await mkdtemp(join(tmpdir(), "stream-sync-real-"));
  const hops: Hop[] = [];
  const hop = (name: string, pass: boolean, detail: string) =>
    hops.push({ name, pass, detail });
  const owner = privateKeyToAccount(OWNER_KEY);
  const serverAccount = privateKeyToAccount(SERVER_KEY);
  let httpServer: Awaited<ReturnType<typeof listenHttpServer>> | undefined;
  let ctx: Awaited<ReturnType<typeof createServer>> | undefined;
  let lite: Awaited<ReturnType<typeof createPsLiteSyncManager>> | undefined;
  try {
    // ---- full server: normal bootstrap, real port, real gateway + storage
    process.env.PS_ACCESS_TOKEN = TOKEN;
    const config = ServerConfigSchema.parse({
      tunnel: { enabled: false },
      server: { port: SERVER_PORT },
      gateway: { url: env.gatewayUrl, chainId: CHAIN },
      storage: {
        backend: "vana",
        config: { vana: { apiUrl: env.storageUrl } },
      },
      sync: { enabled: true },
      streamSync: { write: true, read: true },
      logging: { level: "warn" },
    });
    ctx = await createServer(config, {
      serverDir: join(root, "server"),
      dataDir: join(root, "server", "data"),
      ownerSignature: OWNER_SIGNATURE,
      serverAccount: {
        address: serverAccount.address,
        publicKey: serverAccount.publicKey,
        signMessage: (message: string) =>
          serverAccount.signMessage({ message }),
        signTypedData: (params: unknown) =>
          serverAccount.signTypedData(
            params as Parameters<typeof serverAccount.signTypedData>[0],
          ),
      } as never,
    });
    httpServer = await listenHttpServer({
      fetch: ctx.app.fetch,
      port: SERVER_PORT,
      hostname: "127.0.0.1",
    });
    psql(
      `insert into servers (id, owner_address, server_address, public_key, server_url, signature, status)
       values ('0x${"5e".repeat(32)}', '${OWNER}', '${serverAccount.address}', '0x04', 'http://127.0.0.1', '0x', 'confirmed');`,
    );
    const full = ctx.streamSyncWriter;
    if (!full)
      throw new Error("full server has no stream-sync writer (flag off?)");

    // ---- PS-Lite as the mobile app runs it (sync manager + runtime)
    const liteConfig = ServerConfigSchema.parse({
      gateway: { url: env.gatewayUrl, chainId: CHAIN },
      storage: {
        backend: "vana",
        config: { vana: { apiUrl: env.storageUrl } },
      },
      sync: { enabled: true },
      streamSync: { write: true, read: true },
    });
    const stateStore = createMemoryPsLiteStateStore();
    const storage = createMemoryPsLiteStorage();
    const identity = await loadOrCreatePsLiteServerIdentity({
      store: stateStore,
      ownerSignature: OWNER_SIGNATURE,
    });
    const ownerSigner = createServerSigner(
      {
        address: owner.address,
        publicKey: owner.publicKey,
        signTypedData: (params) =>
          owner.signTypedData(
            params as Parameters<typeof owner.signTypedData>[0],
          ),
        signMessage: (message) => owner.signMessage({ message }),
      },
      { chainId: CHAIN, contracts: config.gateway.contracts },
    );
    lite = await createPsLiteSyncManager({
      config: liteConfig,
      stateStore,
      storage,
      ownerSignature: OWNER_SIGNATURE,
      serverAccount: identity.account,
      autoStartSync: false,
      gateway: createGatewayClient(env.gatewayUrl) as never,
      streamSyncFiles: () =>
        createIndexedDbStreamSyncFiles({
          dbName: "stream-sync-real-lite",
          factory: new IDBFactory(),
          keyRange: IDBKeyRange,
        }),
      ownerSyncSigner: {
        address: owner.address,
        signMessage: (message: string) => owner.signMessage({ message }),
        signAddData: ownerSigner.signAddData.bind(ownerSigner),
        signLineageAttestation:
          ownerSigner.signLineageAttestation.bind(ownerSigner),
      } as never,
      streamSyncRead: {},
      // The host's declaration table: only this digest resolves.
      streamSyncDeclarations: manifestArtifactResolver([INTAKE_MANIFEST]),
      streamSyncDeclaredStreams: manifestStreamLister([INTAKE_MANIFEST]),
    });
    const liteWriter = lite.streamSyncWriter;
    const liteIntake = lite.streamSyncIntake;
    if (!liteWriter || !liteIntake) {
      throw new Error("PS-Lite has no stream-sync writer or run intake");
    }
    const accessLog = createMemoryPsLiteAccessLogStore();
    const runtime = createPsLiteRuntime({
      storage,
      gateway: createGatewayClient(env.gatewayUrl) as never,
      accessLogReader: accessLog,
      accessLogWriter: accessLog,
      tokenStore: createMemoryPsLiteTokenStore(),
      saveConfig: async () => {},
      stateCapabilities: { config: "memory" },
      serverOwner: owner.address,
      scopeDeletions: lite.scopeDeletions,
      streamSyncRead: lite.streamSyncRead,
      auth: {
        authorizeOwner: async () => {},
        authorizeBuilderList: async () => {},
        authorizeBuilderRead: async () => ({
          builder: owner.address,
          grantId: "owner",
        }),
      } as never,
    } as never);
    runtime.activate();

    // ---- readers: full server over HTTP, PS-Lite through its runtime
    const parse = async (res: Response) => {
      if (res.status !== 200) return { status: res.status, records: [] };
      const json = (await res.json()) as {
        data?: { records?: unknown[] };
      };
      return { status: 200, records: json.data?.records ?? [] };
    };
    const readFull = async () =>
      parse(
        await fetch(`http://127.0.0.1:${SERVER_PORT}/v1/data/${SCOPE}`, {
          headers: { authorization: `Bearer ${TOKEN}` },
        }),
      );
    const readLite = async () =>
      parse(
        await runtime.fetch(new Request(`http://lite.local/v1/data/${SCOPE}`)),
      );
    const settle = async (which: "full" | "lite") => {
      for (let i = 0; i < 3; i++) {
        if (which === "full") await ctx!.syncManager!.trigger();
        else await lite!.syncManager.trigger();
      }
    };
    const check = async (
      name: string,
      which: "full" | "lite",
      want: readonly unknown[],
    ) => {
      await settle(which);
      const got = await (which === "full" ? readFull() : readLite());
      const ok =
        got.status === 200 &&
        JSON.stringify(sortedHashes(got.records)) ===
          JSON.stringify(sortedHashes(want));
      hop(
        name,
        ok,
        `status=${got.status} records=${got.records.length} hashes=${sortedHashes(got.records).join(",")}`,
      );
    };

    const T0 = Date.now();
    const first = { id: "real-1", value: "written by the full server" };
    const second = { id: "real-2", value: "written by PS-Lite" };

    // Forward: the full server publishes, both read.
    await full.refreshControls();
    await fixtureRun(full, "real-run-1", T0, [first]);
    const rep1 = await full.cycle();
    if (process.env.DEBUG_REAL) console.error(JSON.stringify(rep1));
    const r1 = rep1.runs.find((r) => r.runId === "real-run-1");
    hop(
      "write: full server publishes run 1",
      r1?.outcome?.kind === "checkpointed",
      `outcome=${r1?.outcome?.kind ?? "none"} expected=${hash(first)}`,
    );
    await check("read: full server (HTTP) sees the record", "full", [first]);
    await check("read: PS-Lite (app runtime) sees the record", "lite", [first]);

    // Reverse: PS-Lite publishes, both read.
    // The phone's path: PS-Lite's own run intake (begin, batch, end), then the
    // sync manager's publish pass. Only the fixture records are a stand-in.
    stub("connector fixture (synthetic records)", "a real connector run");
    await liteIntake.begin("real-run-2", {
      connector: CONNECTOR,
      artifactDigest: INTAKE_DIGEST,
      owner: { address: owner.address, leaseId: null },
      observedAt: T0 + 60_000,
    });
    await liteIntake.batch("real-run-2", {
      batch: 0,
      // A full-refresh run of a mutable stream is a snapshot: it carries the
      // record run 1 published too, or the stream would lose it.
      records: [first, second].map((data) => ({ stream: STREAM, data })),
    });
    await liteIntake.end("real-run-2", {
      outcome: "succeeded",
      coveredStreams: [STREAM],
      checkpointCandidate: { [STREAM]: "real-run-2" },
      lastBatch: 0,
    });
    const r2 = (await liteWriter.cycle()).runs.find(
      (r) => r.runId === "real-run-2",
    );
    hop(
      "write: PS-Lite publishes run 2 (through its run intake)",
      r2?.outcome?.kind === "checkpointed",
      `outcome=${r2?.outcome?.kind ?? "none"} expected=${hash(second)}`,
    );
    await check("read: full server (HTTP) sees both records", "full", [
      first,
      second,
    ]);
    await check("read: PS-Lite (app runtime) sees both records", "lite", [
      first,
      second,
    ]);

    // The registry is the real gateway: report what it holds (counts only).
    const versions = psql("select count(*) from data_point_versions;")
      .toString()
      .trim();
    hop(
      "registry: real gateway holds versions",
      Number(versions) > 0,
      `versions=${versions}`,
    );
  } finally {
    await lite?.syncManager.stop().catch(() => undefined);
    await ctx?.syncManager?.stop?.().catch(() => undefined);
    await new Promise<void>((resolve) =>
      httpServer ? httpServer.close(() => resolve()) : resolve(),
    );
    await rm(root, { recursive: true, force: true });
  }

  for (const h of hops) {
    process.stdout.write(
      `${h.pass ? "PASS" : "FAIL"} ${h.name} (${h.detail})\n`,
    );
  }
  process.stdout.write(`stubs: ${stubs.size}\n`);
  for (const [name, by] of stubs) process.stdout.write(`  ${name} -> ${by}\n`);
  return hops.some((h) => !h.pass) ? 1 : 0;
}

main().then(
  (code) => process.exit(code),
  (error) => {
    process.stderr.write(
      `real-mode crashed: ${error instanceof Error ? (error.stack ?? error.message) : String(error)}\n`,
    );
    process.exit(2);
  },
);
