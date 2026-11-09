/**
 * A connection delete on the Node server, through the real stream-sync writer
 * that `createServer` builds, with an in-memory registry injected in place of
 * the gateway client. Rows are written under a host declaration; the server
 * then restarts without it (the connector removed from config). The delete
 * must still answer, and tombstone the row.
 */
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import type * as StreamSyncModule from "@opendatalabs/personal-server-ts-core/stream-sync";
import {
  createMemoryStreamSyncBlobs,
  createMemoryStreamSyncRegistry,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import { createServer, type ServerContext } from "./bootstrap.js";

const captured = vi.hoisted(() => ({
  writers: [] as unknown[],
}));

vi.mock(
  "@opendatalabs/personal-server-ts-core/stream-sync",
  async (importOriginal) => {
    const actual = await importOriginal<typeof StreamSyncModule>();
    class CapturingWriter extends actual.StreamSyncWriter {
      constructor(
        options: ConstructorParameters<typeof actual.StreamSyncWriter>[0],
      ) {
        super(options);
        captured.writers.push(this);
      }
    }
    return { ...actual, StreamSyncWriter: CapturingWriter };
  },
);

const CONNECTOR = "acme";
const HIGH_S_SIGNATURE =
  "0x1f5c9b3bafc291e8ea7aa4e0c5700a109e68aa2431fdbea08b49f9bf91b5c7dbd555e6d21a3207991a060a0c6afd5992e4183bad14f5218f2fd6dc20cf515f6c1c";

type Writer = {
  refreshControls(): Promise<void>;
  beginRun(input: Record<string, unknown>): Promise<void>;
  declareStream(
    runId: string,
    stream: string,
    shape: Record<string, unknown>,
  ): Promise<void>;
  append(runId: string, stream: string, record: object): Promise<void>;
  finishRun(runId: string, input: Record<string, unknown>): Promise<void>;
  publishPending(): Promise<void>;
  requestConnectionDelete(connector: string): Promise<{ deleteId: string }>;
  status(): Promise<{
    pending: unknown[];
    finished: Array<{ streams: Record<string, { state: string }> }>;
  }>;
};

let tempDir: string;
let ctx: ServerContext | undefined;

beforeEach(async () => {
  captured.writers.length = 0;
  tempDir = await mkdtemp(join(tmpdir(), "bootstrap-durable-delete-"));
  vi.stubEnv("VANA_MASTER_KEY_SIGNATURE", HIGH_S_SIGNATURE);
  vi.stubEnv("VANA_OWNER_PRIVATE_KEY", "");
});

afterEach(async () => {
  await ctx?.cleanup();
  ctx = undefined;
  await rm(tempDir, { recursive: true, force: true });
  vi.unstubAllEnvs();
});

/** Boot on the same data directory; returns the writer `createServer` built. */
async function boot(
  registry: ReturnType<typeof createMemoryStreamSyncRegistry>,
  blobs: ReturnType<typeof createMemoryStreamSyncBlobs>,
  declaredStreams?: (connector: string) => readonly string[],
): Promise<Writer> {
  ctx = await createServer(
    ServerConfigSchema.parse({
      gateway: { url: "http://127.0.0.1:9" },
      tunnel: { enabled: false },
      sync: { enabled: true },
      logging: { level: "warn", pretty: false },
      streamSync: { write: true },
    }),
    {
      serverDir: tempDir,
      dataDir: join(tempDir, "data"),
      streamSyncRegistry: registry,
      streamSyncBlobs: blobs,
      // Unswitched: nothing to import, so a run is not held for an import.
      accountMode: { read: () => "unswitched" },
      ...(declaredStreams ? { declaredStreams } : {}),
    },
  );
  return captured.writers.at(-1) as Writer;
}

/**
 * Writes one row, restarts the server on the same data directory, and deletes
 * the connector. `beforeRestart` may alter the state on disk. Returns the
 * stream row's version before and after the delete.
 */
async function deleteAfterRestart(
  firstDeclared: ((connector: string) => readonly string[]) | undefined,
  beforeRestart: () => Promise<void>,
) {
  const registry = createMemoryStreamSyncRegistry();
  const blobs = createMemoryStreamSyncBlobs();

  const first = await boot(registry, blobs, firstDeclared);
  await first.refreshControls();
  await first.beginRun({
    runId: "run-1",
    connector: CONNECTOR,
    userConnect: false,
    observedAt: Date.now(),
    identity: "none",
    checkpointUsed: null,
  });
  await first.declareStream("run-1", "items", {
    primaryKey: ["id"],
    profile: { key: null, version: "1.0.0" },
  });
  await first.append("run-1", "items", { id: "a" });
  await first.finishRun("run-1", { checkpointCandidate: { cursor: "run-1" } });
  await first.publishPending();

  const rows = await registry.listStreamRows(CONNECTOR);
  expect(rows.length).toBeGreaterThan(0);
  const scope = rows[0]!.scope;
  const before = (await registry.read(scope)) as { version: number };

  await ctx!.cleanup();
  ctx = undefined;
  await beforeRestart();
  // A restart with the connector removed from config: no host name, no manifest.
  const second = await boot(registry, blobs);
  await expect(
    second.requestConnectionDelete(CONNECTOR),
  ).resolves.toMatchObject({ deleteId: expect.any(String) });
  await second.publishPending();

  const after = (await registry.read(scope)) as { version: number };
  return { before: before.version, after: after.version };
}

it("rows written under a host declaration survive a restart without it: the delete answers and tombstones the row", async () => {
  const { before, after } = await deleteAfterRestart(
    (connector) => (connector === CONNECTOR ? ["items"] : []),
    async () => {},
  );
  expect(after).toBeGreaterThan(before);
});

it("pre-change rows: written before any name was recorded, connector absent from config; the delete answers 202 and tombstones the row (mutant: PRECHANGE_ROWS_REFUSED)", async () => {
  const { before, after } = await deleteAfterRestart(undefined, async () => {});
  expect(after).toBeGreaterThan(before);
});

it("rows appended under a host declaration and never published: after a restart without it, the delete answers 202 and no later publish brings them back", async () => {
  const registry = createMemoryStreamSyncRegistry();
  const blobs = createMemoryStreamSyncBlobs();

  // The run appends, then stops before finishRun and before any publish.
  const first = await boot(registry, blobs, (connector) =>
    connector === CONNECTOR ? ["items"] : [],
  );
  await first.refreshControls();
  await first.beginRun({
    runId: "run-1",
    connector: CONNECTOR,
    userConnect: false,
    observedAt: Date.now(),
    identity: "none",
    checkpointUsed: null,
  });
  await first.declareStream("run-1", "items", {
    primaryKey: ["id"],
    profile: { key: null, version: "1.0.0" },
  });
  await first.append("run-1", "items", { id: "a" });

  // A restart on the same data directory, with the connector absent from config.
  await ctx!.cleanup();
  ctx = undefined;
  const second = await boot(registry, blobs);
  await expect(
    second.requestConnectionDelete(CONNECTOR),
  ).resolves.toMatchObject({ deleteId: expect.any(String) });
  await second.publishPending();
  await second.publishPending();

  const { pending, finished } = await second.status();
  expect(pending).toEqual([]);
  expect(
    finished
      .flatMap((run) => Object.values(run.streams))
      .filter((s) => s.state === "committed"),
  ).toEqual([]);
});

it("rows appended under a host declaration, run still open when the delete lands: a later finish is refused and nothing publishes (mutant: UNFINISHED_RUN_STREAMS_IGNORED)", async () => {
  const registry = createMemoryStreamSyncRegistry();
  const blobs = createMemoryStreamSyncBlobs();
  const first = await boot(registry, blobs, (connector) =>
    connector === CONNECTOR ? ["items"] : [],
  );
  await first.refreshControls();
  await first.beginRun({
    runId: "run-1",
    connector: CONNECTOR,
    userConnect: false,
    observedAt: Date.now(),
    identity: "none",
    checkpointUsed: null,
  });
  await first.declareStream("run-1", "items", {
    primaryKey: ["id"],
    profile: { key: null, version: "1.0.0" },
  });
  await first.append("run-1", "items", { id: "a" });

  // The same process deletes while run-1 is still collecting.
  await expect(first.requestConnectionDelete(CONNECTOR)).resolves.toMatchObject(
    { deleteId: expect.any(String) },
  );
  await expect(
    first.finishRun("run-1", { checkpointCandidate: { cursor: "run-1" } }),
  ).rejects.toThrow();
  await first.publishPending();
  await first.publishPending();

  const { pending, finished } = await first.status();
  expect(pending).toEqual([]);
  expect(
    finished
      .flatMap((run) => Object.values(run.streams))
      .filter((s) => s.state === "committed"),
  ).toEqual([]);
});
