/**
 * The host's `declaredStreams` option reaches the stream-sync writer through
 * `createServer`. The writer is wrapped, not replaced, so the boot is
 * otherwise unchanged; the test reads the hook the boot handed to it.
 */
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import type * as StreamSyncModule from "@opendatalabs/personal-server-ts-core/stream-sync";
import { createServer, type ServerContext } from "./bootstrap.js";

const captured = vi.hoisted(() => ({
  options: [] as Array<{
    declaredStreams: (connector: string) => readonly string[];
  }>,
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
        captured.options.push(options as never);
      }
    }
    return { ...actual, StreamSyncWriter: CapturingWriter };
  },
);

const UNINSTALLED = "uninstalled-connector";
const HIGH_S_SIGNATURE =
  "0x1f5c9b3bafc291e8ea7aa4e0c5700a109e68aa2431fdbea08b49f9bf91b5c7dbd555e6d21a3207991a060a0c6afd5992e4183bad14f5218f2fd6dc20cf515f6c1c";

let tempDir: string;
let ctx: ServerContext | undefined;

beforeEach(async () => {
  captured.options.length = 0;
  tempDir = await mkdtemp(join(tmpdir(), "bootstrap-declared-streams-"));
  vi.stubEnv("VANA_MASTER_KEY_SIGNATURE", HIGH_S_SIGNATURE);
  vi.stubEnv("VANA_OWNER_PRIVATE_KEY", "");
});

afterEach(async () => {
  await ctx?.cleanup();
  ctx = undefined;
  await rm(tempDir, { recursive: true, force: true });
  vi.unstubAllEnvs();
});

async function bootWriter(options?: {
  declaredStreams?: (connector: string) => readonly string[];
}) {
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
      ...(options ?? {}),
    },
  );
  return captured.options.at(-1)!.declaredStreams;
}

it("the host's declaredStreams option names an uninstalled connector's streams to the writer (mutant: BOOTSTRAP_OPTION_DROPPED)", async () => {
  const hook = await bootWriter({
    declaredStreams: (connector) =>
      connector === UNINSTALLED ? ["items"] : [],
  });
  expect(hook(UNINSTALLED)).toEqual(["items"]);
});

it("without the option the writer's hook names nothing for an uninstalled connector", async () => {
  const hook = await bootWriter();
  expect(hook(UNINSTALLED)).toEqual([]);
});
