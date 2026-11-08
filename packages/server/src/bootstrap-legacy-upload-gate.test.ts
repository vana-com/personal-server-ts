/**
 * Node host wiring for item "legacy is read-only history after the switch":
 * the sync manager must see the stream-sync switch live, so a switch-off
 * mid-run resumes legacy uploads on the next cycle. The manager's behavior
 * for each switch state is proven in core
 * (`sync-manager.legacy-upload-gate.test.ts`); this proves the host hands it a
 * live switch bound to the running config.
 */

import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import * as sync from "@opendatalabs/personal-server-ts-core/sync";
import { createServer } from "./bootstrap.js";

vi.mock(
  "@opendatalabs/personal-server-ts-core/sync",
  async (importOriginal) => {
    const actual = await importOriginal<typeof sync>();
    return { ...actual, createSyncManager: vi.fn(actual.createSyncManager) };
  },
);

const MASTER_KEY_SIGNATURE =
  "0xedbb7743cce459345238442dcfb291f234a321d253485eaa58251aa0f28ea8f1410ab988bae2657b689cd24417b41e315efc22ba333024f4a6269c424ded8d361b";

describe("createServer: legacy upload gate follows the stream-sync switch", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "bootstrap-upload-gate-"));
    vi.stubEnv("VANA_MASTER_KEY_SIGNATURE", MASTER_KEY_SIGNATURE);
    vi.mocked(sync.createSyncManager).mockClear();
  });

  afterEach(async () => {
    vi.unstubAllEnvs();
    await rm(tempDir, { recursive: true, force: true });
  });

  async function open(write: boolean) {
    const config = ServerConfigSchema.parse({
      sync: { enabled: true },
      tunnel: { enabled: false },
      streamSync: { read: true, write },
    });
    const ctx = await createServer(config, {
      serverDir: tempDir,
      dataDir: join(tempDir, "data"),
    });
    const options = vi.mocked(sync.createSyncManager).mock.calls.at(-1)![2];
    return { ctx, config, options };
  }

  it("writer on: the manager gets a publisher and a switch that reads the config live", async () => {
    const { ctx, config, options } = await open(true);
    try {
      expect(options?.streamSync).not.toBeNull();
      expect(options?.streamSync?.write).toBe(true);
      config.streamSync.write = false;
      expect(options?.streamSync?.write).toBe(false);
      config.streamSync.write = true;
      expect(options?.streamSync?.write).toBe(true);
    } finally {
      await ctx.cleanup();
    }
  });

  it("writer off: the manager gets no stream-sync option, so legacy uploads run unchanged", async () => {
    const { ctx, options } = await open(false);
    try {
      expect(options?.streamSync ?? null).toBeNull();
    } finally {
      await ctx.cleanup();
    }
  });
});
