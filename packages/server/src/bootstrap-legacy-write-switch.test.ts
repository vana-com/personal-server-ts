/**
 * The Node server decides whether to refuse legacy writes from the Account
 * switch (`streamSync.write`) alone. `refuseLegacyWrites` is not a second
 * condition, and the server's one account storage mode feeds the gate.
 */

import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { createServer } from "./bootstrap.js";

const MASTER_KEY_SIGNATURE =
  "0xedbb7743cce459345238442dcfb291f234a321d253485eaa58251aa0f28ea8f1410ab988bae2657b689cd24417b41e315efc22ba333024f4a6269c424ded8d361b";
const ACCESS_TOKEN = "legacy-write-switch-test-token";

describe("createServer legacy write switch", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "bootstrap-write-switch-test-"));
    vi.stubEnv("VANA_MASTER_KEY_SIGNATURE", MASTER_KEY_SIGNATURE);
    vi.stubEnv("PS_ACCESS_TOKEN", ACCESS_TOKEN);
  });

  afterEach(async () => {
    vi.unstubAllEnvs();
    await rm(tempDir, { recursive: true, force: true });
  });

  async function post(streamSync: Record<string, unknown>) {
    const ctx = await createServer(
      ServerConfigSchema.parse({
        sync: { enabled: false },
        tunnel: { enabled: false },
        streamSync,
      }),
      { serverDir: tempDir, dataDir: join(tempDir, "data") },
    );
    try {
      return await ctx.app.request("/v1/data/chatgpt.conversations", {
        method: "POST",
        headers: {
          authorization: `Bearer ${ACCESS_TOKEN}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ records: [] }),
      });
    } finally {
      await ctx.cleanup();
    }
  }

  // SWITCH_REQUIRES_SECOND_FLAG
  it.each([
    ["the refuse flag absent", { write: true }],
    ["the refuse flag false", { write: true, refuseLegacyWrites: false }],
  ])(
    "refuses a legacy write on a switched account with %s",
    async (_n, flags) => {
      expect((await post(flags)).status).toBe(426);
    },
  );

  it("accepts a legacy write when the account is not switched, whatever the refuse flag says", async () => {
    expect(
      (await post({ write: false, refuseLegacyWrites: true })).status,
    ).toBe(201);
  });
});
