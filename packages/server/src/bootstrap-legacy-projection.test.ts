/**
 * The Node server serves projected legacy scope bodies to readers while
 * sync keeps moving the stored PDPP records unchanged.
 */

import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import type { DataStoragePort } from "@opendatalabs/personal-server-ts-core/ports";
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
const ACCESS_TOKEN = "legacy-projection-test-token";
const conversations = {
  records: [
    {
      id: "conv-1",
      title: "Trip plan",
      create_time: "2026-09-01T10:00:00Z",
      update_time: "2026-09-01T10:05:00Z",
      current_node: null,
      message_count_on_current_branch: 0,
    },
  ],
};

describe("createServer legacy projection wiring", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "bootstrap-projection-test-"));
    vi.stubEnv("VANA_MASTER_KEY_SIGNATURE", MASTER_KEY_SIGNATURE);
    vi.stubEnv("PS_ACCESS_TOKEN", ACCESS_TOKEN);
  });

  afterEach(async () => {
    vi.unstubAllEnvs();
    await rm(tempDir, { recursive: true, force: true });
  });

  it("serves the projection over HTTP and gives sync the raw stored records", async () => {
    const ctx = await createServer(
      ServerConfigSchema.parse({
        sync: { enabled: true },
        tunnel: { enabled: false },
      }),
      { serverDir: tempDir, dataDir: join(tempDir, "data") },
    );
    try {
      const write = await ctx.app.request("/v1/data/chatgpt.conversations", {
        method: "POST",
        headers: {
          authorization: `Bearer ${ACCESS_TOKEN}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(conversations),
      });
      expect(write.status).toBe(201);

      const read = await ctx.app.request("/v1/data/chatgpt.conversations", {
        headers: { authorization: `Bearer ${ACCESS_TOKEN}` },
      });
      expect(read.status).toBe(200);
      expect(((await read.json()) as { data: unknown }).data).toMatchObject({
        conversations: [{ id: "conv-1", title: "Trip plan", messages: [] }],
        total: 1,
      });

      const [uploadDeps, downloadDeps] = vi.mocked(sync.createSyncManager).mock
        .calls[0] as unknown as [
        { storage: DataStoragePort },
        { storage: DataStoragePort },
      ];
      for (const { storage } of [uploadDeps, downloadDeps]) {
        // Only the served port carries the stored-view escape hatch.
        expect(storage.readStoredEnvelope).toBeUndefined();
        const entry = storage.findEntry({ scope: "chatgpt.conversations" })!;
        expect(
          (
            await storage.readEnvelope(
              "chatgpt.conversations",
              entry.collectedAt,
            )
          ).data,
        ).toEqual({
          ...conversations,
          $firstAdded: expect.objectContaining({ version: 1 }),
        });
      }
    } finally {
      await ctx.cleanup();
    }
  });
});
