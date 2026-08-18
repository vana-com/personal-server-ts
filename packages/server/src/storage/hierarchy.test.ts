import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, readFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  writeDataFile,
  readDataFile,
  readScopeBlockManifest,
  readScopeBlocks,
  listVersions,
  deleteDataFile,
  deleteAllForScope,
  writeBlockManifest,
} from "./hierarchy.js";
import { createDataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import type { HierarchyManagerOptions } from "@opendatalabs/personal-server-ts-core/storage/hierarchy";

describe("HierarchyManager", () => {
  let dataDir: string;
  let options: HierarchyManagerOptions;

  beforeEach(async () => {
    dataDir = await mkdtemp(join(tmpdir(), "hierarchy-test-"));
    options = { dataDir };
  });

  afterEach(async () => {
    await rm(dataDir, { recursive: true, force: true });
  });

  const scope = "instagram.profile";
  const collectedAt = "2026-01-21T10:00:00Z";
  const data = { username: "testuser", followers: 100 };

  function makeEnvelope(
    s = scope,
    ts = collectedAt,
    d: Record<string, unknown> = data,
  ) {
    return createDataFileEnvelope(s, ts, d);
  }

  describe("writeDataFile", () => {
    it("creates file at expected path", async () => {
      const result = await writeDataFile(options, makeEnvelope());
      const content = await readFile(result.path, "utf-8");
      expect(content).toBeTruthy();
    });

    it("written file is valid JSON with correct envelope fields", async () => {
      const envelope = makeEnvelope();
      const result = await writeDataFile(options, envelope);
      const content = JSON.parse(await readFile(result.path, "utf-8"));
      expect(content.version).toBe("1.0");
      expect(content.scope).toBe(scope);
      expect(content.collectedAt).toBe(collectedAt);
      expect(content.data).toEqual(data);
    });

    it("creates intermediate directories", async () => {
      const envelope = makeEnvelope("chatgpt.conversations.shared");
      const result = await writeDataFile(options, envelope);
      expect(result.path).toContain("chatgpt/conversations/shared");
      const content = await readFile(result.path, "utf-8");
      expect(content).toBeTruthy();
    });

    it("returns correct relativePath", async () => {
      const result = await writeDataFile(options, makeEnvelope());
      expect(result.relativePath).toBe(
        "instagram/profile/2026-01-21T10-00-00Z.json",
      );
    });

    it("returns sizeBytes > 0", async () => {
      const result = await writeDataFile(options, makeEnvelope());
      expect(result.sizeBytes).toBeGreaterThan(0);
    });

    it("atomic write: file content is complete (no partial writes)", async () => {
      const largeData: Record<string, unknown> = {};
      for (let i = 0; i < 1000; i++) {
        largeData[`key_${i}`] = `value_${i}_${"x".repeat(100)}`;
      }
      const envelope = makeEnvelope(scope, collectedAt, largeData);
      const result = await writeDataFile(options, envelope);
      const content = await readFile(result.path, "utf-8");
      const parsed = JSON.parse(content);
      expect(parsed.version).toBe("1.0");
      expect(parsed.data).toEqual(largeData);
    });
  });

  describe("readDataFile", () => {
    it("returns the envelope written by writeDataFile", async () => {
      const envelope = makeEnvelope();
      await writeDataFile(options, envelope);
      const read = await readDataFile(options, scope, collectedAt);
      expect(read).toEqual(envelope);
    });
  });

  describe("readScopeBlocks", () => {
    it("pages through a single oversized block with intra-block cursors", async () => {
      const largeValue = "0123456789".repeat(600);
      const sizeBytes = new TextEncoder().encode(largeValue).byteLength;
      await writeBlockManifest(
        options,
        scope,
        collectedAt,
        {
          version: 1,
          scope,
          collectedAt,
          contentKind: "text",
          blocks: [
            {
              id: "block-000001",
              path: "$.data",
              mediaType: "text/plain",
              sizeBytes,
            },
          ],
          warnings: [],
        },
        [
          {
            id: "block-000001",
            path: "$.data",
            mediaType: "text/plain",
            value: largeValue,
            sizeBytes,
          },
        ],
      );

      const firstPage = await readScopeBlocks(options, scope, collectedAt, {
        maxBytes: 1024,
      });
      expect(firstPage.blocks).toHaveLength(1);
      expect(firstPage.blocks[0]?.value).toBe(largeValue.slice(0, 1024));
      expect(firstPage.blocks[0]?.truncated).toBe(true);
      expect(firstPage.nextCursor).toBeTruthy();

      const secondPage = await readScopeBlocks(options, scope, collectedAt, {
        cursor: firstPage.nextCursor,
        maxBytes: 1024,
      });
      expect(secondPage.blocks).toHaveLength(1);
      expect(secondPage.blocks[0]?.value).toBe(largeValue.slice(1024, 2048));
      expect(secondPage.blocks[0]?.truncated).toBe(true);
      expect(secondPage.nextCursor).toBeTruthy();
    });
  });

  describe("block-addressed reads", () => {
    async function writeThreeBlocks() {
      const blocks = ["alpha", "beta", "gamma"].map((word, index) => ({
        id: `block-00000${index + 1}`,
        path: `$.items[${index}]`,
        mediaType: "text/plain",
        value: word.repeat(100),
        sizeBytes: new TextEncoder().encode(word.repeat(100)).byteLength,
      }));
      await writeBlockManifest(
        options,
        scope,
        collectedAt,
        {
          version: 1,
          scope,
          collectedAt,
          contentKind: "json",
          blocks: blocks.map(({ value: _value, ...ref }) => ref),
          warnings: [],
        },
        blocks,
      );
      return blocks;
    }

    it("returns exactly the requested blocks, in the requested order", async () => {
      const blocks = await writeThreeBlocks();

      const page = await readScopeBlocks(options, scope, collectedAt, {
        maxBytes: 64 * 1024,
        blockIds: ["block-000003", "block-000001"],
      });

      expect(page.blocks.map((block) => block.id)).toEqual([
        "block-000003",
        "block-000001",
      ]);
      expect(page.blocks[0]?.value).toBe(blocks[2].value);
      expect(page.nextCursor).toBeUndefined();
    });

    it("honours maxBytes and reports the ids it could not return", async () => {
      await writeThreeBlocks();

      const page = await readScopeBlocks(options, scope, collectedAt, {
        maxBytes: 600,
        blockIds: ["block-000001", "block-000002", "block-000003"],
      });

      expect(page.blocks.map((block) => block.id)).toEqual(["block-000001"]);
      expect(page.warnings).toContainEqual(
        expect.objectContaining({ code: "block_selection_truncated" }),
      );
    });

    it("warns instead of throwing for ids that are not in the scope", async () => {
      await writeThreeBlocks();

      const page = await readScopeBlocks(options, scope, collectedAt, {
        maxBytes: 64 * 1024,
        blockIds: ["block-000001", "block-does-not-exist"],
      });

      expect(page.blocks.map((block) => block.id)).toEqual(["block-000001"]);
      expect(page.warnings).toContainEqual(
        expect.objectContaining({ code: "block_not_found" }),
      );
    });
  });

  describe("readScopeBlockManifest", () => {
    it("returns the manifest as a table of contents", async () => {
      await writeBlockManifest(
        options,
        scope,
        collectedAt,
        {
          version: 1,
          scope,
          collectedAt,
          contentKind: "json",
          blocks: [
            {
              id: "block-000001",
              path: "$.items[0]",
              mediaType: "application/json",
              sizeBytes: 12,
              itemCount: 1,
            },
          ],
          warnings: [],
        },
        [
          {
            id: "block-000001",
            path: "$.items[0]",
            mediaType: "application/json",
            value: { ok: true },
            sizeBytes: 12,
          },
        ],
      );

      const manifest = await readScopeBlockManifest(
        options,
        scope,
        collectedAt,
      );
      expect(manifest?.blocks).toEqual([
        expect.objectContaining({ id: "block-000001", itemCount: 1 }),
      ]);
    });

    it("returns null when the scope has no manifest", async () => {
      await expect(
        readScopeBlockManifest(options, scope, collectedAt),
      ).resolves.toBeNull();
    });
  });

  describe("listVersions", () => {
    it("returns filenames in reverse chronological order", async () => {
      const ts1 = "2026-01-21T08:00:00Z";
      const ts2 = "2026-01-21T10:00:00Z";
      const ts3 = "2026-01-21T12:00:00Z";

      await writeDataFile(options, makeEnvelope(scope, ts1));
      await writeDataFile(options, makeEnvelope(scope, ts2));
      await writeDataFile(options, makeEnvelope(scope, ts3));

      const versions = await listVersions(options, scope);
      expect(versions).toEqual([ts3, ts2, ts1]);
    });

    it("returns empty array for nonexistent scope", async () => {
      const versions = await listVersions(options, "nonexistent.scope");
      expect(versions).toEqual([]);
    });
  });

  describe("deleteDataFile", () => {
    it("removes file; subsequent readDataFile throws ENOENT", async () => {
      await writeDataFile(options, makeEnvelope());
      await deleteDataFile(options, scope, collectedAt);
      await expect(readDataFile(options, scope, collectedAt)).rejects.toThrow(
        /ENOENT/,
      );
    });

    it("removes sidecars for that version", async () => {
      await writeDataFile(options, makeEnvelope());
      await writeBlockManifest(
        options,
        scope,
        collectedAt,
        {
          version: 1,
          scope,
          collectedAt,
          contentKind: "json",
          blocks: [
            {
              id: "block-000001",
              path: "$",
              mediaType: "application/json",
              sizeBytes: 12,
            },
          ],
          warnings: [],
        },
        [
          {
            id: "block-000001",
            path: "$",
            mediaType: "application/json",
            value: { ok: true },
            sizeBytes: 12,
          },
        ],
      );

      await deleteDataFile(options, scope, collectedAt);

      await expect(
        readScopeBlocks(options, scope, collectedAt, { maxBytes: 1024 }),
      ).rejects.toMatchObject({ code: "block_manifest_not_found" });
    });
  });

  describe("deleteAllForScope", () => {
    it("deletes scope with 2 versions — files and directory removed", async () => {
      const ts1 = "2026-01-21T08:00:00Z";
      const ts2 = "2026-01-21T10:00:00Z";
      await writeDataFile(options, makeEnvelope(scope, ts1));
      await writeDataFile(options, makeEnvelope(scope, ts2));

      await deleteAllForScope(options, scope);

      // Scope directory should be gone
      const { stat } = await import("node:fs/promises");
      const { buildScopeDir } =
        await import("@opendatalabs/personal-server-ts-core/storage/hierarchy");
      const scopeDir = buildScopeDir(dataDir, scope);
      await expect(stat(scopeDir)).rejects.toThrow(/ENOENT/);
    });

    it("after delete, listVersions returns empty array", async () => {
      await writeDataFile(options, makeEnvelope(scope, "2026-01-21T08:00:00Z"));
      await writeDataFile(options, makeEnvelope(scope, "2026-01-21T10:00:00Z"));
      await writeBlockManifest(
        options,
        scope,
        "2026-01-21T10:00:00Z",
        {
          version: 1,
          scope,
          collectedAt: "2026-01-21T10:00:00Z",
          contentKind: "json",
          blocks: [],
          warnings: [],
        },
        [],
      );

      await deleteAllForScope(options, scope);

      const versions = await listVersions(options, scope);
      expect(versions).toEqual([]);
      await expect(
        readScopeBlocks(options, scope, "2026-01-21T10:00:00Z", {
          maxBytes: 1024,
        }),
      ).rejects.toMatchObject({ code: "block_manifest_not_found" });
    });

    it("deleting nonexistent scope does not throw (idempotent)", async () => {
      await expect(
        deleteAllForScope(options, "nonexistent.scope"),
      ).resolves.toBeUndefined();
    });

    it("deletes scope with nested subcategory — entire subtree removed", async () => {
      const nestedScope = "chatgpt.conversations.shared";
      await writeDataFile(
        options,
        makeEnvelope(nestedScope, "2026-01-21T08:00:00Z"),
      );
      await writeDataFile(
        options,
        makeEnvelope(nestedScope, "2026-01-21T10:00:00Z"),
      );

      await deleteAllForScope(options, nestedScope);

      const versions = await listVersions(options, nestedScope);
      expect(versions).toEqual([]);
    });
  });
});
