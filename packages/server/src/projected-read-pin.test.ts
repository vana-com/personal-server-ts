/**
 * A non-owner read of a projected legacy scope is one read contract: every
 * stored input is pinned to its index row and read under an input budget,
 * and the projected output is built under an output cap. Streams, MCP
 * blocks and MCP tables of contents all use it.
 *
 * Real Node storage and the real MCP read client. The probes are Codex's
 * round-2 review probes for PR #458 (~/.tmp/ps458-r2-review/probe.mts).
 */
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { DataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import type { DataStoragePort } from "@opendatalabs/personal-server-ts-core/ports";
import type { IndexManager } from "@opendatalabs/personal-server-ts-core/storage/index";
import { withLegacyProjection } from "@opendatalabs/personal-server-ts-core/storage/legacy-projection";
import { granteeReadPort } from "@opendatalabs/personal-server-ts-core/storage/disclosure-policy";
import { createMcpDataReadClient } from "@opendatalabs/personal-server-ts-core/mcp";
import { initializeDatabase } from "./storage/index-schema.js";
import { createIndexManager } from "./storage/index-manager.js";
import { createNodeDataStorage } from "./storage/node-data-storage.js";

const AT = "2026-10-01T00:00:00.000Z";
const SCOPE = "chatgpt.conversations";

function envelope(scope: string, data: Record<string, unknown>) {
  return { version: "1.0", scope, collectedAt: AT, data } as DataFileEnvelope;
}
const pretty = (value: unknown) => Buffer.from(JSON.stringify(value, null, 2));
const conversation = (title: string) => ({
  id: "c",
  title,
  create_time: "2026-09-01T10:00:00Z",
  update_time: "2026-09-01T10:05:00Z",
  current_node: null,
  message_count_on_current_branch: 0,
});

let dataDir: string;
let indexManager: IndexManager;
let storage: DataStoragePort;

beforeEach(async () => {
  dataDir = await mkdtemp(join(tmpdir(), "projected-read-pin-"));
  indexManager = createIndexManager(initializeDatabase(":memory:"));
  storage = createNodeDataStorage({
    indexManager,
    hierarchyOptions: { dataDir },
  });
});

afterEach(async () => {
  indexManager.close();
  await rm(dataDir, { recursive: true, force: true });
});

async function publish(value: DataFileEnvelope) {
  const written = await storage.writeEnvelope(value);
  const row = await storage.insertEntry({
    fileId: null,
    path: written.relativePath,
    scope: value.scope,
    collectedAt: value.collectedAt,
    sizeBytes: written.sizeBytes,
  });
  return { written, row };
}

/** A grantee's MCP read client over a fresh served port (a cold cache). */
function mcpClient() {
  return createMcpDataReadClient({
    serverOrigin: "https://personal-server.test",
    granteeAccount: {
      address: "0x1111111111111111111111111111111111111111",
      publicKey: "0x04deadbeef",
      signTypedData: async () => `0x${"11".repeat(65)}`,
      signMessage: async () => `0x${"11".repeat(65)}`,
    },
    dataApiDeps: {
      storage: withLegacyProjection(storage),
      auth: { authorizeBuilderRead: async () => ({ grantId: "g" }) },
      accessLogWriter: { write: async () => {} },
    },
  } as unknown as Parameters<typeof createMcpDataReadClient>[0]);
}

describe("a grantee's projected read", () => {
  it("caps the projected output while building it, not after", async () => {
    // 128 conversations with one key all join the same 64 KiB message.
    const repeated = {
      ...conversation("same key"),
      current_node: "m",
      message_count_on_current_branch: 1,
    };
    const { row } = await publish(
      envelope(SCOPE, {
        records: Array.from({ length: 128 }, () => ({ ...repeated })),
      }),
    );
    await publish(
      envelope("chatgpt.messages", {
        records: [
          {
            id: "m",
            conversation_id: "c",
            parent_id: null,
            role: "user",
            content: "z".repeat(65_536),
            content_type: "text",
            create_time: "2026-09-01T10:00:00Z",
            on_current_branch: true,
          },
        ],
      }),
    );
    const cap = 256 * 1024;
    let largest = 0;
    const encode = TextEncoder.prototype.encode;
    const stringify = JSON.stringify;
    TextEncoder.prototype.encode = function (input?: string) {
      largest = Math.max(largest, input?.length ?? 0);
      return encode.call(this, input);
    };
    JSON.stringify = ((...args: Parameters<typeof stringify>) => {
      const text = stringify(...args);
      largest = Math.max(largest, text?.length ?? 0);
      return text;
    }) as typeof JSON.stringify;
    try {
      const port = granteeReadPort(withLegacyProjection(storage));
      await expect(
        port.readEnvelopeStream!(port.pinVersion(row), { maxBytes: cap }),
      ).rejects.toMatchObject({ code: "too_large" });
    } finally {
      TextEncoder.prototype.encode = encode;
      JSON.stringify = stringify;
    }
    // Nothing larger than the cap was serialized on the way to refusing.
    expect(largest).toBeLessThanOrEqual(cap);
  });

  it("refuses MCP blocks of a version whose bytes changed under its row", async () => {
    const { written } = await publish(
      envelope(SCOPE, { records: [conversation("AUTHORIZED_A")] }),
    );
    await writeFile(
      written.path,
      pretty(envelope(SCOPE, { records: [conversation("REPLACED_B")] })),
    );

    const read = await mcpClient()
      .readScopeBlocks({ scope: SCOPE, grantId: "g", maxBytes: 100_000 })
      .then(
        (result) => JSON.stringify(result),
        (error: unknown) => JSON.stringify(error),
      );

    expect(read).not.toContain("REPLACED_B");
    expect(read).toContain("generation_mismatch");
  });

  it("refuses an MCP cursor of one version once the bytes are another's", async () => {
    const { written } = await publish(
      envelope(SCOPE, {
        records: [conversation("AUTHORIZED_A".repeat(2000))],
      }),
    );
    const first = await mcpClient().readScopeBlocks({
      scope: SCOPE,
      grantId: "g",
      maxBytes: 512,
    });
    expect(first.nextCursor).toBeDefined();
    await writeFile(
      written.path,
      pretty(
        envelope(SCOPE, { records: [conversation("REPLACED_B".repeat(2000))] }),
      ),
    );

    const second = await mcpClient()
      .readScopeBlocks({
        scope: SCOPE,
        grantId: "g",
        maxBytes: 512,
        cursor: first.nextCursor,
      })
      .then(
        (result) => JSON.stringify(result),
        (error: unknown) => JSON.stringify(error),
      );

    expect(second).not.toContain("REPLACED_B");
    expect(second).toContain("generation_mismatch");
  });

  it("refuses an MCP table of contents built from changed bytes", async () => {
    const { written } = await publish(
      envelope(SCOPE, { records: [conversation("AUTHORIZED_A")] }),
    );
    await writeFile(
      written.path,
      pretty(envelope(SCOPE, { records: [conversation("REPLACED_B")] })),
    );

    const manifest = await mcpClient()
      .readBlockManifest({ scope: SCOPE, grantId: "g" })
      .then(
        (result) => JSON.stringify(result),
        (error: unknown) => JSON.stringify(error),
      );

    expect(manifest).toContain("generation_mismatch");
  });

  it("still serves blocks of an unchanged projected version", async () => {
    await publish(envelope(SCOPE, { records: [conversation("AUTHORIZED_A")] }));

    const result = await mcpClient().readScopeBlocks({
      scope: SCOPE,
      grantId: "g",
      maxBytes: 100_000,
    });

    expect(result.status).toBe(200);
    expect(JSON.stringify(result)).toContain("AUTHORIZED_A");
  });
});
