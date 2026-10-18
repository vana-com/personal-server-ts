import { mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { createMcpConnection } from "@opendatalabs/personal-server-ts-core/mcp";
import { openLocalMcpState } from "./local-state.js";

const directories: string[] = [];

async function tempDir(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "mcp-local-state-"));
  directories.push(directory);
  return directory;
}

afterEach(async () => {
  await Promise.all(
    directories.splice(0).map((d) => rm(d, { recursive: true, force: true })),
  );
});

describe("openLocalMcpState", () => {
  it("keeps MCP connections and authorizations across a restart", async () => {
    const directory = await tempDir();
    const path = join(directory, "mcp-state.json");
    const masterKey = randomBytes(32);

    const first = await openLocalMcpState({ path, masterKey });
    const created = await createMcpConnection(
      { displayName: "Claude" },
      { store: first.connections, publicOrigin: "https://ps.example" },
    );
    await first.connections.update(created.connectionId, {
      status: "approved",
    });
    await first.authorizations.create({
      id: "auth-1",
      clientId: "client-1",
      redirectUri: "https://claude.ai/api/mcp/auth_callback",
      codeChallenge: "challenge",
      codeChallengeMethod: "S256",
      connectionId: created.connectionId,
      granteeAddress: "0x2222222222222222222222222222222222222222",
      status: "pending",
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    });

    // A restart opens the same file with the same owner key.
    const second = await openLocalMcpState({ path, masterKey });
    const connection = await second.connections.getById(created.connectionId);
    expect(connection?.status).toBe("approved");
    expect(await second.authorizations.getById("auth-1")).not.toBeNull();
  });

  it("starts empty and moves the file aside when it no longer decrypts", async () => {
    const directory = await tempDir();
    const path = join(directory, "mcp-state.json");

    const first = await openLocalMcpState({ path, masterKey: randomBytes(32) });
    await createMcpConnection(
      { displayName: "Claude" },
      { store: first.connections, publicOrigin: "https://ps.example" },
    );

    const warnings: unknown[] = [];
    const other = await openLocalMcpState({
      path,
      masterKey: randomBytes(32),
      logger: { warn: (...args: unknown[]) => warnings.push(args) },
    });
    expect(await other.connections.list()).toEqual([]);
    expect(warnings).toHaveLength(1);
    const files = await readdir(directory);
    expect(files.some((f) => f.startsWith("mcp-state.json.unreadable-"))).toBe(
      true,
    );
  });
});
