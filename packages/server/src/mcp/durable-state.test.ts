import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { createMcpConnection } from "@opendatalabs/personal-server-ts-core/mcp";
import { openMcpDurableState } from "./durable-state.js";

const OWNER = "0x1111111111111111111111111111111111111111";
const directories: string[] = [];

afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

describe("TEE MCP durable state", () => {
  it("restores only the latest sealed owner wakeup envelope after a process restart", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mcp-wakeup-"));
    directories.push(directory);
    const path = join(directory, "state.sealed");
    const key = randomBytes(32);
    const state = await openMcpDurableState({ path, key });
    const identity = {
      userPsId: `0x${"11".repeat(32)}`,
      epoch: 1,
      enclaveAddress: OWNER,
      enclavePublicKey: "0x04",
      sealedEnvelope: {
        v: 1,
        iv: "iv",
        ciphertext: "sealed-owner-material",
        tag: "tag",
        wrappedContentKey: { iv: "iv", ciphertext: "key", tag: "tag" },
      },
    } as const;
    await state.rememberIdentity(identity);
    await state.rememberIdentity({ ...identity, epoch: 2 });
    await state.rememberIdentity(identity);
    const reopened = await openMcpDurableState({ path, key });
    expect((await reopened.getIdentity(identity.userPsId))?.epoch).toBe(2);
    expect(await readFile(path, "utf8")).not.toContain("sealed-owner-material");
  });
  it("restores an approved connection and owner after restart without plaintext grantee material on disk", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mcp-durable-"));
    directories.push(directory);
    const path = join(directory, "state.sealed");
    const key = randomBytes(32);
    const state = await openMcpDurableState({ path, key });
    const created = await createMcpConnection(
      { displayName: "Claude demo" },
      {
        store: state.connections,
        publicOrigin: "https://mcp-dev.vana.org",
      },
    );
    await state.bindOwner(created.connectionId, {
      owner: OWNER,
      chainId: 14800,
    });
    await state.connections.update(created.connectionId, {
      status: "approved",
      grants: [{ grantId: "0xabc", scopes: ["spotify.profile"] }],
    });
    const before = await state.connections.getById(created.connectionId);
    const stored = await readFile(path, "utf8");
    expect(stored).not.toContain("Claude demo");
    expect(stored).not.toContain(OWNER);
    expect(stored).not.toContain(
      JSON.stringify(before?.encryptedGranteePrivateKey),
    );
    const reopened = await openMcpDurableState({ path, key });
    expect(await reopened.connections.getById(created.connectionId)).toEqual(
      before,
    );
    expect(await reopened.getOwner(created.connectionId)).toEqual({
      owner: OWNER,
      chainId: 14800,
    });
    await reopened.connections.update(created.connectionId, {
      status: "revoked",
    });
    const restarted = await openMcpDurableState({ path, key });
    expect(
      await restarted.connections.getByTokenHash(before!.tokenHash),
    ).toBeNull();
  });
});
