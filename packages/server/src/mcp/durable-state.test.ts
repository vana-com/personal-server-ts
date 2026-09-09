import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { createMcpConnection } from "@opendatalabs/personal-server-ts-core/mcp";
import { openMcpDurableState } from "./durable-state.js";
import { userPsId } from "@opendatalabs/vana-sdk/protocol/identity";

const OWNER = "0x1111111111111111111111111111111111111111";
const directories: string[] = [];

it("prepares a fresh imported owner's wakeup envelope atomically for rollback without a job", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mcp-rollback-cache-"));
  directories.push(directory);
  const central = await openMcpDurableState({
    path: join(directory, "central.sealed"),
    key: randomBytes(32),
  });
  const created = await createMcpConnection(
    { displayName: "fresh fleet owner" },
    { store: central.connections, publicOrigin: "https://mcp-dev.vana.org" },
  );
  await central.bindOwner(created.connectionId, {
    owner: OWNER,
    chainId: 14800,
  });
  await central.connections.update(created.connectionId, {
    status: "approved",
  });
  const path = join(directory, "source.sealed"),
    key = randomBytes(32);
  const source = await openMcpDurableState({ path, key });
  await source.importSnapshot(
    await central.fenceAndExport("rollback-cache-1", "source"),
    "rollback-cache-1",
  );
  const identity = {
    userPsId: userPsId(14800, OWNER),
    epoch: 2,
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
  expect(await source.getIdentity(identity.userPsId)).toBeNull();
  const receipt = await source.prepareRollback(
    "rollback-cache-1",
    async (binding) => {
      expect(binding).toEqual({ owner: OWNER, chainId: 14800 });
      return { identity, generation: 4 };
    },
  );
  expect(receipt).toMatchObject({
    migrationId: "rollback-cache-1",
    owners: 1,
    connections: 1,
  });
  const restarted = await openMcpDurableState({ path, key });
  expect(await restarted.getIdentity(identity.userPsId)).toEqual(identity);
  expect(await restarted.getRollbackPreparation()).toMatchObject({
    receipt,
    owners: [{ binding: { owner: OWNER, chainId: 14800 }, identity }],
  });
  expect(await readFile(path, "utf8")).not.toContain("sealed-owner-material");
});

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

it("fences the old OAuth writer durably before exporting and restores connection under a new TEE key", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mcp-migration-"));
  directories.push(directory);
  const sourcePath = join(directory, "source.sealed"),
    targetPath = join(directory, "target.sealed");
  const sourceKey = randomBytes(32),
    targetKey = randomBytes(32);
  const source = await openMcpDurableState({
    path: sourcePath,
    key: sourceKey,
  });
  const created = await createMcpConnection(
    { displayName: "ordinary Claude" },
    { store: source.connections, publicOrigin: "https://mcp-dev.vana.org" },
  );
  await source.bindOwner(created.connectionId, {
    owner: OWNER,
    chainId: 14800,
  });
  const before = await source.connections.getById(created.connectionId);
  const snapshot = await source.fenceAndExport("migration-1", "target-app");
  await expect(
    source.connections.update(created.connectionId, { status: "revoked" }),
  ).rejects.toThrow("fenced");
  const restarted = await openMcpDurableState({
    path: sourcePath,
    key: sourceKey,
  });
  await expect(
    restarted.connections.getById(created.connectionId),
  ).rejects.toThrow("fenced");
  const target = await openMcpDurableState({
    path: targetPath,
    key: targetKey,
  });
  await target.importSnapshot(snapshot, "migration-1");
  snapshot.fill(0);
  expect(await target.connections.getById(created.connectionId)).toEqual(
    before,
  );
  expect(await target.getOwner(created.connectionId)).toEqual({
    owner: OWNER,
    chainId: 14800,
  });
  expect(await readFile(targetPath, "utf8")).not.toContain("ordinary Claude");
  await expect(
    openMcpDurableState({ path: targetPath, key: sourceKey }),
  ).rejects.toThrow();
});

it("invalidates rollback receipts on partial refresh, owner membership, cached identity, and snapshot changes", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mcp-rollback-invalid-"));
  directories.push(directory);
  const central = await openMcpDurableState({
    path: join(directory, "central.sealed"),
    key: randomBytes(32),
  });
  const ids: string[] = [];
  for (const owner of [OWNER, "0x2222222222222222222222222222222222222222"]) {
    const created = await createMcpConnection(
      { displayName: owner },
      { store: central.connections, publicOrigin: "https://mcp-dev.vana.org" },
    );
    ids.push(created.connectionId);
    await central.bindOwner(created.connectionId, { owner, chainId: 14800 });
    await central.connections.update(created.connectionId, {
      status: "approved",
    });
  }
  const source = await openMcpDurableState({
    path: join(directory, "source.sealed"),
    key: randomBytes(32),
  });
  const snapshot = await central.fenceAndExport("rollback-invalid-1", "source");
  await source.importSnapshot(snapshot, "rollback-invalid-1");
  const identity = (owner: string, epoch = 2) => ({
    userPsId: userPsId(14800, owner),
    epoch,
    enclaveAddress: owner,
    enclavePublicKey: "0x04",
    sealedEnvelope: {
      v: 1 as const,
      iv: "iv",
      ciphertext: "ciphertext",
      tag: "tag",
      wrappedContentKey: { iv: "iv", ciphertext: "key", tag: "tag" },
    },
  });
  const prepare = () =>
    source.prepareRollback("rollback-invalid-1", async (binding) => ({
      identity: identity(binding.owner),
      generation: 4,
    }));
  await prepare();
  const sameIdentity = identity(OWNER);
  await source.rememberIdentity({
    sealedEnvelope: sameIdentity.sealedEnvelope,
    enclavePublicKey: sameIdentity.enclavePublicKey,
    enclaveAddress: sameIdentity.enclaveAddress,
    epoch: sameIdentity.epoch,
    userPsId: sameIdentity.userPsId,
  });
  await expect(source.getRollbackPreparation()).resolves.toMatchObject({
    receipt: { owners: 2 },
  });
  let resolved = 0;
  await expect(
    source.prepareRollback("rollback-invalid-1", async (binding) => {
      if (++resolved === 2) throw new Error("second owner denied");
      return { identity: identity(binding.owner, 3), generation: 5 };
    }),
  ).rejects.toThrow("second owner denied");
  expect((await source.getIdentity(userPsId(14800, OWNER)))?.epoch).toBe(2);
  await expect(source.getRollbackPreparation()).rejects.toThrow("not prepared");
  await prepare();
  await source.connections.update(ids[0]!, { status: "revoked" });
  await expect(source.getRollbackPreparation()).rejects.toThrow("not prepared");
  await source.connections.update(ids[0]!, { status: "approved" });
  await prepare();
  await source.rememberIdentity(identity(OWNER, 3));
  await expect(source.getRollbackPreparation()).rejects.toThrow("changed");
  await prepare();
  const next = await openMcpDurableState({
    path: join(directory, "next.sealed"),
    key: randomBytes(32),
  });
  const emptySnapshot = await next.fenceAndExport(
    "rollback-invalid-2",
    "source",
  );
  await source.fenceAndExport("outward-invalid-2", "next");
  await source.importSnapshot(emptySnapshot, "rollback-invalid-2");
  await expect(source.getRollbackPreparation()).rejects.toThrow("not prepared");
  expect(await central.approvedOwnerBindings()).toHaveLength(2);
  await expect(central.connections.getById(ids[0]!)).rejects.toThrow("fenced");
});
