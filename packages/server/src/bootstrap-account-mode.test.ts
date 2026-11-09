/**
 * What the saved account-mode record does at boot: a switched owner's legacy
 * store is left alone, an unreadable record starts the server unknown (legacy
 * writes pause, boot does not fail), and shutdown drains an admitted legacy
 * write before the index closes.
 */
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { privateKeyToAccount } from "viem/accounts";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { createServer, type ServerContext } from "./bootstrap.js";
import { declareAccountMode } from "./account-mode/unswitched-server.test-utils.js";

const config = () => ServerConfigSchema.parse({ tunnel: { enabled: false } });

async function ownerSignature() {
  return privateKeyToAccount(`0x${"11".repeat(32)}`).signMessage({
    message: "Disposably authorize Node",
  });
}

describe("the server's hold on the account mode records", () => {
  let dir: string;
  const open: ServerContext[] = [];
  const start = async (): Promise<ServerContext> => {
    const ctx = await createServer(config(), {
      serverDir: dir,
      dataDir: join(dir, "data"),
      ownerSignature: await ownerSignature(),
    });
    open.push(ctx);
    return ctx;
  };
  const tick = (ms: number) => new Promise((r) => setTimeout(r, ms));

  beforeEach(async () => {
    dir = await mkdtemp(join(process.env.HOME ?? "", ".tmp", "boot-owner-"));
  });
  afterEach(async () => {
    for (const ctx of open.splice(0)) await ctx.cleanup().catch(() => {});
    await rm(dir, { recursive: true, force: true });
  });

  it("a saved On plus a reindex condition at boot produces no legacy write", async () => {
    const first = await start();
    await declareAccountMode(first, "on");
    await first.cleanup();
    open.splice(0);
    // The index would be rebuilt on this boot (a reindex was left unfinished).
    const marker = join(dir, "reindex-in-progress");
    await writeFile(marker, "left over\n");

    const second = await start();
    expect(await readFile(marker, "utf8")).toBe("left over\n");
    expect(
      second.accountModeAuthority.read(second.serverOwner ?? "").kind,
    ).toBe("streams");
  }, 30_000);

  it("an owner with no saved On repairs the legacy store at boot, as before", async () => {
    const marker = join(dir, "reindex-in-progress");
    await writeFile(marker, "left over\n");
    await start();
    await expect(readFile(marker, "utf8")).rejects.toMatchObject({
      code: "ENOENT",
    });
  }, 30_000);

  it("a saved record that cannot be read starts the runtime unknown: legacy writes pause", async () => {
    await mkdir(join(dir, "account-mode"), { recursive: true });
    await writeFile(join(dir, "account-mode", "broken.json"), "{not json");
    const ctx = await start();
    expect(ctx.accountModeAuthority.read(ctx.serverOwner ?? "").kind).toBe(
      "refuse",
    );
  }, 30_000);

  it("shutdown waits for an admitted legacy write before it closes", async () => {
    const first = await start();
    await declareAccountMode(first, "off");
    const owner = first.serverOwner ?? "";
    let entered!: () => void;
    const inside = new Promise<void>((r) => (entered = r));
    let leave!: () => void;
    const latch = new Promise<void>((r) => (leave = r));
    const write = first.accountModeAuthority.commitLegacy(owner, async () => {
      entered();
      await latch;
    });
    await inside;

    let closed = false;
    const closing = first.cleanup().then(() => {
      closed = true;
    });
    await tick(200);
    expect(closed).toBe(false);

    leave();
    expect(await write).toMatchObject({ ok: true });
    await closing;
    const second = await start();
    await declareAccountMode(second, "on");
    expect(second.accountModeAuthority.read(owner).kind).toBe("streams");
  }, 30_000);
});
