/**
 * The server's hold on the account mode record folder: ownership comes before
 * any data step, a runtime another one owns is inert, shutdown drains before it
 * lets go, and a failed start does not strand the folder.
 */
import {
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { privateKeyToAccount } from "viem/accounts";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ModeStoreOwnedError } from "@opendatalabs/personal-server-ts-core/sync/account-mode";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { createServer, type ServerContext } from "./bootstrap.js";
import { createFileModeRecordStore } from "./account-mode/file-record-store.js";
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

  // OWNED_REFUSAL_SWALLOWED, BOOT_DATA_BEFORE_OWNER
  it("a runtime another one owns is refused with a typed error and touches no data", async () => {
    const holder = await createFileModeRecordStore(
      join(dir, "account-mode"),
    ).claim();
    try {
      await expect(start()).rejects.toBeInstanceOf(ModeStoreOwnedError);
      // No index, no migration state, no key, no logs, no sentinel: only the
      // two directories every start makes, and the owner's own folder.
      expect((await readdir(dir)).sort()).toEqual(["account-mode", "data"]);
      expect(await readdir(join(dir, "data"))).toEqual([]);
    } finally {
      await holder.release();
    }
    // Once the owner has gone, the same root starts.
    const again = await start();
    expect(again.indexManager).toBeDefined();
  }, 30_000);

  // BOOT_DATA_BEFORE_OWNER
  it("opens no index while the records are still being claimed", async () => {
    // A store whose claim takes a while: until it answers, nothing else runs.
    const inner = createFileModeRecordStore(join(dir, "account-mode"));
    let release!: () => void;
    const slow = new Promise<void>((r) => (release = r));
    let claimed = false;
    const store = {
      async claim() {
        await slow;
        const lease = await inner.claim();
        claimed = true;
        return lease;
      },
      load: () => inner.load(),
      save: inner.save.bind(inner),
    };
    const starting = createServer(config(), {
      serverDir: dir,
      dataDir: join(dir, "data"),
      ownerSignature: await ownerSignature(),
      accountModeStore: store,
    });
    await tick(300);
    expect(claimed).toBe(false);
    expect(await readdir(dir)).not.toContain("index.db");
    release();
    const ctx = await starting;
    open.push(ctx);
    expect(await readdir(dir)).toContain("index.db");
  }, 30_000);

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

  it("a saved mode that cannot be loaded starts the runtime, refusing legacy work, and repairs nothing", async () => {
    // A directory where a record file belongs: the load fails, not the claim.
    await mkdir(join(dir, "account-mode", "broken.json"), { recursive: true });
    const marker = join(dir, "reindex-in-progress");
    await writeFile(marker, "left over\n");
    const ctx = await start();
    expect(ctx.accountModeAuthority.read(ctx.serverOwner ?? "").kind).toBe(
      "refuse",
    );
    expect(await readFile(marker, "utf8")).toBe("left over\n");
  }, 30_000);

  it("shutdown waits for an admitted legacy write before it lets the next runtime own the records", async () => {
    const first = await start();
    await declareAccountMode(first, "off");
    const owner = first.serverOwner ?? "";
    let entered!: () => void;
    const inside = new Promise<void>((r) => (entered = r));
    let leave!: () => void;
    const latch = new Promise<void>((r) => (leave = r));
    const write = first.accountModeAuthority.commitLegacy(
      owner,
      "op",
      async () => {
        entered();
        await latch;
      },
    );
    await inside;

    let closed = false;
    const closing = first.cleanup().then(() => {
      closed = true;
    });
    await tick(200);
    expect(closed).toBe(false);
    // The records are still the first runtime's.
    await expect(start()).rejects.toBeInstanceOf(ModeStoreOwnedError);

    leave();
    expect(await write).toMatchObject({ ok: true });
    await closing;
    const second = await start();
    await declareAccountMode(second, "on");
    expect(second.accountModeAuthority.read(owner).kind).toBe("streams");
  }, 30_000);

  // NO_RELEASE_ON_FAILED_START
  it("a start that fails after the records are claimed lets them go", async () => {
    // A file where the logs folder must go: the start throws after the claim.
    await writeFile(join(dir, "logs"), "not a folder");
    await expect(start()).rejects.toThrow();
    await rm(join(dir, "logs"));
    const again = await start();
    await declareAccountMode(again, "off");
    expect(again.accountModeAuthority.read(again.serverOwner ?? "").kind).toBe(
      "legacy",
    );
  }, 30_000);
});
