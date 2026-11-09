/**
 * A claim that fails after taking the lock gives the lock back, and a folder
 * on a network file system is refused before any lock is tried. These need
 * the file system calls replaced, so they live apart from the other tests.
 */
import type * as FsPromises from "node:fs/promises";
import { mkdtemp, readdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ModeStoreOwnedError } from "@opendatalabs/personal-server-ts-core/sync/account-mode";

const fsMock = vi.hoisted(() => ({
  readdirFailures: 0,
  statfsType: null as number | null,
}));

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof FsPromises>();
  return {
    ...actual,
    readdir: ((...args: Parameters<typeof actual.readdir>) => {
      if (fsMock.readdirFailures > 0) {
        fsMock.readdirFailures -= 1;
        return Promise.reject(new Error("injected readdir failure"));
      }
      return actual.readdir(...args);
    }) as typeof actual.readdir,
    statfs: ((...args: Parameters<typeof actual.statfs>) =>
      fsMock.statfsType === null
        ? actual.statfs(...args)
        : Promise.resolve({
            type: fsMock.statfsType,
          })) as typeof actual.statfs,
  };
});

const { createFileModeRecordStore } = await import("./file-record-store.js");
const { networkFilesystemName, ModeStoreUnsupportedError } =
  await import("./owner-lock.js");

describe("a claim that cannot finish", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(process.env.HOME ?? "", ".tmp", "mode-claim-"));
  });
  afterEach(async () => {
    fsMock.readdirFailures = 0;
    fsMock.statfsType = null;
    await rm(dir, { recursive: true, force: true });
  });

  // NO_CLAIM_ROLLBACK
  it("lets the folder go when the work after taking the lock fails", async () => {
    fsMock.readdirFailures = 1;
    const store = createFileModeRecordStore(dir);
    await expect(store.claim()).rejects.toThrow("injected readdir failure");
    // Nothing is stranded: this store, and any other, claims at once.
    const again = await store.claim();
    await again.release();
    const other = await createFileModeRecordStore(dir).claim();
    await other.release();
  });

  it.skipIf(process.platform !== "linux")(
    "refuses a folder on a network file system before it tries any lock",
    async () => {
      fsMock.statfsType = 0x6969;
      const store = createFileModeRecordStore(dir);
      const refused = await store.claim().catch((error: unknown) => error);
      expect(refused).toBeInstanceOf(ModeStoreUnsupportedError);
      expect(refused).not.toBeInstanceOf(ModeStoreOwnedError);
      expect(String(refused)).toMatch(/NFS/);
      expect(await readdir(dir)).toEqual([]);
      await expect(store.load()).rejects.toBeInstanceOf(ModeStoreOwnedError);
    },
  );

  it("names the network file systems it refuses, and no local one", () => {
    expect(networkFilesystemName(0x6969)).toBe("NFS");
    expect(networkFilesystemName(0xff534d42)).toBe("CIFS");
    expect(networkFilesystemName(0xef53)).toBeNull(); // ext4
    expect(networkFilesystemName(0x58465342)).toBeNull(); // xfs
  });
});
