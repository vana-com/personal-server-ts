import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  mkdir,
  mkdtemp,
  open,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import {
  UploadAttemptStoreInvalidError,
  createUploadAttemptLedger,
  uploadAttemptKey,
} from "@opendatalabs/personal-server-ts-core/sync";
import type { IndexEntry } from "@opendatalabs/personal-server-ts-core/storage/index/types";

import { createFileUploadAttemptStore } from "./upload-attempts.js";

const OWNER = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12";
const entry = {
  id: 1,
  scope: "chatgpt.conversations",
  path: "chatgpt.conversations/2026-11-07T10:00:00Z.json",
  collectedAt: "2026-11-07T10:00:00Z",
  version: 1,
  sizeBytes: 4096,
} as IndexEntry;

describe("createFileUploadAttemptStore", () => {
  let dir: string;
  beforeEach(async () => {
    const base = join(homedir(), ".tmp");
    await mkdir(base, { recursive: true });
    dir = await mkdtemp(join(base, "upload-attempts-"));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("keeps an unsettled attempt across process restarts and quarantines at the second", async () => {
    const path = join(dir, "nested", "upload-attempts.json");
    for (let boot = 0; boot < 2; boot++) {
      const ledger = createUploadAttemptLedger(
        createFileUploadAttemptStore(path),
        OWNER,
      );
      await ledger.recover();
      expect(ledger.quarantined()).toEqual([]);
      await ledger.begin(entry); // the process dies here, never settles
      await ledger.close(); // a dead process holds no lock
    }
    const ledger = createUploadAttemptLedger(
      createFileUploadAttemptStore(path),
      OWNER,
    );
    await ledger.recover();
    expect(ledger.isQuarantined(uploadAttemptKey(OWNER, entry))).toBe(true);
  });

  it("starts empty when the file does not exist, and clears on settle", async () => {
    const path = join(dir, "upload-attempts.json");
    const store = createFileUploadAttemptStore(path);
    expect(await store.read()).toBeNull();
    const ledger = createUploadAttemptLedger(store, OWNER);
    await ledger.recover();
    await ledger.begin(entry);
    await ledger.settle(entry, "success");
    expect(await store.read()).toEqual({ version: 1, records: [] });
  });

  it("keeps a value that is not a ledger and refuses to upload over it", async () => {
    const path = join(dir, "upload-attempts.json");
    const bad = '{"version":1,"records":{}}\n';
    await writeFile(path, bad);
    const ledger = createUploadAttemptLedger(
      createFileUploadAttemptStore(path),
      OWNER,
    );
    await expect(ledger.recover()).rejects.toBeInstanceOf(
      UploadAttemptStoreInvalidError,
    );
    await expect(ledger.begin(entry)).rejects.toThrow();
    expect(await readFile(path, "utf8")).toBe(bad);
    // Unparseable text is kept as well.
    await writeFile(path, "{not json");
    const broken = createUploadAttemptLedger(
      createFileUploadAttemptStore(path),
      OWNER,
    );
    await expect(broken.recover()).rejects.toThrow();
    expect(await readFile(path, "utf8")).toBe("{not json");
  });

  it("lets one manager at a time own the file", async () => {
    const path = join(dir, "upload-attempts.json");
    const first = createUploadAttemptLedger(
      createFileUploadAttemptStore(path),
      OWNER,
    );
    const second = createUploadAttemptLedger(
      createFileUploadAttemptStore(path),
      OWNER,
    );
    expect(await first.recover()).toBe(true);
    await first.begin(entry);
    expect(await second.recover()).toBe(false);
    await first.close();
    expect(await second.recover()).toBe(true);
    // The live attempt was counted once, by the manager that took over.
    expect(second.quarantined()).toEqual([]);
  });

  it("writes through a unique temp file, flushes it and the directory, and leaves no temp file", async () => {
    const path = join(dir, "upload-attempts.json");
    const probe = await open(path, "w");
    const handle = Object.getPrototypeOf(probe) as { sync(): Promise<void> };
    await probe.close();
    const sync = vi.spyOn(handle, "sync");
    const store = createFileUploadAttemptStore(path);
    const record = { version: 1 as const, records: [] };
    await Promise.all([store.write(record), store.write(record)]);
    // Two writes, each flushing its file and then the directory.
    expect(sync).toHaveBeenCalledTimes(4);
    sync.mockRestore();
    expect((await readdir(dir)).filter((f) => f.endsWith(".tmp"))).toEqual([]);
    expect(JSON.parse(await readFile(path, "utf8"))).toEqual(record);
  });
});
