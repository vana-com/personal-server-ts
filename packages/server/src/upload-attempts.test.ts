import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import {
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
    await ledger.begin(entry);
    await ledger.settle(entry);
    expect(await store.read()).toEqual([]);
  });
});
