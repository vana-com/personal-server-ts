/**
 * POST /v1/data/:scope through the real handler, over a REAL seal.
 *
 * The route's early refusal reads a mode without the lock and is only a
 * courtesy. These tests give the route a STALE "unswitched" early mode while
 * the seal says otherwise, so the answer can only come from the seal at the
 * durable step: 426 once switched, a retryable 503 while unknown, and nothing
 * is stored in either case.
 */
import { describe, expect, it } from "vitest";
import {
  handlePersonalServerDataRequest,
  type PersonalServerDataApiDeps,
} from "./index.js";
import { createLegacyWriteSeal } from "../storage/legacy-write-seal.js";
import {
  createMemoryModeRecordStore,
  createModeAuthority,
} from "../sync/account-mode/index.js";
import {
  authorityHearing,
  fixedOwnedAccountStorageMode,
} from "../test-utils/index.js";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";

const OWNER = "0x1111111111111111111111111111111111111111";

async function fixture(mode: "unswitched" | "switched" | "unknown") {
  const authority =
    mode === "unknown"
      ? createModeAuthority({
          store: createMemoryModeRecordStore(),
        })
      : await authorityHearing(OWNER, mode === "switched" ? "on" : "off");
  await authority.ready;
  const storage = createMemoryDataStorage({
    legacyWriteSeal: createLegacyWriteSeal({ authority, owner: OWNER }),
  });
  const deps: PersonalServerDataApiDeps = {
    storage,
    serverOwner: OWNER,
    // Stale on purpose: the early refusal lets the write through.
    accountStorageMode: fixedOwnedAccountStorageMode("unswitched"),
    auth: {
      authorizeOwner: async () => undefined,
      authorizeBuilderList: async () => undefined,
      authorizeBuilderRead: async () => undefined,
    },
    accessLogWriter: { write: async () => undefined },
  };
  const post = () =>
    handlePersonalServerDataRequest(
      new Request("https://ps.example/notes.entries", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ items: [{ id: 1 }] }),
      }),
      deps,
    );
  return { storage, post };
}

describe("POST /v1/data/:scope is sealed at its durable step", () => {
  // WITHAPIERRORS_REFUSAL_500
  it("answers 426 update_required on a switched account and stores nothing", async () => {
    const f = await fixture("switched");
    const response = await f.post();
    expect(response.status).toBe(426);
    expect((await response.json()).error.errorCode).toBe("update_required");
    expect(f.storage.entries).toHaveLength(0);
  });

  it("answers the retryable 503 while the mode is unknown and stores nothing", async () => {
    const f = await fixture("unknown");
    const response = await f.post();
    expect(response.status).toBe(503);
    expect((await response.json()).error.errorCode).toBe(
      "ACCOUNT_MODE_UNKNOWN",
    );
    expect(response.headers.get("retry-after")).not.toBeNull();
    expect(f.storage.entries).toHaveLength(0);
  });

  it("stores the write on an unswitched account", async () => {
    const f = await fixture("unswitched");
    expect((await f.post()).status).toBe(201);
    expect(f.storage.entries).toHaveLength(1);
  });
});
