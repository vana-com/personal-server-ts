/**
 * DELETE /v1/data/:scope through the real handler, with a REAL seal over a
 * memory storage and a real mode authority.
 *
 * A legacy-only delete on a switched account would answer "deleted" while the
 * stream rows stay readable, so a switched account is refused with 409
 * USE_CONNECTOR_DELETE; an unknown mode is a retryable 503; an unswitched
 * account deletes as before. The decision and the delete are one `commit`.
 */
import { describe, expect, it, vi } from "vitest";
import {
  handlePersonalServerDataRequest,
  type PersonalServerDataApiDeps,
} from "./index.js";
import { createLegacyWriteSeal } from "../storage/legacy-write-seal.js";
import { createSyncManager } from "../sync/engine/sync-manager.js";
import {
  createMemoryModeRecordStore,
  createModeAuthority,
  type ModeAuthority,
} from "../sync/account-mode/index.js";
import { authorityHearing } from "../test-utils/account-mode.js";
import {
  createMemoryDataStorage,
  type MemoryDataStorage,
} from "../test-utils/memory-storage.js";
import { createMemoryPendingBlobDeletionStore } from "../sync/pending-blob-deletions.js";
import type { Logger } from "../logger/index.js";
import type { DeleteDataPort } from "../ports/index.js";

const OWNER = "0x1111111111111111111111111111111111111111";
const SCOPE = "notes.entries";

const quietLogger = (): Logger =>
  ({
    info: vi.fn(),
    error: vi.fn(),
    warn: vi.fn(),
    debug: vi.fn(),
    trace: vi.fn(),
    fatal: vi.fn(),
  }) as unknown as Logger;

function gate() {
  let open!: () => void;
  const opened = new Promise<void>((resolve) => {
    open = resolve;
  });
  return { opened, open };
}
const tick = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

type Mode = "unswitched" | "switched" | "unknown";

async function authorityFor(mode: Mode): Promise<ModeAuthority> {
  if (mode === "unswitched") return authorityHearing(OWNER, "off");
  if (mode === "switched") return authorityHearing(OWNER, "on");
  const authority = createModeAuthority({
    store: createMemoryModeRecordStore(),
  });
  await authority.ready;
  return authority;
}

function seed(storage: MemoryDataStorage, versions = 2): void {
  for (let n = 1; n <= versions; n += 1) {
    storage.entries.push({
      id: n,
      fileId: null,
      schemaId: null,
      path: `${SCOPE}/${n}.json`,
      scope: SCOPE,
      collectedAt: `2026-11-0${n}T00:00:00.000Z`,
      createdAt: "2026-11-01T00:00:00.000Z",
      sizeBytes: 10,
      version: n,
      casRevision: n,
      dataPointId: null,
    });
  }
}

function deleteData(
  onTombstone: () => Promise<void> = async () => undefined,
): DeleteDataPort & { tombstone: ReturnType<typeof vi.fn> } {
  return {
    tombstone: vi.fn(async () => {
      await onTombstone();
      return {
        status: "tombstoned" as const,
        dataPointId: "0xdp",
        version: "1",
        deletedAt: "2026-11-09T00:00:00.000Z",
        replaced: null,
      };
    }),
    deleteBlobVersions: vi.fn(async (_scope: string, versions: string[]) => ({
      deleted: versions,
      missing: [],
      failed: [],
    })),
  } as unknown as DeleteDataPort & { tombstone: ReturnType<typeof vi.fn> };
}

async function fixture(
  mode: Mode,
  options: {
    manager?: boolean;
    remote?: DeleteDataPort;
    insideSealed?: () => Promise<void>;
    sealed?: boolean;
  } = {},
) {
  const authority = await authorityFor(mode);
  const seal = createLegacyWriteSeal({ authority, owner: OWNER });
  const storage = createMemoryDataStorage({
    ...(options.sealed === false ? {} : { legacyWriteSeal: seal }),
    insideSealed: options.insideSealed,
  });
  seed(storage);
  const remote = options.remote ?? deleteData();
  const syncManager = options.manager
    ? createSyncManager(
        {
          storage,
          storageAdapter: {} as never,
          gateway: {} as never,
          signer: {} as never,
          masterKey: new Uint8Array(65).fill(0xaa),
          serverOwner: OWNER,
          logger: quietLogger(),
        },
        {
          storage,
          storageAdapter: {} as never,
          gateway: {} as never,
          cursor: { read: async () => null, write: async () => undefined },
          masterKey: new Uint8Array(65).fill(0xaa),
          serverOwner: OWNER,
          logger: quietLogger(),
        },
        {
          deleteData: remote,
          pendingBlobDeletions: createMemoryPendingBlobDeletionStore(),
        },
      )
    : null;
  const accessLog = vi.fn(async () => undefined);
  const deps: PersonalServerDataApiDeps = {
    storage,
    serverOwner: OWNER,
    syncManager,
    auth: {
      authorizeOwner: vi.fn(async () => undefined),
      authorizeBuilderList: vi.fn(async () => undefined),
      authorizeBuilderRead: vi.fn(async () => undefined),
    },
    accessLogWriter: { write: accessLog },
  };
  const send = () =>
    handlePersonalServerDataRequest(
      new Request(`https://ps.example/${SCOPE}`, { method: "DELETE" }),
      deps,
    );
  return { authority, seal, storage, remote, syncManager, accessLog, send };
}

const evidence = (state: "on" | "off") => ({
  owner: OWNER,
  state,
});

describe.each([
  ["without a sync manager (local copy only)", false],
  ["through the sync manager (tombstone, blobs, local)", true],
] as const)("DELETE /v1/data/:scope %s", (_label, manager) => {
  // ROUTE_DELETE_ADMITS_SWITCHED
  it("refuses a switched account with 409 USE_CONNECTOR_DELETE and deletes nothing", async () => {
    const f = await fixture("switched", { manager });
    const response = await f.send();
    expect(response.status).toBe(409);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("content-type")).toContain("application/json");
    const body = await response.json();
    expect(body.error.code).toBe(409);
    expect(body.error.errorCode).toBe("USE_CONNECTOR_DELETE");
    expect(typeof body.error.message).toBe("string");
    expect(f.storage.entries).toHaveLength(2);
    expect(f.remote.tombstone).not.toHaveBeenCalled();
    expect(f.accessLog).not.toHaveBeenCalled();
  });

  it("refuses an unknown mode with the retryable 503 and deletes nothing", async () => {
    const f = await fixture("unknown", { manager });
    const response = await f.send();
    expect(response.status).toBe(503);
    expect(response.headers.get("retry-after")).toBe("5");
    expect((await response.json()).error.errorCode).toBe(
      "ACCOUNT_MODE_UNKNOWN",
    );
    expect(f.storage.entries).toHaveLength(2);
    expect(f.remote.tombstone).not.toHaveBeenCalled();
  });

  it("deletes for an unswitched account, as before", async () => {
    const f = await fixture("unswitched", { manager });
    const response = await f.send();
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.steps.local.status).toBe("ok");
    expect(f.storage.entries).toHaveLength(0);
    expect(f.remote.tombstone).toHaveBeenCalledTimes(manager ? 1 : 0);
    expect(f.accessLog).toHaveBeenCalledOnce();
  });

  it("treats a storage with no seal as unknown: a missing answer is never permission", async () => {
    const f = await fixture("unswitched", { manager, sealed: false });
    const response = await f.send();
    expect(response.status).toBe(503);
    expect((await response.json()).error.errorCode).toBe(
      "ACCOUNT_MODE_UNKNOWN",
    );
    expect(f.storage.entries).toHaveLength(2);
    expect(f.remote.tombstone).not.toHaveBeenCalled();
  });
});

describe("the DELETE route and the On latch share one lock", () => {
  it("lets a delete in flight when On is submitted finish before On is answered", async () => {
    const barrier = gate();
    let held = false;
    const remote = deleteData(async () => {
      held = true;
      await barrier.opened;
    });
    const f = await fixture("unswitched", { manager: true, remote });
    const response = f.send();
    await vi.waitFor(() => expect(held).toBe(true));

    let answeredWith: number | undefined;
    const on = f.authority.submitEvidence(evidence("on")).then((decision) => {
      answeredWith = f.storage.entries.length;
      return decision;
    });
    await tick();
    await tick();
    // On waits for the delete: it has not been answered, and the delete has
    // not yet removed anything.
    expect(answeredWith).toBeUndefined();

    barrier.open();
    // The removal inside the commit uses the hold. If it asked the lock again
    // it would queue behind the waiting On and this would never settle.
    expect((await response).status).toBe(200);
    expect((await on).kind).toBe("streams");
    expect(answeredWith).toBe(0);
    expect(f.storage.entries).toHaveLength(0);
  });

  it("refuses a delete that starts after On was submitted and removes nothing", async () => {
    const barrier = gate();
    const f = await fixture("unswitched", {
      manager: false,
      insideSealed: undefined,
    });
    // Hold the shared lock with an unrelated legacy write so On has to wait.
    const write = f.seal.commit(() => barrier.opened);
    await tick();
    const on = f.authority.submitEvidence(evidence("on"));
    await tick();
    const response = f.send();
    await tick();
    await tick();
    barrier.open();
    await write;
    await on;
    const refused = await response;
    expect(refused.status).toBe(409);
    expect((await refused.json()).error.errorCode).toBe("USE_CONNECTOR_DELETE");
    expect(f.storage.entries).toHaveLength(2);
  });

  it("passes its hold to the local removal instead of taking the lock again", async () => {
    const f = await fixture("unswitched", { manager: false });
    const original = f.storage.deleteScope.bind(f.storage);
    const holds: unknown[] = [];
    f.storage.deleteScope = (async (scope: string, hold?: unknown) => {
      holds.push(hold);
      return original(scope, hold as never);
    }) as typeof f.storage.deleteScope;
    expect((await f.send()).status).toBe(200);
    expect(holds).toHaveLength(1);
    expect(holds[0]).toBeDefined();
  });
});
