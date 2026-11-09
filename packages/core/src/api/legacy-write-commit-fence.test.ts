/**
 * The commit fence: a legacy write admitted while the account was unswitched
 * must still be refused if the account switches before the write becomes
 * durable. Each test parks a real request on its body read (after admission),
 * switches the account from outside, then resumes the request. Every test
 * drives the production handler; the fence is not copied.
 */
import { describe, expect, it, vi } from "vitest";
import {
  createAccountStorageMode,
  handlePersonalServerDataRequest,
  type PersonalServerDataApiDeps,
} from "./index.js";
import { createScopeUploadRegistry } from "./scope-uploads.js";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";
import type { DataStoragePort } from "../ports/index.js";

const OWNER = "0x1111111111111111111111111111111111111111";
const scope = "notes.entries";
const operation = "c".repeat(64);

/** A request whose body read parks until `release()` is called. */
function parkedRequest(
  url: string,
  init: { method: string; headers?: Record<string, string> },
  body: string | Uint8Array,
) {
  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  let started!: () => void;
  const reading = new Promise<void>((resolve) => {
    started = resolve;
  });
  const bytes =
    typeof body === "string" ? new TextEncoder().encode(body) : body;
  const stream = new ReadableStream<Uint8Array>({
    async pull(controller) {
      started();
      await gate;
      controller.enqueue(bytes);
      controller.close();
    },
  });
  const request = new Request(url, {
    ...init,
    body: stream,
    duplex: "half",
  } as RequestInit);
  return { request, release, reading };
}

/** A switch source the test flips from outside the request. */
function switchable() {
  const state = { value: false as boolean | "unreachable" };
  const mode = createAccountStorageMode({
    owner: OWNER,
    source: () => {
      if (state.value === "unreachable") throw new Error("Account unreachable");
      return state.value;
    },
  });
  return { state, mode };
}

function depsFor(
  mode: PersonalServerDataApiDeps["accountStorageMode"],
  extra: Partial<PersonalServerDataApiDeps> = {},
): PersonalServerDataApiDeps {
  return {
    storage: createMemoryDataStorage(),
    serverOwner: OWNER,
    accountStorageMode: mode,
    auth: {
      authorizeOwner: vi.fn(async () => undefined),
      authorizeBuilderList: vi.fn(async () => undefined),
      authorizeBuilderRead: vi.fn(async () => undefined),
    },
    accessLogWriter: { write: vi.fn(async () => undefined) },
    now: () => new Date("2026-11-09T00:00:00.000Z"),
    ...extra,
  };
}

const URL_BASE = "https://ps.example";

/**
 * Park `request` in the handler (admission passed), switch the account, let
 * the request resume, and return its response.
 */
async function switchWhileParked(
  parked: ReturnType<typeof parkedRequest>,
  deps: PersonalServerDataApiDeps,
  flip: () => void,
) {
  const pending = handlePersonalServerDataRequest(parked.request, deps);
  await parked.reading;
  flip();
  parked.release();
  return pending;
}

describe("the commit fence refuses a write that was admitted before the switch", () => {
  // ADMISSION_ONLY_GATE: upload commit
  it("upload commit: 426, the staged upload is discarded and nothing is published", async () => {
    const { state, mode } = switchable();
    const writerCommit = vi.fn(async () => ({
      path: "p",
      relativePath: "p",
      sizeBytes: 1,
    }));
    const writerAbort = vi.fn(async () => undefined);
    const storage = {
      ...createMemoryDataStorage(),
      async openVersionWriter() {
        return {
          write: async () => undefined,
          commit: writerCommit,
          abort: writerAbort,
        };
      },
    } as unknown as DataStoragePort;
    const scopeUploads = createScopeUploadRegistry({ createId: () => "u1" });
    await scopeUploads.begin({
      scope,
      collectedAt: "2026-11-09T00:00:00.000Z",
      storage,
      release: () => undefined,
      body: { data: {}, arrayKey: "records" },
    });
    const deps = depsFor(mode, { storage, scopeUploads });
    const parked = parkedRequest(
      `${URL_BASE}/${scope}/uploads/u1/commit`,
      { method: "POST", headers: { "content-type": "application/json" } },
      "{}",
    );
    const response = await switchWhileParked(parked, deps, () => {
      state.value = true;
    });
    expect(response.status).toBe(426);
    expect((await response.json()).errorCode).toBe("update_required");
    expect(writerCommit).not.toHaveBeenCalled();
    expect(writerAbort).toHaveBeenCalled();
  });

  // ADMISSION_ONLY_GATE: JSON POST
  it("JSON POST: 426 and no version stored", async () => {
    const { state, mode } = switchable();
    const deps = depsFor(mode);
    const parked = parkedRequest(
      `${URL_BASE}/${scope}`,
      { method: "POST", headers: { "content-type": "application/json" } },
      JSON.stringify({ records: [{ id: 1 }] }),
    );
    const response = await switchWhileParked(parked, deps, () => {
      state.value = true;
    });
    expect(response.status).toBe(426);
    expect(
      (deps.storage as ReturnType<typeof createMemoryDataStorage>).entries,
    ).toHaveLength(0);
  });

  // ADMISSION_ONLY_GATE: binary POST
  it("binary POST: 426 and no version stored", async () => {
    const { state, mode } = switchable();
    const deps = depsFor(mode);
    const parked = parkedRequest(
      `${URL_BASE}/${scope}`,
      { method: "POST", headers: { "content-type": "application/pdf" } },
      new Uint8Array([1, 2, 3]),
    );
    const response = await switchWhileParked(parked, deps, () => {
      state.value = true;
    });
    expect(response.status).toBe(426);
    expect(
      (deps.storage as ReturnType<typeof createMemoryDataStorage>).entries,
    ).toHaveLength(0);
  });

  // ADMISSION_ONLY_GATE: durable import
  it("durable import: 426 and no version committed", async () => {
    const { state, mode } = switchable();
    const commitVersion = vi.fn(async () => {
      throw new Error("a refused import must not reach storage");
    });
    const storage = Object.assign(createMemoryDataStorage(), { commitVersion });
    const deps = depsFor(mode, { storage });
    const parked = parkedRequest(
      `${URL_BASE}/${scope}/imports/${operation}`,
      { method: "PUT", headers: { "content-type": "application/json" } },
      JSON.stringify({ records: [{ id: 1 }] }),
    );
    const response = await switchWhileParked(parked, deps, () => {
      state.value = true;
    });
    expect(response.status).toBe(426);
    expect(commitVersion).not.toHaveBeenCalled();
    expect(storage.entries).toHaveLength(0);
  });

  it("refuses with a retryable 503 when the mode becomes unknown after admission", async () => {
    const { state, mode } = switchable();
    const deps = depsFor(mode);
    const parked = parkedRequest(
      `${URL_BASE}/${scope}`,
      { method: "POST", headers: { "content-type": "application/json" } },
      JSON.stringify({ records: [{ id: 1 }] }),
    );
    const response = await switchWhileParked(parked, deps, () => {
      state.value = "unreachable";
    });
    expect(response.status).toBe(503);
    expect((await response.json()).error.errorCode).toBe(
      "ACCOUNT_MODE_UNKNOWN",
    );
    expect(
      (deps.storage as ReturnType<typeof createMemoryDataStorage>).entries,
    ).toHaveLength(0);
  });

  it("still stores the write when the account stays unswitched", async () => {
    const { mode } = switchable();
    const deps = depsFor(mode);
    const parked = parkedRequest(
      `${URL_BASE}/${scope}`,
      { method: "POST", headers: { "content-type": "application/json" } },
      JSON.stringify({ records: [{ id: 1 }] }),
    );
    const response = await switchWhileParked(parked, deps, () => undefined);
    expect(response.status).toBe(201);
    expect(
      (deps.storage as ReturnType<typeof createMemoryDataStorage>).entries,
    ).toHaveLength(1);
  });
});
