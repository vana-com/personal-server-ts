/**
 * The account storage mode: one answer, one latch, shared by the legacy write
 * gate and the read selector. Every test drives production code; none copies it.
 */
import { describe, expect, it, vi } from "vitest";
import {
  createAccountStorageMode,
  refuseLegacyWrite,
  handlePersonalServerDataRequest,
  selectAccountStorageMode,
  type AccountStorageMode,
  type PersonalServerDataApiDeps,
} from "./index.js";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";

const OWNER_A = "0x1111111111111111111111111111111111111111";
const OWNER_B = "0x2222222222222222222222222222222222222222";

/** A switch source whose answer a test changes between reads. */
function source(initial: boolean | "unreachable") {
  const state = { value: initial };
  const read = vi.fn(() => {
    if (state.value === "unreachable") throw new Error("Account unreachable");
    return state.value;
  });
  return { state, read };
}

function dataDeps(
  extra: Partial<PersonalServerDataApiDeps> = {},
): PersonalServerDataApiDeps {
  return {
    storage: createMemoryDataStorage(),
    serverOwner: OWNER_A,
    auth: {
      authorizeOwner: vi.fn(async () => undefined),
      authorizeBuilderList: vi.fn(async () => undefined),
      authorizeBuilderRead: vi.fn(async () => undefined),
    },
    accessLogWriter: { write: vi.fn(async () => undefined) },
    now: () => new Date("2026-11-01T00:00:00.000Z"),
    createLogId: () => "log-1",
    ...extra,
  };
}

const post = () =>
  new Request("https://ps.example/notes.entries", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ records: [{ id: 1 }] }),
  });

describe("createAccountStorageMode", () => {
  it("reads unswitched while the source says false", () => {
    const { read } = source(false);
    expect(createAccountStorageMode({ source: read }).read()).toBe(
      "unswitched",
    );
  });

  it("reads switched once the source says true, and stays switched", () => {
    const { state, read } = source(true);
    const mode = createAccountStorageMode({ source: read });
    expect(mode.read()).toBe("switched");
    state.value = false;
    expect(mode.read()).toBe("switched");
    state.value = "unreachable";
    expect(mode.read()).toBe("switched");
    // Once latched the source is not consulted again.
    expect(read).toHaveBeenCalledTimes(1);
  });

  it("reads unknown, not unswitched, while the source is unreachable and nothing is latched", () => {
    const { state, read } = source("unreachable");
    const mode = createAccountStorageMode({ source: read });
    expect(mode.read()).toBe("unknown");
    state.value = false;
    expect(mode.read()).toBe("unswitched");
    state.value = true;
    expect(mode.read()).toBe("switched");
  });

  // LATCH_CROSSES_ACCOUNTS
  it("keeps the latch inside the instance: another account's mode is not switched by it", () => {
    const a = createAccountStorageMode({ owner: OWNER_A, source: () => true });
    const b = createAccountStorageMode({ owner: OWNER_B, source: () => false });
    expect(a.read()).toBe("switched");
    expect(b.read()).toBe("unswitched");
    expect(a.read()).toBe("switched");
  });

  // LATCH_CROSSES_ACCOUNTS
  it("answers unknown for an owner it is not bound to, even after it latched", () => {
    const mode = createAccountStorageMode({
      owner: OWNER_A,
      source: () => true,
    });
    expect(mode.read(OWNER_A)).toBe("switched");
    expect(mode.read(OWNER_A.toUpperCase().replace("0X", "0x"))).toBe(
      "switched",
    );
    expect(mode.read(OWNER_B)).toBe("unknown");
    // The foreign question did not disturb the bound owner's latch.
    expect(mode.read(OWNER_A)).toBe("switched");
  });

  it("does not consult the source again for an owner it is not bound to", () => {
    const { read } = source(false);
    const mode = createAccountStorageMode({ owner: OWNER_A, source: read });
    // Built eagerly: one sample at construction, none for a foreign question.
    expect(read).toHaveBeenCalledTimes(1);
    expect(mode.read(OWNER_B)).toBe("unknown");
    expect(read).toHaveBeenCalledTimes(1);
  });

  // LAZY_LATCH
  it("latches a startup true before any caller reads it", () => {
    const { state, read } = source(true);
    const mode = createAccountStorageMode({ source: read });
    state.value = false;
    expect(mode.read()).toBe("switched");
  });
});

describe("selectAccountStorageMode", () => {
  it("selects legacy when no mode is wired", () => {
    expect(selectAccountStorageMode({}).kind).toBe("legacy");
  });

  // UNSWITCHED_CHANGED
  it("selects legacy for an unswitched account", () => {
    const mode = createAccountStorageMode({ source: () => false });
    expect(selectAccountStorageMode({ accountStorageMode: mode })).toEqual({
      kind: "legacy",
    });
  });

  it("selects streams for a switched account", () => {
    const mode = createAccountStorageMode({ source: () => true });
    expect(selectAccountStorageMode({ accountStorageMode: mode })).toEqual({
      kind: "streams",
    });
  });

  // UNKNOWN_READS_LEGACY
  it("refuses with a retryable 503 when the mode is unknown and nothing is latched, never legacy", async () => {
    const { read } = source("unreachable");
    const selection = selectAccountStorageMode({
      accountStorageMode: createAccountStorageMode({ source: read }),
    });
    expect(selection.kind).toBe("refuse");
    if (selection.kind !== "refuse") throw new Error("unreachable");
    expect(selection.retryable).toBe(true);
    expect(selection.reason).toBe("mode_unknown");
    expect(selection.response.status).toBe(503);
    expect(selection.response.headers.get("retry-after")).toBe("5");
    const body = await selection.response.json();
    expect(body.error.errorCode).toBe("ACCOUNT_MODE_UNKNOWN");
  });

  // UNKNOWN_READS_LEGACY
  it("refuses a foreign owner instead of answering from this instance's latch", () => {
    const mode = createAccountStorageMode({
      owner: OWNER_A,
      source: () => false,
    });
    expect(
      selectAccountStorageMode({
        accountStorageMode: mode,
        serverOwner: OWNER_B,
      }).kind,
    ).toBe("refuse");
    expect(
      selectAccountStorageMode({
        accountStorageMode: mode,
        serverOwner: OWNER_A,
      }).kind,
    ).toBe("legacy");
  });

  it("uses the latch when the source later becomes unreachable", () => {
    const { state, read } = source(true);
    const deps = {
      accountStorageMode: createAccountStorageMode({ source: read }),
    };
    expect(selectAccountStorageMode(deps).kind).toBe("streams");
    state.value = "unreachable";
    expect(selectAccountStorageMode(deps).kind).toBe("streams");
  });

  // READER_PRESENCE_AS_MODE
  it("does not take a wired stream reader as the mode", () => {
    const reader = { resolve: vi.fn() };
    const unswitched = selectAccountStorageMode({
      accountStorageMode: createAccountStorageMode({ source: () => false }),
      streamSyncRead: reader,
    } as never);
    expect(unswitched.kind).toBe("legacy");
    const switchedWithoutReader = selectAccountStorageMode({
      accountStorageMode: createAccountStorageMode({ source: () => true }),
    });
    expect(switchedWithoutReader.kind).toBe("streams");
    const noModeWithReader = selectAccountStorageMode({
      streamSyncRead: reader,
    } as never);
    expect(noModeWithReader.kind).toBe("legacy");
    expect(reader.resolve).not.toHaveBeenCalled();
  });
});

describe("the write gate and the read selector share one answer", () => {
  // GATE_AND_SELECTOR_DISAGREE
  it("refuse a legacy write exactly when the selector says streams, through every transition", async () => {
    const { state, read } = source(false);
    const mode = createAccountStorageMode({ owner: OWNER_A, source: read });
    const deps = dataDeps({ accountStorageMode: mode });
    const sweep: Array<boolean | "unreachable"> = [
      false,
      "unreachable",
      false,
      true,
      false,
      "unreachable",
    ];
    for (const value of sweep) {
      state.value = value;
      const selection = selectAccountStorageMode(deps).kind;
      const write = await handlePersonalServerDataRequest(post(), deps);
      expect(write.status === 426, `source ${String(value)}`).toBe(
        selection === "streams",
      );
      expect(refuseLegacyWrite(mode, OWNER_A)?.status === 426).toBe(
        selection === "streams",
      );
    }
  });

  // GATE_AND_SELECTOR_DISAGREE
  it("refuses a legacy write with a retryable 503 while the mode is unknown, as reads do", async () => {
    const { read } = source("unreachable");
    const mode = createAccountStorageMode({ source: read });
    const write = await handlePersonalServerDataRequest(
      post(),
      dataDeps({ accountStorageMode: mode }),
    );
    expect(write.status).toBe(503);
    expect((await write.json()).error.errorCode).toBe("ACCOUNT_MODE_UNKNOWN");
    expect(selectAccountStorageMode({ accountStorageMode: mode }).kind).toBe(
      "refuse",
    );
  });
});

describe("a read of an unswitched account is unchanged", () => {
  /** The same requests against deps with and without a mode wired. */
  async function transcript(accountStorageMode?: AccountStorageMode) {
    const storage = createMemoryDataStorage();
    const deps = dataDeps({ storage, accountStorageMode });
    // An unswitched account writes legacy data and reads it back.
    const written = await handlePersonalServerDataRequest(post(), deps);
    const responses = [{ path: "POST", status: written.status, body: "" }];
    for (const path of ["/", "/notes.entries", "/notes.entries/versions"]) {
      const response = await handlePersonalServerDataRequest(
        new Request(`https://ps.example${path}`),
        deps,
      );
      responses.push({
        path,
        status: response.status,
        body: await response.text(),
      });
    }
    return responses;
  }

  // UNSWITCHED_CHANGED
  it("answers list, read and versions exactly as with no mode wired", async () => {
    const baseline = await transcript(undefined);
    expect(baseline.map((r) => r.status)).toEqual([201, 200, 200, 200]);
    const unswitched = await transcript(
      createAccountStorageMode({ owner: OWNER_A, source: () => false }),
    );
    expect(unswitched).toEqual(baseline);
  });
});
