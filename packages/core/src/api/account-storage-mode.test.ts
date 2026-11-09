/**
 * The account storage mode: one answer, one latch, shared by the legacy write
 * gate and the read selector. Every test drives production code; none copies it.
 */
import { describe, expect, it, vi } from "vitest";
import {
  accountStorageModeFor,
  createAccountStorageMode,
  handlePersonalServerDataRequest,
  legacyWriteSwitchOf,
  selectAccountStorageMode,
  type AccountStorageMode,
  type OwnedAccountStorageMode,
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

/** A mode bound to OWNER_A, viewed as the runtime of OWNER_A. */
function ownedBy(
  read: () => boolean,
  owner = OWNER_A,
): OwnedAccountStorageMode {
  return accountStorageModeFor(
    createAccountStorageMode({ owner: OWNER_A, source: read }),
    owner,
  );
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
    expect(
      createAccountStorageMode({ owner: OWNER_A, source: read }).read(OWNER_A),
    ).toBe("unswitched");
  });

  it("reads switched once the source says true, and stays switched", () => {
    const { state, read } = source(true);
    const mode = createAccountStorageMode({ owner: OWNER_A, source: read });
    expect(mode.read(OWNER_A)).toBe("switched");
    state.value = false;
    expect(mode.read(OWNER_A)).toBe("switched");
    state.value = "unreachable";
    expect(mode.read(OWNER_A)).toBe("switched");
    // Once latched the source is not consulted again.
    expect(read).toHaveBeenCalledTimes(1);
  });

  it("reads unknown, not unswitched, while the source is unreachable and nothing is latched", () => {
    const { state, read } = source("unreachable");
    const mode = createAccountStorageMode({ owner: OWNER_A, source: read });
    expect(mode.read(OWNER_A)).toBe("unknown");
    state.value = false;
    expect(mode.read(OWNER_A)).toBe("unswitched");
    state.value = true;
    expect(mode.read(OWNER_A)).toBe("switched");
  });

  // LATCH_CROSSES_ACCOUNTS
  it("keeps the latch inside the instance: another account's mode is not switched by it", () => {
    const a = createAccountStorageMode({ owner: OWNER_A, source: () => true });
    const b = createAccountStorageMode({ owner: OWNER_B, source: () => false });
    expect(a.read(OWNER_A)).toBe("switched");
    expect(b.read(OWNER_B)).toBe("unswitched");
    expect(a.read(OWNER_A)).toBe("switched");
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

  // DROP_REQUEST_OWNER
  it("answers unknown, never the latch, when the owner is empty or missing", () => {
    const mode = createAccountStorageMode({
      owner: OWNER_A,
      source: () => true,
    });
    expect(mode.read(OWNER_A)).toBe("switched");
    expect(mode.read("")).toBe("unknown");
    expect(mode.read(undefined as unknown as string)).toBe("unknown");
    // A mode bound to no owner answers nobody.
    const unbound = createAccountStorageMode({ owner: "", source: () => true });
    expect(unbound.read("")).toBe("unknown");
    expect(unbound.read(OWNER_A)).toBe("unknown");
  });

  it("does not consult the source for an owner it is not bound to", () => {
    const { read } = source(true);
    const mode = createAccountStorageMode({ owner: OWNER_A, source: read });
    expect(mode.read(OWNER_B)).toBe("unknown");
    expect(mode.read("")).toBe("unknown");
    expect(read).not.toHaveBeenCalled();
  });
});

describe("accountStorageModeFor", () => {
  // DROP_REQUEST_OWNER
  it("asks the mode about the owner it was bound to, every time", () => {
    const asked: string[] = [];
    const mode: AccountStorageMode = {
      read: (requestOwner) => {
        asked.push(requestOwner);
        return "unswitched";
      },
    };
    const view = accountStorageModeFor(mode, OWNER_B);
    view.read();
    view.read();
    expect(asked).toEqual([OWNER_B, OWNER_B]);
    expect(view.owner).toBe(OWNER_B);
  });

  // DROP_REQUEST_OWNER
  it("binds a runtime with no owner to the empty owner, which is unknown", () => {
    const asked: string[] = [];
    const view = accountStorageModeFor(
      {
        read: (requestOwner) => {
          asked.push(requestOwner);
          return "switched";
        },
      },
      undefined,
    );
    view.read();
    expect(asked).toEqual([""]);
  });

  // LATCH_CROSSES_ACCOUNTS
  it("answers unknown to a runtime of another owner, though the mode is latched switched", () => {
    const mode = createAccountStorageMode({
      owner: OWNER_A,
      source: () => true,
    });
    expect(accountStorageModeFor(mode, OWNER_A).read()).toBe("switched");
    expect(accountStorageModeFor(mode, OWNER_B).read()).toBe("unknown");
  });
});

describe("selectAccountStorageMode", () => {
  it("selects legacy when no mode is wired", () => {
    expect(selectAccountStorageMode({}).kind).toBe("legacy");
  });

  // UNSWITCHED_CHANGED
  it("selects legacy for an unswitched account", () => {
    expect(
      selectAccountStorageMode({ accountStorageMode: ownedBy(() => false) }),
    ).toEqual({ kind: "legacy" });
  });

  it("selects streams for a switched account", () => {
    expect(
      selectAccountStorageMode({ accountStorageMode: ownedBy(() => true) }),
    ).toEqual({ kind: "streams" });
  });

  // UNKNOWN_READS_LEGACY
  it("refuses with a retryable 503 when the mode is unknown and nothing is latched, never legacy", async () => {
    const { read } = source("unreachable");
    const selection = selectAccountStorageMode({
      accountStorageMode: ownedBy(read),
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
  it("refuses a runtime of another owner instead of answering from this instance's latch", () => {
    const latched = createAccountStorageMode({
      owner: OWNER_A,
      source: () => true,
    });
    expect(latched.read(OWNER_A)).toBe("switched");
    const selection = selectAccountStorageMode({
      accountStorageMode: accountStorageModeFor(latched, OWNER_B),
    });
    expect(selection.kind).toBe("refuse");
    expect(
      selectAccountStorageMode({
        accountStorageMode: accountStorageModeFor(latched, OWNER_A),
      }).kind,
    ).toBe("streams");
  });

  it("uses the latch when the source later becomes unreachable", () => {
    const { state, read } = source(true);
    const deps = { accountStorageMode: ownedBy(read) };
    expect(selectAccountStorageMode(deps).kind).toBe("streams");
    state.value = "unreachable";
    expect(selectAccountStorageMode(deps).kind).toBe("streams");
  });

  // READER_PRESENCE_AS_MODE
  it("does not take a wired stream reader as the mode", () => {
    const reader = { resolve: vi.fn() };
    const unswitched = selectAccountStorageMode({
      accountStorageMode: ownedBy(() => false),
      streamSyncRead: reader,
    } as never);
    expect(unswitched.kind).toBe("legacy");
    const switchedWithoutReader = selectAccountStorageMode({
      accountStorageMode: ownedBy(() => true),
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
    const mode = ownedBy(read);
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
      expect(legacyWriteSwitchOf(mode)()).toBe(selection === "streams");
    }
  });

  // GATE_AND_SELECTOR_DISAGREE
  it("takes the gate's answer from the mode, not from a separate switch", async () => {
    const deps = dataDeps({
      accountStorageMode: ownedBy(() => false),
      // A stale plain switch that disagrees with the mode must not win.
      legacyWritesRefused: () => true,
    });
    const write = await handlePersonalServerDataRequest(post(), deps);
    expect(write.status).not.toBe(426);

    const switched = dataDeps({
      accountStorageMode: ownedBy(() => true),
      legacyWritesRefused: () => false,
    });
    expect(
      (await handlePersonalServerDataRequest(post(), switched)).status,
    ).toBe(426);
  });

  // GATE_AND_SELECTOR_DISAGREE
  it("lets an unknown mode through the write gate (fail open) while reads refuse", async () => {
    const { read } = source("unreachable");
    const mode = ownedBy(read);
    expect(legacyWriteSwitchOf(mode)()).toBe(false);
    expect(selectAccountStorageMode({ accountStorageMode: mode }).kind).toBe(
      "refuse",
    );
  });

  // LATCH_CROSSES_ACCOUNTS
  it("gives a runtime of another owner unknown at the gate and the selector alike", async () => {
    const latched = createAccountStorageMode({
      owner: OWNER_A,
      source: () => true,
    });
    expect(latched.read(OWNER_A)).toBe("switched");
    const asked: string[] = [];
    const spy: AccountStorageMode = {
      read: (requestOwner) => {
        asked.push(requestOwner);
        return latched.read(requestOwner);
      },
    };
    const deps = dataDeps({
      serverOwner: OWNER_B,
      accountStorageMode: accountStorageModeFor(spy, OWNER_B),
    });
    expect(selectAccountStorageMode(deps).kind).toBe("refuse");
    // Unknown is no refusal for writes: the write is not turned away as
    // switched, because B is not switched.
    expect(
      (await handlePersonalServerDataRequest(post(), deps)).status,
    ).not.toBe(426);
    expect(asked.length).toBeGreaterThan(0);
    expect(new Set(asked)).toEqual(new Set([OWNER_B]));
  });
});

describe("a read of an unswitched account is unchanged", () => {
  /** The same requests against deps with and without a mode wired. */
  async function transcript(accountStorageMode?: OwnedAccountStorageMode) {
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
    const unswitched = await transcript(ownedBy(() => false));
    expect(unswitched).toEqual(baseline);
  });
});
