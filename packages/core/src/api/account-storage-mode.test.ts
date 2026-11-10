/**
 * The account storage mode port: one answer, shared by the legacy write gate
 * and the read selector. Every test drives production code; none copies it.
 * The answer itself comes from the account-mode module
 * (`sync/account-mode`), which has its own tests.
 */
import { describe, expect, it, vi } from "vitest";
import {
  accountStorageModeFor,
  handlePersonalServerDataRequest,
  selectAccountStorageMode,
  type AccountStorageMode,
  type AccountStorageModeValue,
  type PersonalServerDataApiDeps,
} from "./index.js";
import { accountStorageModeOf } from "../sync/account-mode/index.js";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";
import {
  authorityHearing,
  fixedOwnedAccountStorageMode,
} from "../test-utils/account-mode.js";

const OWNER_A = "0x1111111111111111111111111111111111111111";
const OWNER_B = "0x2222222222222222222222222222222222222222";

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
  it("binds a runtime with no owner to the empty owner", () => {
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

  // OWNERLESS_READ_ANSWERS
  it("answers unknown, from the real module, to a runtime of another owner or of none", async () => {
    const authority = await authorityHearing(OWNER_A, "on");
    const mode = accountStorageModeOf(authority);
    expect(accountStorageModeFor(mode, OWNER_A).read()).toBe("switched");
    expect(accountStorageModeFor(mode, OWNER_B).read()).toBe("unknown");
    expect(accountStorageModeFor(mode, undefined).read()).toBe("unknown");
    expect(mode.read(undefined as unknown as string)).toBe("unknown");
  });
});

describe("selectAccountStorageMode", () => {
  it("keeps reads on the legacy path when no mode is wired", () => {
    expect(selectAccountStorageMode({})).toEqual({ kind: "legacy" });
  });

  // UNSWITCHED_CHANGED
  it("selects legacy for an unswitched account", () => {
    expect(
      selectAccountStorageMode({
        accountStorageMode: fixedOwnedAccountStorageMode("unswitched"),
      }),
    ).toEqual({ kind: "legacy" });
  });

  it("selects streams for a switched account", () => {
    expect(
      selectAccountStorageMode({
        accountStorageMode: fixedOwnedAccountStorageMode("switched"),
      }),
    ).toEqual({ kind: "streams" });
  });

  it("keeps reads open before the owner's first answer", () => {
    expect(
      selectAccountStorageMode({
        accountStorageMode: fixedOwnedAccountStorageMode("unknown"),
      }),
    ).toEqual({ kind: "legacy" });
  });

  // READER_PRESENCE_AS_MODE
  it("does not take a wired stream reader as the mode", () => {
    const reader = { resolve: vi.fn() };
    const unswitched = selectAccountStorageMode({
      accountStorageMode: fixedOwnedAccountStorageMode("unswitched"),
      streamSyncRead: reader,
    } as never);
    expect(unswitched.kind).toBe("legacy");
    const noModeWithReader = selectAccountStorageMode({
      streamSyncRead: reader,
    } as never);
    expect(noModeWithReader.kind).toBe("legacy");
    expect(reader.resolve).not.toHaveBeenCalled();
  });
});

describe("the write gate and the read selector share one answer", () => {
  const VALUES: AccountStorageModeValue[] = [
    "unswitched",
    "unknown",
    "switched",
    "unknown",
    "unswitched",
  ];

  it("send a legacy write to streams only when switched, through every value", async () => {
    let current: AccountStorageModeValue = "unswitched";
    const deps = dataDeps({
      accountStorageMode: {
        owner: OWNER_A,
        read: () => current,
      },
    });
    for (const value of VALUES) {
      current = value;
      const selection = selectAccountStorageMode(deps).kind;
      const write = await handlePersonalServerDataRequest(post(), deps);
      const expectedStatus =
        value === "switched" ? 426 : value === "unknown" ? 503 : 201;
      expect(write.status, `mode ${value}`).toBe(expectedStatus);
      expect(selection === "streams", `mode ${value}`).toBe(
        value === "switched",
      );
    }
  });

  // GATE_AND_SELECTOR_DISAGREE
  it("refuses a legacy write with a retryable 503 when the mode is unknown", async () => {
    const write = await handlePersonalServerDataRequest(
      post(),
      dataDeps({
        accountStorageMode: fixedOwnedAccountStorageMode("unknown", OWNER_A),
      }),
    );
    expect(write.status).toBe(503);
    expect((await write.json()).error.errorCode).toBe("ACCOUNT_MODE_UNKNOWN");
  });

  it("pauses a legacy write when no mode is wired", async () => {
    const write = await handlePersonalServerDataRequest(post(), dataDeps());
    expect(write.status).toBe(503);
  });

  // OWNERLESS_READ_ANSWERS
  it("gives a runtime of another owner a paused write and a legacy read", async () => {
    const authority = await authorityHearing(OWNER_A, "on");
    const deps = dataDeps({
      serverOwner: OWNER_B,
      accountStorageMode: accountStorageModeFor(
        accountStorageModeOf(authority),
        OWNER_B,
      ),
    });
    expect(selectAccountStorageMode(deps).kind).toBe("legacy");
    expect((await handlePersonalServerDataRequest(post(), deps)).status).toBe(
      503,
    );
  });
});

describe("a read of an unswitched account", () => {
  // UNSWITCHED_CHANGED: the golden transcript. A fresh explicit Off answers
  // exactly as an account did before the module existed.
  it("answers write, list, read and versions with today's responses", async () => {
    const storage = createMemoryDataStorage();
    const deps = dataDeps({
      storage,
      accountStorageMode: fixedOwnedAccountStorageMode("unswitched", OWNER_A),
    });
    const written = await handlePersonalServerDataRequest(post(), deps);
    const transcript = [{ path: "POST", status: written.status, body: "" }];
    for (const path of ["/", "/notes.entries", "/notes.entries/versions"]) {
      const response = await handlePersonalServerDataRequest(
        new Request(`https://ps.example${path}`),
        deps,
      );
      transcript.push({
        path,
        status: response.status,
        body: await response.text(),
      });
    }
    expect(transcript).toMatchSnapshot();
  });
});
