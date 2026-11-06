import { describe, expect, it, vi } from "vitest";
import type * as VanaSdk from "@opendatalabs/vana-sdk/browser";

// Watch the SDK scope schema: a physical name must never reach it.
vi.mock("@opendatalabs/vana-sdk/browser", async (importOriginal) => {
  const actual = (await importOriginal()) as typeof VanaSdk;
  return {
    ...actual,
    ScopeSchema: {
      ...actual.ScopeSchema,
      safeParse: vi.fn((value: unknown) => actual.ScopeSchema.safeParse(value)),
    },
  };
});

import { ScopeSchema } from "@opendatalabs/vana-sdk/browser";
import { parseDataScopeContract } from "../contracts/data.js";
import { createGrantContract } from "../contracts/grants.js";
import { isPhysicalScope } from "./routing.js";

const PHYSICAL = [
  "pdpp.chatgpt~0123456789abcdef.conversations",
  "pdpp.chatgpt~0123456789abcdef",
  "pdpp.chatgpt~.conversations",
  "pdpp.chatgpt~",
  "x~y",
];

describe("physical stream-sync names", () => {
  it("are recognised, logical names are not", () => {
    for (const name of PHYSICAL) expect(isPhysicalScope(name)).toBe(true);
    for (const name of [
      "pdpp.chatgpt.conversations",
      "chatgpt.conversations",
    ]) {
      expect(isPhysicalScope(name)).toBe(false);
    }
  });

  it("are refused as requested names before the SDK schema", () => {
    const safeParse = vi.mocked(ScopeSchema.safeParse);
    safeParse.mockClear();
    for (const name of PHYSICAL) {
      expect(parseDataScopeContract(name)).toMatchObject({
        ok: false,
        status: 400,
        body: { error: "INVALID_SCOPE" },
      });
    }
    expect(safeParse).not.toHaveBeenCalled();
    // The refusal is the one the schema gave these names before.
    const before = ScopeSchema.safeParse(PHYSICAL[0]);
    expect(before.success).toBe(false);
    expect(parseDataScopeContract(PHYSICAL[0]!)).toMatchObject({
      body: { message: before.error?.issues[0]?.message },
    });
    expect(parseDataScopeContract("pdpp.chatgpt.conversations")).toEqual({
      ok: true,
      scope: "pdpp.chatgpt.conversations",
    });
  });

  it("are not grantable", async () => {
    const getBuilder = vi.fn();
    const result = await createGrantContract({
      serverOwner: "0x1111111111111111111111111111111111111111",
      serverSigner: {} as never,
      gateway: { getBuilder } as never,
      body: {
        granteeAddress: "0x2222222222222222222222222222222222222222",
        scopes: ["chatgpt.conversations", PHYSICAL[0]!],
      },
    } as never);
    expect(result).toMatchObject({ status: 400 });
    expect(getBuilder).not.toHaveBeenCalled();
  });
});
