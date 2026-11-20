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
import {
  parseDataReadScopeContract,
  parseDataScopeContract,
} from "../contracts/data.js";
import { createGrantContract } from "../contracts/grants.js";
import { isPhysicalScope, streamReadScope } from "./routing.js";

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

describe("stream-sync read names", () => {
  it("maps the logical name and the identity-less physical scope to the logical name", () => {
    expect(streamReadScope("pdpp.github-browser.repositories")).toBe(
      "pdpp.github-browser.repositories",
    );
    expect(streamReadScope("pdpp.github-browser~.repositories")).toBe(
      "pdpp.github-browser.repositories",
    );
    expect(streamReadScope("pdpp.chatgpt~.conversations")).toBe(
      "pdpp.chatgpt.conversations",
    );
  });

  it("refuses a namespaced scope, a control scope, a path and a non-stream name", () => {
    for (const name of [
      "pdpp.chatgpt~0123456789abcdef.conversations",
      "pdpp.chatgpt~0123456789abcdef",
      "pdpp.chatgpt~",
      "chatgpt.conversations",
      "pdpp.chatgpt",
      "pdpp.a.b/../c",
      "pdpp.a b.c",
      "pdpp.a.b\nc",
      "pdpp.a~b.c",
    ]) {
      expect(streamReadScope(name), name).toBeNull();
    }
  });

  it("a read takes the names, and no other contract does", () => {
    const safeParse = vi.mocked(ScopeSchema.safeParse);
    safeParse.mockClear();
    for (const name of [
      "pdpp.github-browser.repositories",
      "pdpp.github-browser~.repositories",
    ]) {
      expect(parseDataReadScopeContract(name)).toEqual({
        ok: true,
        scope: "pdpp.github-browser.repositories",
      });
    }
    expect(safeParse).not.toHaveBeenCalled();
    // The strict rule is unchanged: writes, deletes and imports never take them.
    expect(
      parseDataScopeContract("pdpp.github-browser.repositories"),
    ).toMatchObject({
      ok: false,
      body: { error: "INVALID_SCOPE" },
    });
    expect(
      parseDataScopeContract("pdpp.github-browser~.repositories"),
    ).toMatchObject({
      ok: false,
      body: { error: "INVALID_SCOPE" },
    });
    // A read still refuses the other physical names.
    for (const name of [
      "pdpp.chatgpt~0123456789abcdef.conversations",
      "pdpp.chatgpt~0123456789abcdef",
      "pdpp.chatgpt~",
    ]) {
      expect(parseDataReadScopeContract(name)).toMatchObject({
        ok: false,
        body: { error: "INVALID_SCOPE" },
      });
    }
    // Names that were valid stay valid and unchanged.
    expect(parseDataReadScopeContract("instagram.profile")).toEqual({
      ok: true,
      scope: "instagram.profile",
    });
  });
});
