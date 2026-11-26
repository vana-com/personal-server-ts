import { describe, expect, it } from "vitest";
import { createCursorSeal } from "./pdpp-cursor-seal.js";
import { decodeBase64Url } from "../encoding/base64url.js";

/** spec-core §4 "Incremental sync", §8 "List records"; §9 RS item 21. */
describe("cursor seal", () => {
  const key = new Uint8Array(32).fill(1);

  it("opens what it sealed for the same kind and context only", async () => {
    const seal = createCursorSeal(key);
    const token = await seal.seal("sync", ["g1", "s"], "inner-42");
    expect(token).toMatch(/^cs_[A-Za-z0-9_-]+$/);
    await expect(seal.open("sync", ["g1", "s"], token)).resolves.toBe(
      "inner-42",
    );
    for (const [kind, context, value] of [
      ["sync", ["g2", "s"], token],
      ["page", ["g1", "s"], token],
      ["sync", ["g1", "s"], token.slice(0, -2) + "AA"],
      ["sync", ["g1", "s"], "cs_!!"],
    ] as const) {
      await expect(seal.open(kind, context, value)).rejects.toMatchObject({
        code: "invalid_cursor",
        status: 400,
      });
    }
  });

  it("issues a distinct opaque token each time and survives a new seal with the same key", async () => {
    const a = createCursorSeal(key);
    const first = await a.seal("page", ["c"], "same-position");
    const second = await a.seal("page", ["c"], "same-position");
    expect(first).not.toBe(second);
    expect(
      new TextDecoder().decode(decodeBase64Url(first.slice(3))),
    ).not.toContain("same-position");
    await expect(createCursorSeal(key).open("page", ["c"], first)).resolves.toBe(
      "same-position",
    );
    await expect(
      createCursorSeal(new Uint8Array(32).fill(2)).open("page", ["c"], first),
    ).rejects.toMatchObject({ code: "invalid_cursor" });
  });

  it("expires an unsealed sync token this RS issued before sealing", async () => {
    const seal = createCursorSeal(key);
    const legacy = btoa(JSON.stringify({ kind: "changes_since", horizon: "3" }))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    for (const token of [legacy, "17"])
      await expect(seal.open("sync", [], token)).rejects.toMatchObject({
        code: "cursor_expired",
        status: 410,
      });
    await expect(seal.open("page", [], legacy)).rejects.toMatchObject({
      code: "invalid_cursor",
    });
  });
});
