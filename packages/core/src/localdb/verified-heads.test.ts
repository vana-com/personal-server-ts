import { describe, expect, it } from "vitest";
import {
  HEAD_FORMAT,
  type Head,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { createMemoryStreamSyncBlobs } from "../stream-sync/index.js";
import { recallHead, rememberHead, rememberOwnHead } from "./verified-heads.js";

const SCOPE = "pdpp.c~ns~s";
const HASH = `0x${"ab".repeat(32)}`;

function head(): Head {
  return {
    complete: false,
    connector: "c",
    format: HEAD_FORMAT,
    generation: 1,
    keyCheck: "k1",
    lastDeleteVersion: 0,
    ns: "ns",
    observedAt: 1,
    parts: [{ hash: "h", bytes: 1, count: 1, prefix: "" }],
    primaryKey: ["id"],
    profile: { key: "c", version: "1.0.0" },
    recordCount: 1,
    stream: "s",
  } as Head;
}

const port = () => ({ blobs: createMemoryStreamSyncBlobs() });

describe("verified head cache", () => {
  it("is keyed by blob port, hash (any case) and key check", () => {
    const a = port();
    rememberOwnHead(a, SCOPE, HASH, "k1", head());
    expect(
      recallHead(a, SCOPE, HASH.toUpperCase().replace("0X", "0x"), "k1"),
    ).toEqual(head());
    expect(recallHead(a, SCOPE, HASH, "k2")).toBeUndefined();
    expect(recallHead(a, `${SCOPE}2`, HASH, "k1")).toBeUndefined();
    expect(recallHead(port(), SCOPE, HASH, "k1")).toBeUndefined();
  });

  it("holds a deep frozen copy: neither the caller's object nor the cache can change the other", () => {
    const own = head();
    const cache = port();
    rememberOwnHead(cache, SCOPE, HASH, "k1", own);
    own.parts[0]!.count = 99;
    (own.primaryKey as string[]).push("x");
    const held = recallHead(cache, SCOPE, HASH, "k1")!;
    expect(held).toEqual(head());
    expect(() => {
      (held.parts[0] as { count: number }).count = 5;
    }).toThrow(TypeError);
    expect(() => (held.primaryKey as string[]).push("y")).toThrow(TypeError);
    expect(() => {
      (held as { generation: number }).generation = 9;
    }).toThrow(TypeError);
    expect(recallHead(cache, SCOPE, HASH, "k1")).toEqual(head());
  });

  it("keeps the 512 most recently remembered heads", () => {
    const cache = port();
    for (let i = 0; i < 513; i++)
      rememberHead(
        cache,
        SCOPE,
        `0x${i.toString(16).padStart(64, "0")}`,
        "k1",
        head(),
      );
    expect(
      recallHead(cache, SCOPE, `0x${(0).toString(16).padStart(64, "0")}`, "k1"),
    ).toBeUndefined();
    expect(
      recallHead(cache, SCOPE, `0x${(1).toString(16).padStart(64, "0")}`, "k1"),
    ).toBeDefined();
    expect(
      recallHead(
        cache,
        SCOPE,
        `0x${(512).toString(16).padStart(64, "0")}`,
        "k1",
      ),
    ).toBeDefined();
  });
});
