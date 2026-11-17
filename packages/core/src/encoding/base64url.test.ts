import { afterEach, describe, expect, it, vi } from "vitest";
import { Buffer as NodeBuffer } from "node:buffer";
import { Buffer as BrowserBuffer } from "buffer/";
import {
  encodeBase64Url,
  decodeBase64Url,
  encodeBase64UrlUtf8,
  decodeBase64UrlUtf8,
} from "./base64url.js";
import { listCursor, type RecordQuery } from "../localdb/query.js";
import { parseRecordQuery } from "../api/pdpp-record-query.js";
import { localListCursors, localRecordPage } from "../api/pdpp-records-list.js";

afterEach(() => vi.unstubAllGlobals());

describe("portable base64url", () => {
  it("matches Node for arbitrary bytes and every padding length", () => {
    vi.stubGlobal("Buffer", BrowserBuffer);
    for (let length = 0; length <= 260; length++) {
      const bytes = Uint8Array.from(
        { length },
        (_, i) => (i * 73 + length) % 256,
      );
      const encoded = encodeBase64Url(bytes);
      expect(encoded).toBe(NodeBuffer.from(bytes).toString("base64url"));
      expect(decodeBase64Url(encoded)).toEqual(bytes);
      expect(
        decodeBase64Url(NodeBuffer.from(bytes).toString("base64")),
      ).toEqual(bytes);
    }
  });

  it.each([
    "",
    "a",
    "ab",
    "abc",
    "abcd",
    "café 中文 🌍",
    "\u0000\ufeff",
    "\ufeffleading BOM",
  ])("round-trips UTF-8 %j", (text) => {
    expect(encodeBase64UrlUtf8(text)).toBe(
      NodeBuffer.from(text).toString("base64url"),
    );
    expect(decodeBase64UrlUtf8(encodeBase64UrlUtf8(text))).toBe(text);
  });

  it("keeps issued list and multi-instance cursors byte-identical under the browser shim", () => {
    const oldList =
      "v2." +
      NodeBuffer.from(JSON.stringify(["中文", "hash"])).toString("base64url");
    const oldMulti = NodeBuffer.from(
      JSON.stringify({
        kind: "local-records",
        stream: "posts",
        instances: ["a", "b"],
        after: [oldList, null],
      }),
    ).toString("base64url");
    vi.stubGlobal("Buffer", BrowserBuffer);
    expect(listCursor("中文", "hash")).toBe(oldList);
    expect(localListCursors(oldMulti, "posts", ["a", "b"])).toEqual([
      oldList,
      undefined,
    ]);
  });
  it("orders merged pages by UTF-8 bytes and emits a compatible multi-instance cursor", async () => {
    const keys = { a: "𐀀", b: "\ue000", c: "a" };
    const query: RecordQuery = {
      listRecords: async ({ connectionId }) => ({
        records: [
          {
            stream: "posts",
            recordKey: keys[connectionId as keyof typeof keys],
            pkHash: "hash",
            body: "{}",
            emittedAt: 0,
          },
        ],
        nextCursor: null,
      }),
      getRecord: vi.fn(),
      changesSince: vi.fn(),
      streamRecords: vi.fn(),
    };
    vi.stubGlobal("Buffer", BrowserBuffer);
    const page = await localRecordPage(
      query,
      "posts",
      ["a", "b", "c"],
      parseRecordQuery("https://example.test/?limit=2", "listRecords"),
      undefined,
      true,
      undefined,
      false,
      undefined,
    );
    expect(page.data.map((row) => row.recordKey)).toEqual(["a", "\ue000"]);
    expect(page.hasMore).toBe(true);
    const after = [null, listCursor("\ue000", "hash"), listCursor("a", "hash")];
    const oldEncoded = NodeBuffer.from(
      JSON.stringify({
        kind: "local-records",
        stream: "posts",
        instances: ["a", "b", "c"],
        after,
      }),
    ).toString("base64url");
    expect(page.nextCursor).toBe(oldEncoded);
    expect(localListCursors(oldEncoded, "posts", ["a", "b", "c"])).toEqual([
      undefined,
      after[1],
      after[2],
    ]);
  });
});
