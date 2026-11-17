import { afterEach, describe, expect, it, vi } from "vitest";
import { Buffer as NodeBuffer } from "node:buffer";
import { Buffer as BrowserBuffer } from "buffer/";
import {
  encodeBase64Url,
  decodeBase64Url,
  encodeBase64UrlUtf8,
  decodeBase64UrlUtf8,
} from "./base64url.js";
import {
  createRecordQuery,
  listCursor,
  type RecordQuery,
} from "../localdb/query.js";
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
    " \t\r\n",
    "WyJrIiwiaCJd\n",
    " Z m9\tv\r\n",
    "Z#m!9@v$",
    "Zg====",
    "Zg=Zm9v",
    "Z",
    "Zm9vZ",
    "Zm9vZ \n",
    "-__v",
  ])("matches Node's forgiving decoder for %j", (input) => {
    vi.stubGlobal("Buffer", BrowserBuffer);
    expect(decodeBase64Url(input)).toEqual(
      new Uint8Array(NodeBuffer.from(input, "base64url")),
    );
  });

  it("resumes after the original key and hash through both cursor consumers", async () => {
    const cursor = new URL(
      "https://example.test/?cursor=v2.WyJrIiwiaCJd%0A",
    ).searchParams.get("cursor")!;
    const multiCursor =
      NodeBuffer.from(
        JSON.stringify({
          kind: "local-records",
          stream: "posts",
          instances: ["a", "b"],
          after: [cursor, null],
        }),
      ).toString("base64url") + "\n";
    const read = vi.fn(async () => []);
    const query = createRecordQuery({ query: read });
    vi.stubGlobal("Buffer", BrowserBuffer);
    await query.listRecords({
      connectionId: "a",
      stream: "posts",
      cursor,
      limit: 2,
    });
    const after = localListCursors(multiCursor, "posts", ["a", "b"]);
    expect(after).toEqual([cursor, undefined]);
    await query.listRecords({
      connectionId: "a",
      stream: "posts",
      cursor: after[0],
      limit: 2,
    });
    expect(read).toHaveBeenCalledTimes(2);
    for (const call of read.mock.calls) {
      expect(call).toEqual([
        expect.stringContaining("AND (record_key, pk_hash) > (?, ?)"),
        ["a", "posts", "k", "h", 3],
      ]);
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
