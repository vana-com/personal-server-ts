import { describe, expect, it } from "vitest";
import { openBatchBody } from "./stream-sync-batch-body.js";

const enc = new TextEncoder();

async function* chunked(text: string, size: number) {
  const bytes = enc.encode(text);
  for (let at = 0; at < bytes.length; at += size) {
    yield bytes.subarray(at, at + size);
  }
}

async function read(text: string, size: number) {
  const open = await openBatchBody(chunked(text, size), 1 << 30);
  const records: unknown[] = [];
  for await (const r of open.records) records.push(r);
  return { batch: open.batch, records };
}

const RECORDS = [
  { stream: "s", data: { id: "a", t: 'q"uo\\te}]{[,', u: "é日本\u{1F600}" } },
  { stream: "s", op: "delete", data: { id: ["x", { y: [1, 2, {}] }] } },
  { stream: "s", data: {} },
];

describe("openBatchBody", () => {
  it.each([1, 2, 3, 7, 64, 1 << 20])(
    "reads batch and records at chunk size %i",
    async (size) => {
      const text = JSON.stringify({ batch: 4, records: RECORDS });
      expect(await read(text, size)).toEqual({ batch: 4, records: RECORDS });
    },
  );

  it.each([1, 5])(
    "accepts records before batch, spaces and extra members (chunk %i)",
    async (size) => {
      const text = ` { "note" : {"a":[1]} , "records" : [ ${RECORDS.map((r) => JSON.stringify(r)).join(" , ")} ] , "batch" : 9 } `;
      expect(await read(text, size)).toEqual({ batch: 9, records: RECORDS });
    },
  );

  it("reads an empty records array", async () => {
    expect(await read('{"batch":0,"records":[]}', 3)).toEqual({
      batch: 0,
      records: [],
    });
  });

  it.each([
    "",
    "[]",
    "{",
    '{"batch":0}',
    '{"records":[]}',
    '{"batch":0,"records":[1,]}',
    '{"batch":0,"records":[1 }',
    '{"batch":0,"records":{}}',
    '{"batch":0,"records":[]}x',
    '{"batch":]}',
    '{"batch":0,"records":[],"records":[1]}',
  ])("refuses %j", async (text) => {
    await expect(read(text, 4)).rejects.toMatchObject({
      code: "invalid_request",
    });
  });

  it("refuses a body over the limit while reading", async () => {
    const text = JSON.stringify({ batch: 0, records: RECORDS });
    const open = await openBatchBody(chunked(text, 8), text.length - 1);
    await expect(
      (async () => {
        for await (const r of open.records) void r;
      })(),
    ).rejects.toMatchObject({ code: "invalid_request" });
  });
});
