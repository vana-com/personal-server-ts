import { expect, it } from "vitest";
import {
  encodeSegment,
  LOG_FORMAT,
  type LogOperation,
  type WireOperation,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { operationBytes, publishedOperationBytes } from "./log-replacement.js";
import { putBodiesOutOfLine } from "./log-bodies.js";

it("counts the existing wire encoder exactly for escaped, Unicode, and reference bodies", async () => {
  const operations: LogOperation[] = [];
  for (let seed = 0; seed < 30; seed++) {
    const common = {
      stream: 's\\"雪',
      pkHash: "a".repeat(64),
      stamp: { o: 1000 + seed, r: 'r\\"雪' },
    };
    operations.push({
      kind: "upsert",
      ...common,
      firstSeen: seed % 2 ? null : 2,
      ordinal: seed,
      value: { id: seed, text: '\\"\n雪😀'.repeat(seed * 30) },
    });
    operations.push({ kind: "delete", ...common, key: [seed, '\\"雪'] });
    operations.push({
      kind: "complete",
      stream: common.stream,
      cutoff: common.stamp,
      omitted: [{ pkHash: common.pkHash, key: [seed, '\\"雪'] }],
    });
  }
  const envelope = (ops: readonly WireOperation[]) =>
    encodeSegment({
      format: LOG_FORMAT,
      connector: "test",
      ns: "",
      generation: 1,
      keyCheck: "0".repeat(16),
      position: 1,
      observedAt: 1,
      base: 0,
      snapshot: null,
      refs: [],
      streams: [
        {
          stream: 's\\"雪',
          primaryKey: ["id"],
          profile: { key: "test", version: "1" },
          complete: true,
        },
      ],
      operations: ops,
    });
  for (const op of operations) {
    const result = await putBodiesOutOfLine(
      { keys: { encryptPart: async (_s, b) => b } as never },
      "scope",
      [op],
      1024,
    );
    const actual = result.ops as WireOperation[];
    expect(publishedOperationBytes(op, 1024)).toBe(
      envelope(actual).length - envelope([]).length,
    );
    expect(operationBytes(op)).toBe(
      envelope([op]).length - envelope([]).length,
    );
  }
});
