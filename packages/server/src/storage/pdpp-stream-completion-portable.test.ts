import { createHash, webcrypto } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import {
  encodeLiveSnapshotDigestInput,
  liveSnapshotDigestAsync,
  parseCompletionRequest as portableParser,
  StreamCompletionError as PortableCompletionError,
  type LiveSnapshotRow,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records/completion";
import { createRecordDataValidator as portableValidator } from "@opendatalabs/personal-server-ts-core/storage/pdpp-records/schema";
import { createRecordDataValidator } from "../pdpp/record-schema.js";
import {
  liveSnapshotDigest,
  parseCompletionRequest,
  StreamCompletionError,
} from "./pdpp-stream-completion.js";

const identity = {
  sourceId: "source",
  instance: "connection",
  method: "collector",
  generation: 1,
  stream: "items",
};
const row = (recordKey: string, data: unknown): LiveSnapshotRow => ({
  recordKey,
  dataJson: JSON.stringify(data),
});

// Preimages are independent literal vectors. Hex values were captured from
// the original synchronous server implementation before extraction.
const vectors = [
  {
    name: "empty stream",
    primaryKey: ["id"],
    rows: [],
    pairs: "[]",
    hex: "1fe3fd277e56989f8dd985771dd599cc8333f409ba4dd43e4d30c3a5b79da0c8",
  },
  {
    name: "compound keys",
    primaryKey: ["a", "b"],
    rows: [row('["x","y"]', { b: "y", a: "x" })],
    pairs: '[["[\\"x\\",\\"y\\"]",{"a":"x","b":"y"}]]',
    hex: "04b114dd98b1728ad3a04e3d42b7e411c4bf626594941953d0bebe4c150fb8bd",
  },
  {
    name: "Unicode UTF-16 ordering without normalization",
    primaryKey: ["id"],
    rows: ["\uE000", "😀", "é", "é", "a"].map((id) => row(id, { id })),
    pairs:
      '[["a",{"id":"a"}],["é",{"id":"é"}],["é",{"id":"é"}],["😀",{"id":"😀"}],["\uE000",{"id":"\uE000"}]]',
    hex: "8806edb8be52f2e44426ae5743f12a7b547b76adf7a39aa1f890cecb617fef70",
  },
  {
    name: "numeric-looking keys and object properties",
    primaryKey: ["id"],
    rows: [
      row("9", { id: "9" }),
      row("10", { id: "10", "10": "ten", "2": "two", "01": "one" }),
      row("2", { id: "2" }),
    ],
    pairs:
      '[["10",{"2":"two","10":"ten","01":"one","id":"10"}],["2",{"id":"2"}],["9",{"id":"9"}]]',
    hex: "1552f4755984673633921603b3de64ba4d2f9e1c30a542aff4c1d541dbf2e5b7",
  },
];

describe("portable completion compatibility", () => {
  it.each(vectors)(
    "preserves bytes and Node/Web Crypto hashes for $name",
    async ({ primaryKey, rows, pairs, hex }) => {
      const expectedBytes = new TextEncoder().encode(
        `["source","connection","collector",1,"items",${pairs}]`,
      );
      const bytes = encodeLiveSnapshotDigestInput(identity, primaryKey, rows);
      expect(bytes).toEqual(expectedBytes);
      const nodeBytes = new Uint8Array(
        createHash("sha256").update(bytes).digest(),
      );
      const webBytes = new Uint8Array(
        await webcrypto.subtle.digest("SHA-256", bytes),
      );
      expect(nodeBytes).toEqual(webBytes);
      expect(liveSnapshotDigest(identity, primaryKey, rows)).toBe(hex);
      await expect(
        liveSnapshotDigestAsync(identity, primaryKey, rows),
      ).resolves.toBe(hex);
      const nodeSha256 = vi.fn(
        async (input: Uint8Array) =>
          new Uint8Array(createHash("sha256").update(input).digest()),
      );
      await expect(
        liveSnapshotDigestAsync(identity, primaryKey, rows, nodeSha256),
      ).resolves.toBe(hex);
      expect(nodeSha256).toHaveBeenCalledExactlyOnceWith(expectedBytes);
    },
  );

  it.each([
    { name: "malformed JSON", rows: [{ recordKey: "x", dataJson: "{" }] },
    {
      name: "duplicate record keys",
      rows: [row("x", { id: "x" }), row("x", { id: "x" })],
    },
    { name: "key/data disagreement", rows: [row("x", { id: "y" })] },
    { name: "non-object data", rows: [row("x", [])] },
    { name: "lone surrogate", rows: [row("x", { id: "x", text: "\uD800" })] },
  ])("rejects $name before invoking SHA-256", async ({ rows }) => {
    const sha256 = vi.fn();
    expect(() => liveSnapshotDigest(identity, ["id"], rows)).toThrow(
      expect.objectContaining({ reason: "invalid_snapshot_data" }),
    );
    await expect(
      liveSnapshotDigestAsync(identity, ["id"], rows, sha256),
    ).rejects.toThrow(
      expect.objectContaining({ reason: "invalid_snapshot_data" }),
    );
    expect(sha256).not.toHaveBeenCalled();
  });

  it("keeps server parsers, error classes and schema validators as the same exports", () => {
    expect(parseCompletionRequest).toBe(portableParser);
    expect(StreamCompletionError).toBe(PortableCompletionError);
    expect(createRecordDataValidator).toBe(portableValidator);
  });
});
