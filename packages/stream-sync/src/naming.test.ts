import { describe, expect, it } from "vitest";
import { filesOfConnection } from "./connection-files.js";
import { InvalidNameError } from "./errors.js";
import { placeholderNaming } from "./naming.js";

const hash = "0123456789abcdef".repeat(4);

describe("placeholder naming", () => {
  const ref = { connectionId: "conn-1", stream: "conversations" };

  it("round-trips the stream key, heads and parts through the parser", () => {
    expect(placeholderNaming.parse(placeholderNaming.streamName(ref))).toEqual({
      kind: "stream",
      ...ref,
    });
    expect(
      placeholderNaming.parse(placeholderNaming.headName(ref, hash)),
    ).toEqual({ kind: "head", ...ref, hash });
    expect(
      placeholderNaming.parse(placeholderNaming.partName(ref, hash)),
    ).toEqual({ kind: "part", ...ref, hash });
  });

  it("names a head by its own hash, never by the fixed stream name", () => {
    const name = placeholderNaming.headName(ref, hash);
    expect(name).not.toBe(placeholderNaming.streamName(ref));
    expect(name.endsWith(hash)).toBe(true);
    expect(placeholderNaming.headName(ref, "f".repeat(64))).not.toBe(name);
  });

  it("refuses to build names from segments with dots or empty segments", () => {
    expect(() =>
      placeholderNaming.streamName({ connectionId: "a.b", stream: "s" }),
    ).toThrow(InvalidNameError);
    expect(() =>
      placeholderNaming.streamName({ connectionId: "", stream: "s" }),
    ).toThrow(InvalidNameError);
    expect(() => placeholderNaming.partName(ref, "short")).toThrow(
      InvalidNameError,
    );
    expect(() => placeholderNaming.headName(ref, "short")).toThrow(
      InvalidNameError,
    );
  });

  it.each([
    "",
    "pdpp",
    "pdpp.a",
    "pdpp.a.b.c.d",
    "chatgpt.conversations",
    "pdpp..s",
    `pdpp.a.s.part-${hash.toUpperCase()}`,
    `pdpp.a.s.head-${hash.toUpperCase()}`,
    "pdpp.a.s.other",
    `pdpp.a.s.tail-${hash}`,
  ])("does not own %j", (name) => {
    expect(placeholderNaming.parse(name)).toBeNull();
  });
});

describe("filesOfConnection", () => {
  it("does not use the text before the first dot as the connection", () => {
    const names = [
      "pdpp.chatgpt.conversations",
      `pdpp.chatgpt.conversations.head-${hash}`,
      `pdpp.chatgpt.conversations.part-${hash}`,
      "pdpp.notes.entries",
    ];
    expect(filesOfConnection(names, "pdpp")).toEqual([]);
    expect(filesOfConnection(names, "chatgpt")).toEqual(names.slice(0, 3));
  });

  it("takes any naming scheme, so a changed grammar stays local", () => {
    const dashed = {
      streamName: () => "",
      headName: () => "",
      partName: () => "",
      parse: (name: string) => {
        const [connectionId, stream] = name.split("/");
        return stream
          ? { kind: "stream" as const, connectionId: connectionId!, stream }
          : null;
      },
    };
    expect(filesOfConnection(["a/x", "b/y", "a/z"], "a", dashed)).toEqual([
      "a/x",
      "a/z",
    ]);
  });
});
