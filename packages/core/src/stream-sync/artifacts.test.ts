import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  artifactResolver,
  documentDigest,
  manifestArtifact,
  manifestArtifactResolver,
} from "./artifacts.js";

const MANIFEST = JSON.stringify({
  connector_key: "github-browser",
  version: "0.3.18",
  streams: [
    { name: "profile", semantics: "mutable_state", primary_key: ["id"] },
    {
      name: "events",
      semantics: "append_only",
      primary_key: ["id", "kind"],
      incremental: false,
    },
  ],
});

const sha = (text: string) =>
  createHash("sha256").update(text, "utf8").digest("hex");

describe("documentDigest", () => {
  it("is the sha-256 of the UTF-8 bytes", () => {
    expect(documentDigest(MANIFEST)).toBe(sha(MANIFEST));
    expect(documentDigest("é")).toBe(sha("é"));
  });
});

describe("manifestArtifactResolver", () => {
  it("resolves the digest of the document bytes, with or without sha256:", async () => {
    const resolve = manifestArtifactResolver([MANIFEST]);
    const expected = {
      connector: "github-browser",
      version: "0.3.18",
      streams: [
        { name: "profile", semantics: "mutable_state", primaryKey: ["id"] },
        {
          name: "events",
          semantics: "append_only",
          primaryKey: ["id", "kind"],
          incremental: false,
        },
      ],
    };
    expect(await resolve(`sha256:${sha(MANIFEST)}`)).toEqual(expected);
    expect(await resolve(sha(MANIFEST).toUpperCase())).toEqual(expected);
  });

  it("takes the connector key from the manifest bytes, never from a host", async () => {
    const other = JSON.stringify({
      ...JSON.parse(MANIFEST),
      connector_key: "github-api",
    });
    const resolve = manifestArtifactResolver([MANIFEST, other]);
    expect((await resolve(sha(MANIFEST)))?.connector).toBe("github-browser");
    expect((await resolve(sha(other)))?.connector).toBe("github-api");
  });

  it("leaves a manifest with no connector key unresolvable", async () => {
    const { connector_key: _dropped, ...keyless } = JSON.parse(MANIFEST);
    const document = JSON.stringify(keyless);
    const resolve = manifestArtifactResolver([document]);
    expect(await resolve(sha(document))).toBeNull();
  });

  it("does not resolve bytes that differ or a digest nobody verified", async () => {
    const resolve = manifestArtifactResolver([MANIFEST]);
    expect(await resolve(`sha256:${sha(`${MANIFEST} `)}`)).toBeNull();
    expect(await resolve(`sha256:${"00".repeat(32)}`)).toBeNull();
  });

  it("drops a malformed document instead of guessing", () => {
    const bad = [
      "not json",
      "[]",
      JSON.stringify({ connector_key: "a~b", version: "1", streams: [] }),
      JSON.stringify({
        version: "1",
        streams: [{ name: "s", primary_key: ["id"] }],
      }),
      JSON.stringify({ connector_key: "a", version: "1", streams: [] }),
      JSON.stringify({
        connector_key: "a",
        version: "1",
        streams: [{ name: "s", primary_key: [] }],
      }),
      JSON.stringify({
        connector_key: "a",
        version: "1",
        streams: [
          { name: "s", primary_key: ["id"] },
          { name: "s", primary_key: ["id"] },
        ],
      }),
      JSON.stringify({
        connector_key: "a",
        version: "1",
        streams: [{ name: "s", semantics: "wild", primary_key: ["id"] }],
      }),
    ];
    for (const document of bad) expect(manifestArtifact(document)).toBeNull();
  });
});

describe("artifactResolver", () => {
  it("keys the table by the hash it computes, never by a producer value", async () => {
    const resolve = artifactResolver([
      {
        document: "one",
        declarations: { connector: "c", version: "1", streams: [] },
      },
    ]);
    expect(await resolve(sha("one"))).not.toBeNull();
    expect(await resolve("one")).toBeNull();
  });
});
