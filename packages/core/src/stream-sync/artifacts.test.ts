import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { DeclarationSnapshot } from "../pdpp/types.js";
import {
  artifactResolver,
  documentDigest,
  manifestArtifact,
  manifestArtifactResolver,
  retainedArtifactResolver,
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

describe("retainedArtifactResolver", () => {
  const snapshot = {
    source_id: "github",
    source_kind: "connector",
    version: "0.5.1",
    digest: "x",
    streams: [
      {
        name: "user",
        semantics: "mutable_state",
        primary_key: ["id"],
        consent_time_field: "updated_at",
      },
    ],
  } as unknown as DeclarationSnapshot;

  it("binds each retained document to the connector key the host names", async () => {
    const resolve = retainedArtifactResolver(
      [snapshot],
      new Map([["github", "doc-bytes"]]),
      () => "github-browser",
    );
    expect(await resolve(`sha256:${sha("doc-bytes")}`)).toEqual({
      connector: "github-browser",
      version: "0.5.1",
      streams: [
        {
          name: "user",
          semantics: "mutable_state",
          primaryKey: ["id"],
          consentTimeField: "updated_at",
        },
      ],
    });
  });

  it("leaves a source with no document or no connector key unresolvable", async () => {
    const noKey = retainedArtifactResolver(
      [snapshot],
      new Map([["github", "doc-bytes"]]),
      () => null,
    );
    expect(await noKey(`sha256:${sha("doc-bytes")}`)).toBeNull();
    const noDocument = retainedArtifactResolver(
      [snapshot],
      new Map(),
      () => "github",
    );
    expect(await noDocument(`sha256:${sha("")}`)).toBeNull();
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
