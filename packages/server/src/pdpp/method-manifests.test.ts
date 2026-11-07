import { createHash } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { manifestArtifactResolver } from "@opendatalabs/personal-server-ts-core/stream-sync";
import { streamScope } from "@opendatalabs/personal-server-ts-stream-sync";
import { readMethodManifests } from "./bootstrap.js";

const MANIFEST = JSON.stringify({
  connector_id: "https://registry.pdpp.dev/connectors/github-browser",
  connector_key: "github-browser",
  version: "0.3.18",
  streams: [
    { name: "profile", semantics: "mutable_state", primary_key: ["id"] },
    { name: "repositories", semantics: "mutable_state", primary_key: ["id"] },
  ],
});
const sha = (text: string) =>
  createHash("sha256").update(text, "utf8").digest("hex");

let dir: string;
const logger = { warn: vi.fn() };
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "method-manifests-"));
  logger.warn.mockClear();
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

async function write(name: string, text: string): Promise<string> {
  await mkdir(dir, { recursive: true });
  const path = join(dir, name);
  await writeFile(path, text, "utf8");
  return path;
}

async function read(
  method: {
    method_id: string;
    manifest_path?: string;
    manifest_sha256?: string;
  },
  retained = true,
) {
  const declaration_path = join(dir, "declaration.json");
  return readMethodManifests(
    [{ declaration_path, ...method }],
    new Set(retained ? [resolve(declaration_path)] : []),
    logger as never,
  );
}

describe("readMethodManifests", () => {
  it("keeps a manifest whose bytes match its pin and whose key is the method id", async () => {
    const manifest_path = await write("m.json", MANIFEST);
    expect(
      await read({
        method_id: "github-browser",
        manifest_path,
        manifest_sha256: sha(MANIFEST),
      }),
    ).toEqual([MANIFEST]);
    expect(logger.warn).not.toHaveBeenCalled();
  });

  it("gives the full server and PS-Lite the same key and the same physical scope", async () => {
    const manifest_path = await write("m.json", MANIFEST);
    const [pinned] = await read({
      method_id: "github-browser",
      manifest_path,
      manifest_sha256: sha(MANIFEST),
    });
    const digest = `sha256:${sha(MANIFEST)}`;
    const fullServer = await manifestArtifactResolver([pinned!])(digest);
    const lite = await manifestArtifactResolver([MANIFEST])(digest);
    expect(fullServer).toEqual(lite);
    expect(fullServer?.connector).toBe("github-browser");
    const scopes = (declared: typeof lite) =>
      declared?.streams.map((s) => streamScope(declared.connector, "", s.name));
    expect(scopes(fullServer)).toEqual(scopes(lite));
    expect(scopes(fullServer)).toEqual([
      "pdpp.github-browser~.profile",
      "pdpp.github-browser~.repositories",
    ]);
  });

  it.each([
    ["no pinned manifest", {}, "manifest_missing"],
    [
      "an unreadable path",
      { manifest_path: "/nonexistent/m.json", manifest_sha256: sha(MANIFEST) },
      "manifest_unreadable",
    ],
  ])(
    "leaves a method with %s legacy-only and says why",
    async (_n, pin, reason) => {
      expect(await read({ method_id: "github-browser", ...pin })).toEqual([]);
      expect(logger.warn).toHaveBeenCalledTimes(1);
      expect(logger.warn.mock.calls[0]![0]).toEqual({
        methodId: "github-browser",
        reason,
      });
    },
  );

  it("refuses bytes that differ from the pin", async () => {
    const manifest_path = await write("m.json", `${MANIFEST} `);
    expect(
      await read({
        method_id: "github-browser",
        manifest_path,
        manifest_sha256: sha(MANIFEST),
      }),
    ).toEqual([]);
    expect(logger.warn.mock.calls[0]![0].reason).toBe(
      "manifest_digest_mismatch",
    );
  });

  it("never falls back to another name when the manifest key is not the method id", async () => {
    const manifest_path = await write("m.json", MANIFEST);
    expect(
      await read({
        method_id: "github",
        manifest_path,
        manifest_sha256: sha(MANIFEST),
      }),
    ).toEqual([]);
    expect(logger.warn.mock.calls[0]![0].reason).toBe("manifest_key_mismatch");
  });

  it("ignores a method whose declaration was not retained", async () => {
    const manifest_path = await write("m.json", MANIFEST);
    expect(
      await read(
        {
          method_id: "github-browser",
          manifest_path,
          manifest_sha256: sha(MANIFEST),
        },
        false,
      ),
    ).toEqual([]);
    expect(logger.warn).not.toHaveBeenCalled();
  });
});
