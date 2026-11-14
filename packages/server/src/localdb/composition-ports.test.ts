import { beforeEach, expect, it, vi } from "vitest";
import { readFileSync, readdirSync } from "node:fs";

const ports = vi.hoisted(() => ({
  build: vi.fn(),
  aliases: vi.fn(),
  bindings: new Map([
    [
      "fixture.summary",
      {
        pdppSource: "https://fixture.invalid/source",
        pdppStreams: ["items"],
        primaryKey: { items: ["id"] },
        rowOrder: "arrival" as const,
      },
    ],
  ]),
}));
vi.mock("@opendatalabs/personal-server-ts-core/localdb", () => ({
  createLocalSync: ports.build,
}));
vi.mock(
  "@opendatalabs/personal-server-ts-core/legacy-projection",
  async (original) => ({
    ...(await original<object>()),
    LEGACY_SCOPE_BINDINGS: ports.bindings,
    legacyAliasScopes: ports.aliases,
  }),
);
import {
  aliasScopes,
  createServerLocalSync,
  importProjection,
} from "./sync.js";

beforeEach(() => {
  vi.clearAllMocks();
});

it("composes catalogue and alias ports at the host boundary", () => {
  createServerLocalSync({} as never, {
    resolveArtifact: async () => null,
    declaredStreams: () => [],
    olderVersionReads: () => false,
  });
  const options = ports.build.mock.calls[0]![1];
  expect([...options.aliasScopes()]).toEqual(["fixture.summary"]);
  expect([...aliasScopes()]).toEqual(["fixture.summary"]);
  expect(options.aliasTargets).toBe(ports.aliases);
  expect(importProjection.bindings.get("fixture.summary")).toEqual({
    connector: "source",
    streams: ["items"],
  });
});

it("allows catalogue imports only at the host composition site", () => {
  const directory = new URL("./", import.meta.url);
  const importing = new Set<string>();
  for (const file of readdirSync(directory).filter(
    (name) => name.endsWith(".ts") && !/\.(test|test-utils)\.ts$/.test(name),
  )) {
    const source = readFileSync(new URL(file, directory), "utf8");
    for (const match of source.matchAll(
      /\b(?:from|import|require)\s*(?:\(\s*)?(["'`])([^"'`]+)\1/g,
    )) {
      if (match[2]!.includes("legacy-projection")) importing.add(file);
    }
  }
  // This file constructs the host's frozen ports. No database algorithm may
  // obtain its own catalogue; the existing core guard remains unchanged.
  expect([...importing]).toEqual(["sync.ts"]);
});
