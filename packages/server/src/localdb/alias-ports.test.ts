import { describe, expect, it, vi } from "vitest";
import {
  LEGACY_SCOPE_BINDINGS,
  legacyAliasScopes,
} from "@opendatalabs/personal-server-ts-core/legacy-projection";
import { createServerLocalSync } from "./sync.js";

const build = vi.hoisted(() =>
  vi.fn<
    (
      deps: unknown,
      options: {
        aliasScopes: () => Iterable<string>;
        aliasTargets: unknown;
      },
    ) => unknown
  >(() => ({})),
);
vi.mock("@opendatalabs/personal-server-ts-core/localdb", () => ({
  createLocalSync: build,
}));

describe("server alias ports", () => {
  it("supplies fresh catalogue iterators and keeps projection knowledge on the host side", () => {
    createServerLocalSync({} as never, {
      resolveArtifact: () => null,
      declaredStreams: () => [],
      olderVersionReads: () => false,
    });
    const { aliasScopes, aliasTargets } = build.mock.calls[0][1];
    expect([...aliasScopes()]).toEqual([...LEGACY_SCOPE_BINDINGS.keys()]);
    expect([...aliasScopes()]).toEqual([...LEGACY_SCOPE_BINDINGS.keys()]);
    expect(aliasTargets).toBe(legacyAliasScopes);
  });
});
