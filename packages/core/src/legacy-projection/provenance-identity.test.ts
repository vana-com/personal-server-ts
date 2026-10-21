import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { LEGACY_SCOPE_BINDINGS } from "./bindings.js";
import type { LegacyScopeBindingProvenance } from "./provenance.js";

/**
 * What a provenance entry may claim about a connector's identity.
 *
 * An `oci` entry names the signed artifact: its digest is the OCI manifest
 * digest, which the registry resolves and the publisher signs. A digest of the
 * generated `collection-profile.json` bytes names one layer of that artifact,
 * so it cannot stand in for the manifest. The vendored `<name>.provenance.json`
 * records every layer digest the build produced, which makes the confusion
 * checkable without contacting a registry.
 */

type BuildProvenance = {
  source: { revision: string };
  outputs: Record<string, string | null>;
};

const DECLARATIONS = new URL("./declarations/", import.meta.url);

function declarationName(path: string): string {
  const match = path.match(
    /^declarations\/([\w.-]+)\.collection-profile\.json/,
  );
  if (!match) throw new Error(`unparseable provenance path: ${path}`);
  return match[1] as string;
}

function buildProvenance(name: string): BuildProvenance | undefined {
  const file = new URL(`${name}.provenance.json`, DECLARATIONS);
  return existsSync(file)
    ? (JSON.parse(readFileSync(file, "utf8")) as BuildProvenance)
    : undefined;
}

function sha256(file: URL): string {
  return `sha256:${createHash("sha256").update(readFileSync(file)).digest("hex")}`;
}

const entries = [...LEGACY_SCOPE_BINDINGS].flatMap(([scope, binding]) =>
  binding.provenance.map((provenance) => ({ scope, provenance })),
);

describe("legacy binding provenance identifies the connector artifact", () => {
  for (const { scope, provenance } of entries) {
    if (provenance.kind !== "oci") continue;
    it(`${scope}: an oci digest is not the digest of a build output layer`, () => {
      const built = buildProvenance(declarationName(provenance.path));
      // A pin with no vendored build record cannot be checked here; the
      // signed manifest digest has to be verified against the registry.
      if (!built) return;
      const layerNames = Object.entries(built.outputs)
        .filter(([, digest]) => digest === provenance.digest)
        .map(([layer]) => layer);
      expect(
        layerNames,
        `${provenance.ref} cites ${provenance.digest}, which is the digest of its ${layerNames.join(", ")} layer, not an OCI manifest`,
      ).toEqual([]);
    });
  }

  it("Whole Foods names the vendored profile bytes, not a published artifact", () => {
    const built = buildProvenance("wholefoods");
    expect(built).toBeDefined();
    const profile = sha256(
      new URL("wholefoods.collection-profile.json", DECLARATIONS),
    );
    expect(profile).toBe(built?.outputs["collection-profile.json"]);

    const cited = new Set<string>();
    for (const scope of [
      "wholefoods.profile",
      "wholefoods.orders",
      "wholefoods.nutrition",
    ]) {
      const [only, ...rest] =
        LEGACY_SCOPE_BINDINGS.get(scope)?.provenance ?? [];
      expect(rest, scope).toEqual([]);
      const provenance = only as LegacyScopeBindingProvenance;
      expect(provenance.kind, scope).toBe("collection-profile");
      if (provenance.kind !== "collection-profile") continue;
      expect(provenance.digest, scope).toBe(profile);
      // The ref locates the exact data-connectors source the profile was
      // built from, so the pin survives a re-pushed tag.
      expect(provenance.ref, scope).toBe(
        `https://github.com/PDP-Connect/data-connectors/tree/${built?.source.revision}/connectors/wholefoods`,
      );
      cited.add(provenance.digest);
    }
    expect(cited.size).toBe(1);
  });
});
