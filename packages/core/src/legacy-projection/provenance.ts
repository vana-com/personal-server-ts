/**
 * Evidence provenance for a legacy-scope binding. No entry in the binding
 * table may omit this — an entry with no resolvable provenance is a gap,
 * per the brief, not a binding.
 *
 * - "oci": pulled live from ghcr.io/pdp-connect/connector/<name> via
 *   `oras pull`. `ref` is the OCI tag (human-readable, mutable); `digest` is
 *   the manifest digest captured at the same pull (`oras manifest fetch
 *   --descriptor`), the immutable pin a tag can be re-pushed away from. The
 *   connector-provenance.json digest inside that artifact (vendored
 *   alongside the collection-profile.json in
 *   ./declarations/<name>.provenance.json) names the exact data-connectors
 *   commit the artifact was built from.
 * - "ps-fixture": vendored from vana-com/personal-server-ts test fixtures.
 *   These fixtures are themselves *copies of this repo's own prior output*
 *   (see declarations/README — PROVENANCE.md at the cited commit says so
 *   explicitly: producer repo unity-surfaces, PR #1098, commit bccc682e).
 *   Treat as corroboration of this repo's own history, not independent
 *   upstream confirmation.
 * - "retired-descriptor": content from a data-connectors commit that has
 *   since been deleted upstream (PR #123, 2026-09-16, "retire the
 *   tarball-era PDPP Collection Profile descriptors"). Still real history,
 *   cited with its real hash, but not resolvable at HEAD and superseded by
 *   the OCI artifact path.
 * - "collection-profile": immutable digest of the generated collection
 *   profile output. This pins the declaration bytes when the OCI manifest
 *   digest is not present in this checkout; it does not claim Desktop has
 *   admitted the connector or verified its signature at runtime.
 * - "source-manifest": vendored source manifest bytes from an unpublished
 *   source worktree. The digest pins this adapter input but does not establish
 *   a published, signed collection profile.
 */
export type LegacyScopeBindingProvenance =
  | { digest: string; kind: "oci"; path: string; ref: string }
  | { digest: string; kind: "collection-profile"; path: string; ref: string }
  | { digest: string; kind: "source-manifest"; path: string; ref: string }
  | { kind: "ps-fixture"; path: string; ref: string }
  | { kind: "retired-descriptor"; path: string; ref: string };
