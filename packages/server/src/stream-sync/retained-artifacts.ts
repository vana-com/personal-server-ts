/**
 * Resolve a run's `artifactDigest` on the full server (run-intake contract
 * v2 §6). The table holds only retained declarations whose document bytes
 * this boot hashed itself: a digest the producer sends matches the sha256 of
 * the retained document, so no producer can name keys for a document the
 * server did not verify.
 */

import { createHash } from "node:crypto";
import type { DeclarationSnapshot } from "@opendatalabs/personal-server-ts-core/pdpp";
import type {
  IntakeDeclarations,
  ResolveArtifact,
} from "@opendatalabs/personal-server-ts-core/stream-sync";

export function retainedArtifactResolver(
  snapshots: readonly DeclarationSnapshot[],
  documents: ReadonlyMap<string, string>,
): ResolveArtifact {
  const table = new Map<string, IntakeDeclarations>();
  for (const snapshot of snapshots) {
    const document = documents.get(snapshot.source_id);
    if (document === undefined) continue;
    const digest = createHash("sha256").update(document, "utf8").digest("hex");
    table.set(digest, {
      version: snapshot.version,
      streams: snapshot.streams.map((stream) => ({
        name: stream.name,
        semantics: stream.semantics ?? "mutable_state",
        primaryKey: stream.primary_key,
        ...((stream as { incremental?: boolean }).incremental === false
          ? { incremental: false }
          : {}),
        ...(stream.consent_time_field
          ? { consentTimeField: stream.consent_time_field }
          : {}),
      })),
    });
  }
  return (digest) =>
    table.get(digest.replace(/^sha256:/, "").toLowerCase()) ?? null;
}
