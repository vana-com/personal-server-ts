/**
 * The one resolver every host uses to turn a run's `artifactDigest` into the
 * stream shapes of a verified connector artifact (run-intake contract v2 §6).
 *
 * A host verifies an artifact and hands over its document bytes. The resolver
 * hashes those bytes itself, so a digest a producer sends matches only a
 * document the host holds, and no producer can name keys for a document the
 * host did not verify. Every host feeds it the connector manifest documents it
 * verified: the full server the ones its operator pinned by digest, PS-Lite the
 * ones its embedding app verified. The connector key is the manifest's own
 * `connector_key`, the signed pin id, so no host names a key and two hosts that
 * verified the same bytes publish under the same physical name.
 */

import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";
import type { KeyFieldType } from "@opendatalabs/personal-server-ts-stream-sync";
import type {
  CoverageStrategy,
  IntakeDeclarations,
  IntakeStreamDeclaration,
  ResolveArtifact,
} from "./intake.js";

/** One verified artifact: its document bytes and what they declare. */
export interface VerifiedArtifact {
  /** The exact bytes the host verified. The resolver hashes them. */
  readonly document: string;
  readonly declarations: IntakeDeclarations;
}

const encoder = new TextEncoder();

export function documentDigest(document: string): string {
  return bytesToHex(sha256(encoder.encode(document)));
}

export function artifactResolver(
  artifacts: Iterable<VerifiedArtifact>,
): ResolveArtifact {
  const table = new Map<string, IntakeDeclarations>();
  for (const artifact of artifacts) {
    table.set(documentDigest(artifact.document), artifact.declarations);
  }
  return (digest) =>
    table.get(digest.replace(/^sha256:/, "").toLowerCase()) ?? null;
}

function isCoverageStrategy(value: unknown): value is CoverageStrategy {
  return [
    "checkpoint_window",
    "full_inventory",
    "parent_detail_accounting",
    "snapshot_import_receipt",
    "singleton_presence",
  ].includes(value as string);
}

interface DeclaredStreamShape {
  readonly name: string;
  readonly semantics?: string;
  readonly primary_key: readonly string[];
  readonly incremental?: unknown;
  readonly coverage_strategy?: CoverageStrategy;
  readonly consent_time_field?: unknown;
  readonly key_types?: readonly (KeyFieldType | null)[];
  readonly state_parents?: readonly string[];
}

function streamDeclaration(
  stream: DeclaredStreamShape,
): IntakeStreamDeclaration {
  return {
    name: stream.name,
    semantics:
      stream.semantics === "append_only" ? "append_only" : "mutable_state",
    primaryKey: stream.primary_key,
    ...(stream.coverage_strategy
      ? { coverageStrategy: stream.coverage_strategy }
      : {}),
    ...(stream.incremental === false ? { incremental: false } : {}),
    ...(stream.key_types?.some((t) => t !== null)
      ? { keyTypes: stream.key_types }
      : {}),
    ...(typeof stream.consent_time_field === "string" &&
    stream.consent_time_field !== ""
      ? { consentTimeField: stream.consent_time_field }
      : {}),
    ...(stream.state_parents?.length
      ? { stateParents: stream.state_parents }
      : {}),
  };
}

/** `state_stream`, then each string of `parent_streams`. Others are ignored. */
function stateParentsOf(stream: Record<string, unknown>): string[] {
  const parents =
    typeof stream.state_stream === "string" ? [stream.state_stream] : [];
  if (Array.isArray(stream.parent_streams))
    for (const parent of stream.parent_streams)
      if (typeof parent === "string") parents.push(parent);
  return parents;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function nonEmptyStrings(value: unknown): value is string[] {
  return (
    Array.isArray(value) &&
    value.length > 0 &&
    value.every((part) => typeof part === "string" && part !== "")
  );
}

const KEY_FIELD_TYPES: readonly string[] = [
  "string",
  "number",
  "integer",
  "boolean",
];

/**
 * The type a stream's embedded schema declares for each primary-key field:
 * one plain type name, else `null` (no schema, no property, a union, or a type
 * the key cannot be).
 */
function keyTypesOf(
  schema: unknown,
  primaryKey: readonly string[],
): (KeyFieldType | null)[] {
  const properties =
    isRecord(schema) && isRecord(schema.properties) ? schema.properties : {};
  return primaryKey.map((field) => {
    const property = properties[field];
    const type = isRecord(property) ? property.type : undefined;
    return typeof type === "string" && KEY_FIELD_TYPES.includes(type)
      ? (type as KeyFieldType)
      : null;
  });
}

/**
 * Read a connector manifest document (`connector_key`, `version`, `streams`
 * with `primary_key`). Anything malformed answers `null`, so a bad document
 * is never resolvable.
 */
export function manifestArtifact(document: string): VerifiedArtifact | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(document);
  } catch {
    return null;
  }
  if (!isRecord(parsed)) return null;
  const { connector_key: connector, version, streams } = parsed;
  if (
    typeof connector !== "string" ||
    connector === "" ||
    connector.includes("~") ||
    typeof version !== "string" ||
    version === "" ||
    !Array.isArray(streams) ||
    streams.length === 0
  ) {
    return null;
  }
  const declared: IntakeStreamDeclaration[] = [];
  const seen = new Set<string>();
  for (const stream of streams) {
    if (
      !isRecord(stream) ||
      typeof stream.name !== "string" ||
      stream.name === "" ||
      seen.has(stream.name) ||
      !nonEmptyStrings(stream.primary_key) ||
      (stream.coverage_strategy !== undefined &&
        !isCoverageStrategy(stream.coverage_strategy)) ||
      (stream.semantics !== undefined &&
        stream.semantics !== "mutable_state" &&
        stream.semantics !== "append_only")
    ) {
      return null;
    }
    seen.add(stream.name);
    declared.push(
      streamDeclaration({
        name: stream.name,
        semantics: stream.semantics,
        primary_key: stream.primary_key,
        incremental: stream.incremental,
        coverage_strategy: stream.coverage_strategy as
          CoverageStrategy | undefined,
        consent_time_field: stream.consent_time_field,
        key_types: keyTypesOf(stream.schema, stream.primary_key),
        state_parents: stateParentsOf(stream),
      }),
    );
  }
  return { document, declarations: { connector, version, streams: declared } };
}

/** The resolver for connector manifest documents a host verified. */
export function manifestArtifactResolver(
  documents: Iterable<string>,
): ResolveArtifact {
  const artifacts: VerifiedArtifact[] = [];
  for (const document of documents) {
    const artifact = manifestArtifact(document);
    if (artifact) artifacts.push(artifact);
  }
  return artifactResolver(artifacts);
}

/**
 * The stream names each connector declares, from the manifest documents a host
 * verified. The connector is the manifest's own `connector_key`, so no caller
 * names a key. A connector with several verified manifest versions yields the
 * union of their streams.
 */
export function manifestStreamLister(
  documents: Iterable<string>,
): (connector: string) => readonly string[] {
  const table = new Map<string, Set<string>>();
  for (const document of documents) {
    const artifact = manifestArtifact(document);
    if (!artifact) continue;
    const { connector, streams } = artifact.declarations;
    const names = table.get(connector) ?? new Set<string>();
    for (const stream of streams) names.add(stream.name);
    table.set(connector, names);
  }
  return (connector) => [...(table.get(connector) ?? [])];
}
