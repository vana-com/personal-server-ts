import type { DataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import { readStoredLineage, LINEAGE_KEY } from "../lineage/lineage.js";
import { WRITER_ATTRIBUTION_KEY } from "../write/attribution-key.js";
import { isBinaryEnvelope } from "../contracts/binary.js";
import { inputHasPdppOrigin } from "../sync/pdpp-import.js";

/** Internal facts about the inputs to a value, independent of its JSON view. */
export interface ReadEvidence {
  readonly lineageSources: readonly string[];
  readonly pdppOrigin: boolean;
  readonly inputVersions: readonly Readonly<{
    scope: string;
    collectedAt: string;
  }>[];
}

// Presentation transforms never serialize this evidence into application data.
const evidence = new WeakMap<DataFileEnvelope, ReadEvidence>();

export function readEvidence(
  envelope: DataFileEnvelope,
  entry?: { pdppOrigin?: boolean },
): ReadEvidence {
  const retained = evidence.get(envelope);
  let lineageSources: readonly string[] = [];
  if (retained) lineageSources = retained.lineageSources;
  else lineageSources = readStoredLineage(envelope.data)?.sources ?? [];
  return Object.freeze({
    lineageSources: Object.freeze([...lineageSources]),
    inputVersions:
      retained?.inputVersions ??
      Object.freeze([
        Object.freeze({
          scope: envelope.scope,
          collectedAt: envelope.collectedAt,
        }),
      ]),
    pdppOrigin:
      retained?.pdppOrigin === true || inputHasPdppOrigin(entry, envelope),
  });
}

/** A presentation value depends on all actual inputs, including joined ones. */
export function retainReadEvidence(
  envelope: DataFileEnvelope,
  inputs: readonly ReadEvidence[],
): void {
  evidence.set(
    envelope,
    Object.freeze({
      lineageSources: Object.freeze([
        ...new Set(inputs.flatMap((input) => [...input.lineageSources])),
      ]),
      pdppOrigin: inputs.some((input) => input.pdppOrigin),
      inputVersions: Object.freeze([
        ...new Map(
          inputs.flatMap((input) =>
            input.inputVersions.map(
              (version) =>
                [
                  JSON.stringify([version.scope, version.collectedAt]),
                  Object.freeze({
                    scope: version.scope,
                    collectedAt: version.collectedAt,
                  }),
                ] as const,
            ),
          ),
        ).values(),
      ]),
    }),
  );
}

/** Detach approved data while retaining facts dropped by presentation. */
export function ownReadEnvelope(envelope: DataFileEnvelope): DataFileEnvelope {
  const owned = structuredClone(envelope);
  const retained = evidence.get(envelope);
  if (retained) evidence.set(owned, retained);
  return owned;
}

/** Only server-stamped computed records designate parallel provenance fields. */
export function privateProvenanceFields(lineage: unknown): readonly string[] {
  try {
    return readStoredLineage({ $lineage: lineage })?.kind ===
      "computed-question"
      ? ["sources"]
      : [];
  } catch {
    return [];
  }
}

/**
 * The envelope view a grantee read is entitled to. The server-stamped
 * `$writtenBy` (writing builder's address, grantId, signature) and
 * `$lineage` (the owner's source data-point ids, dictionary-attackable back
 * to scopes since dataPointId = keccak(owner, scope)) never leave the server
 * on a grantee read: the owner reads them from storage, and grantees get the
 * graph only through the grant-redacted lineage endpoint. When `$lineage` is
 * present, the caller-supplied lineage field it mirrors (top-level `lineage`
 * on a JSON record, `metadata.lineage` on a binary one) carries the same ids
 * and is dropped with it; without the stamp such a field is ordinary user
 * data and stays. Redaction is at serve time only — the stored envelope, its
 * dataHash commitment, and the owner's view are unchanged.
 */
export function redactEnvelopeForGrantee(
  envelope: DataFileEnvelope,
): DataFileEnvelope {
  const {
    [WRITER_ATTRIBUTION_KEY]: attribution,
    [LINEAGE_KEY]: storedLineage,
    ...rest
  } = envelope.data;
  if (attribution === undefined && storedLineage === undefined) {
    return envelope;
  }
  const privateFields = new Set(privateProvenanceFields(storedLineage));
  let data: Record<string, unknown> = Object.fromEntries(
    Object.entries(rest).filter(([key]) => !privateFields.has(key)),
  );
  if (storedLineage !== undefined) {
    if (isBinaryEnvelope(envelope)) {
      const metadata = data["metadata"];
      if (
        metadata !== null &&
        typeof metadata === "object" &&
        !Array.isArray(metadata)
      ) {
        const { lineage: _consumed, ...metadataRest } = metadata as Record<
          string,
          unknown
        >;
        if (Object.keys(metadataRest).length === 0) {
          // The lineage was the whole metadata object; leaving `{}` behind
          // would still disclose that a metadata object existed.
          const { metadata: _emptied, ...dataRest } = data;
          data = dataRest;
        } else {
          data = { ...data, metadata: metadataRest };
        }
      }
    } else {
      const { lineage: _consumed, ...dataRest } = data;
      data = dataRest;
    }
  }
  const served = { ...envelope, data };
  const retained = evidence.get(envelope);
  if (retained) evidence.set(served, retained);
  return served;
}
