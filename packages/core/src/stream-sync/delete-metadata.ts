import { keccak256, stringToHex } from "viem";

/** Row-only delete marker, in a separate domain from ordinary publication metadata. */
export function deleteMetadataHash(
  scope: string,
  version: number,
): `0x${string}` {
  return keccak256(
    stringToHex(
      JSON.stringify(["vana.stream-sync.delete.v1", scope, String(version)]),
    ),
  );
}

/**
 * Row-only delete marker that also records the connection generation the
 * delete ended. The head of a delete is always generation 1, so the head
 * cannot say which lifetime it ended; this marker can, with no change to the
 * head format. A reader that does not know it sees an unmarked row and still
 * reads the head's own `lastDeleteVersion`.
 */
export function endedGenerationDeleteMetadataHash(
  scope: string,
  version: number,
  generation: number,
): `0x${string}` {
  return keccak256(
    stringToHex(
      JSON.stringify([
        "vana.stream-sync.delete.v2",
        scope,
        String(version),
        String(generation),
      ]),
    ),
  );
}

/** Generations above this are never searched; the answer is then "unproven". */
const MAX_SEARCHED_GENERATION = 100_000;

/**
 * True only when the row proves its delete ended a lifetime EARLIER than
 * `activeGeneration`. A row without the marker (every delete written before
 * the marker existed) proves nothing and answers false: it may be the delete
 * of the active lifetime whose control tombstone has not landed yet.
 */
export function deleteEndedEarlierLifetime(
  scope: string,
  row: { readonly version: number; readonly metadataHash: string },
  activeGeneration: number,
): boolean {
  if (activeGeneration > MAX_SEARCHED_GENERATION) return false;
  const marked = row.metadataHash.toLowerCase();
  for (let g = 1; g < activeGeneration; g++)
    if (endedGenerationDeleteMetadataHash(scope, row.version, g) === marked)
      return true;
  return false;
}
