/**
 * The legacy-surface disclosure decision. Kept apart from the chain grant
 * policy in `data-read.ts` so browser-safe storage code (the disclosure view
 * under the legacy projection) can use it without the grant machinery.
 */
import { GrantRequiredError } from "../errors/catalog.js";
import type { IndexEntry } from "../storage/index/types.js";
import { hasPdppOrigin } from "../sync/pdpp-import.js";
import { WRITER_ATTRIBUTION_KEY } from "../write/attribution-key.js";

/**
 * Who receives a read served by the legacy data surfaces: `/v1/data` (Node
 * and Lite), MCP, derivative questions and TEE jobs. `owner` is the owner or
 * the server-internal policy-bypass sentinel; every other caller, including
 * one holding a PDPP-bound chain grant, is a `grantee`.
 */
export type LegacyReader =
  | "owner"
  | "grantee"
  /**
   * A grantee whose identity is known: the builder recovered from its
   * Web3Signed read. Only this reader can qualify for the own-write exception
   * in `authorizeLegacyRead`.
   */
  | { builder: string };

/** What a legacy-surface read is about to disclose, or has selected. */
export type LegacyReadBody =
  /** The canonical view, or its refusal, of a scope the PDPP store owns. */
  | { kind: "canonical-view" }
  /**
   * The stored envelope actually read, the bytes about to be served. This is
   * the authority: `withDisclosurePolicy` decides on it for every body a
   * non-owner storage view returns.
   */
  | { kind: "stored-envelope"; envelope: { data: unknown; producer?: unknown } }
  /**
   * Blocks read from a sidecar whose manifest records the provenance of the
   * envelope it was built from, read in the same call as the blocks.
   */
  | { kind: "stored-blocks"; pdppOrigin: boolean }
  /**
   * The index row selected before any body is read. Only an early refusal,
   * so a read that will be refused is not charged: a row known to be PDPP is
   * refused here; any other row is decided later on its bytes.
   */
  | {
      kind: "indexed-version";
      entry: Pick<IndexEntry, "pdppOrigin" | "producer">;
    };

const ADDRESS = /^0x[0-9a-fA-F]{40}$/;

/**
 * True when the stored version is a direct non-owner write whose server-
 * stamped `$writtenBy.builder` is the reader: the reader learns nothing it
 * did not already hold. A version without a well-formed `$writtenBy` (owner
 * writes, builder-registered compute, anything malformed) never qualifies.
 */
function readerWroteVersion(reader: LegacyReader, data: unknown): boolean {
  if (typeof reader !== "object") return false;
  if (typeof data !== "object" || data === null) return false;
  const stamp = (data as Record<string, unknown>)[WRITER_ATTRIBUTION_KEY];
  if (typeof stamp !== "object" || stamp === null) return false;
  const { builder, grantId, signature, bodyHash, writtenAt } = stamp as Record<
    string,
    unknown
  >;
  return (
    typeof builder === "string" &&
    ADDRESS.test(builder) &&
    ADDRESS.test(reader.builder) &&
    typeof grantId === "string" &&
    typeof signature === "string" &&
    typeof bodyHash === "string" &&
    typeof writtenAt === "string" &&
    builder.toLowerCase() === reader.builder.toLowerCase()
  );
}

/**
 * The one decision for disclosing PDPP data through the legacy surfaces.
 *
 * A legacy chain grant authorizes actual legacy files only, with or without a
 * PDPP grant binding. The canonical view and every stored envelope with PDPP
 * origin (native `$pdpp` metadata, or a PDPP producer stamp) reach a
 * non-owner only through the PDPP resource server, which applies the PDPP
 * grant's selection, projection and time constraints. There is deliberately
 * no chain-to-PDPP bridge here. The owner keeps full authority over their own
 * data.
 *
 * One exception, decided on the bytes served: a reader whose identity is known
 * may read back a version it wrote itself (`$writtenBy.builder`). It applies
 * to envelope reads only. A block manifest does not carry `$writtenBy`, so
 * block reads and the canonical view stay refused, and a version's index row
 * is deferred to its bytes only for a pdpp-derivative row, the stamp a direct
 * non-owner write gets.
 */
export function authorizeLegacyRead(
  reader: LegacyReader,
  body: LegacyReadBody,
): void {
  if (reader === "owner") return;
  const pdpp =
    body.kind === "canonical-view" ||
    (body.kind === "stored-envelope" &&
      hasPdppOrigin(body.envelope) &&
      !readerWroteVersion(reader, body.envelope.data)) ||
    (body.kind === "stored-blocks" && body.pdppOrigin) ||
    (body.kind === "indexed-version" &&
      body.entry.pdppOrigin === true &&
      !(
        typeof reader === "object" && body.entry.producer === "pdpp-derivative"
      ));
  if (!pdpp) return;
  throw new GrantRequiredError({
    reason:
      "PDPP data is readable only with a PDPP access token at the PDPP resource server",
  });
}
