/**
 * The legacy-surface disclosure decision. Kept apart from the chain grant
 * policy in `data-read.ts` so browser-safe storage code (the grantee read
 * port) can use it without the grant machinery.
 */
import { GrantRequiredError } from "../errors/catalog.js";
import type { IndexEntry } from "../storage/index/types.js";
import { hasPdppOrigin } from "../sync/pdpp-import.js";

/**
 * Who receives a read served by the legacy data surfaces: `/v1/data` (Node
 * and Lite), MCP, derivative questions and TEE jobs. `owner` is the owner or
 * the server-internal policy-bypass sentinel; every other caller, including
 * one holding a PDPP-bound chain grant, is a `grantee`.
 */
export type LegacyReader = "owner" | "grantee";

/** What a legacy-surface read is about to disclose, or has selected. */
export type LegacyReadBody =
  /** The canonical view, or its refusal, of a scope the PDPP store owns. */
  | { kind: "canonical-view" }
  /**
   * The stored envelope actually read, the bytes about to be served. This is
   * the authority: `granteeReadPort` decides on it for every body a
   * non-owner read returns.
   */
  | { kind: "stored-envelope"; envelope: { data: unknown; producer?: unknown } }
  /**
   * Blocks read from a sidecar whose manifest records the provenance of the
   * envelope it was built from, read in the same call as the blocks.
   */
  | { kind: "stored-blocks"; pdppOrigin: boolean }
  /**
   * Bytes streamed from a version whose index row records the provenance
   * and the SHA-256 storage derived from the same published bytes. The
   * stream is checked against that digest and fails, before it completes,
   * on any other bytes.
   */
  | { kind: "digest-pinned-bytes"; pdppOrigin: boolean }
  /**
   * The index row selected before any body is read. Only an early refusal,
   * so a read that will be refused is not charged: a row known to be PDPP is
   * refused here; any other row is decided later on its bytes.
   */
  | { kind: "indexed-version"; entry: Pick<IndexEntry, "pdppOrigin"> };

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
 */
export function authorizeLegacyRead(
  reader: LegacyReader,
  body: LegacyReadBody,
): void {
  if (reader === "owner") return;
  const pdpp =
    body.kind === "canonical-view" ||
    (body.kind === "stored-envelope" && hasPdppOrigin(body.envelope)) ||
    ((body.kind === "stored-blocks" || body.kind === "digest-pinned-bytes") &&
      body.pdppOrigin) ||
    (body.kind === "indexed-version" && body.entry.pdppOrigin === true);
  if (!pdpp) return;
  throw new GrantRequiredError({
    reason:
      "PDPP data is readable only with a PDPP access token at the PDPP resource server",
  });
}
