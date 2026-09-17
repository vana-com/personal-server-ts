/**
 * Deployment wiring for the PDPP Authorization Server.
 *
 * Two jobs the route module deliberately does not do, because both are
 * deployment policy rather than protocol:
 *
 *   1. Decide which source declarations this server will accept as authority
 *      over a source. Core §5 requires an explicit trust policy; "we could
 *      reach it over HTTPS" is not one. The policy here is derived from what
 *      this PS actually serves, so a server that holds no Spotify data does
 *      not accept a Spotify declaration and cannot be talked into issuing a
 *      grant over data it has never collected.
 *
 *   2. Map a verified owner wallet to the PDPP subject. This PS is
 *      single-owner, so the subject is the server owner and nothing else.
 *
 * There is no trust-all default. A deployment that has configured no
 * declarations accepts none, which makes `/pdpp/v1` inert rather than
 * dangerous — the failure mode of a misconfigured authorization server should
 * be "issues nothing", never "issues anything".
 */

import type { DeclarationSnapshot } from "@opendatalabs/personal-server-ts-core/pdpp";
import { parseDeclaration } from "@opendatalabs/personal-server-ts-core/pdpp";
import type { Logger } from "pino";

/**
 * The connector inventory this PS serves, derived from the scopes it actually
 * holds. A scope is `{source}.{category}[.{subcategory}]`, so the leading
 * segment is the connector.
 */
export function deriveSupportedConnectors(scopes: string[]): string[] {
  const sources = new Set<string>();
  for (const scope of scopes) {
    const source = scope.split(".")[0];
    if (source && source.length > 0) sources.add(source);
  }
  return Array.from(sources).sort();
}

/**
 * A declaration this deployment retains, as configured.
 *
 * `document` is the exact retained bytes. Keeping the raw document (rather
 * than a parsed object) is what lets the digest be computed over what was
 * actually retrieved, which is the evidence §9 item 16 requires to survive
 * into consent and issuance.
 */
export interface ConfiguredDeclaration {
  sourceId: string;
  document: string;
}

export interface PdppDeclarationRegistryOptions {
  /** Declarations this deployment has explicitly retained. */
  declarations: ConfiguredDeclaration[];
  /** Connector inventory; a declaration for an unserved source is rejected. */
  supportedConnectors: string[];
  logger: Logger;
}

/**
 * Build the `resolveDeclaration` lookup the AS routes consume.
 *
 * Every configured declaration is validated and digested once at startup, then
 * pinned. A declaration that fails validation is dropped with a warning rather
 * than accepted-and-hoped-for: an AS resolving grants against a malformed
 * declaration would freeze nonsense into an immutable consent artifact.
 *
 * The connector gate is the part that makes this a real trust policy rather
 * than a config list. A declaration naming a source this PS does not serve is
 * refused even if an operator pasted it in, because a grant over data that
 * cannot exist here is at best useless and at worst a consent screen showing
 * an owner something they cannot actually be sharing.
 */
export function buildDeclarationRegistry(
  options: PdppDeclarationRegistryOptions,
): {
  resolve: (sourceId: string) => DeclarationSnapshot | null;
  retained: DeclarationSnapshot[];
} {
  const { logger } = options;
  const supported = new Set(options.supportedConnectors);
  const bySourceId = new Map<string, DeclarationSnapshot>();

  for (const configured of options.declarations) {
    const parsed = parseDeclaration(configured.document, configured.sourceId);
    if (!parsed.ok) {
      logger.warn(
        { sourceId: configured.sourceId, reason: parsed.failure.message },
        "PDPP declaration rejected: not retained",
      );
      continue;
    }

    const connector = connectorNameFor(parsed.snapshot);
    if (!supported.has(connector)) {
      logger.warn(
        { sourceId: configured.sourceId, connector },
        "PDPP declaration rejected: this server does not serve that connector",
      );
      continue;
    }

    bySourceId.set(parsed.snapshot.source_id, parsed.snapshot);
    logger.info(
      {
        sourceId: parsed.snapshot.source_id,
        version: parsed.snapshot.version,
        digest: parsed.snapshot.digest.slice(0, 12),
      },
      "PDPP declaration retained",
    );
  }

  return {
    resolve: (sourceId: string) => bySourceId.get(sourceId) ?? null,
    retained: Array.from(bySourceId.values()),
  };
}

/**
 * The connector a declaration belongs to.
 *
 * Source IDs are absolute URIs whose last path segment names the connector
 * (`https://registry.pdpp.dev/connectors/spotify` → `spotify`). Falling back
 * to the whole ID for an unparseable value means an odd source fails the
 * `supported` check rather than silently matching a connector it is not.
 */
function connectorNameFor(snapshot: DeclarationSnapshot): string {
  try {
    const segments = new URL(snapshot.source_id).pathname
      .split("/")
      .filter((s) => s.length > 0);
    return segments[segments.length - 1] ?? snapshot.source_id;
  } catch {
    return snapshot.source_id;
  }
}

/**
 * The owner's connected instances for a source.
 *
 * This PS is single-instance per source today: one owner, one connected
 * account per connector, and the scope index carries no per-account handle.
 * Reporting exactly one handle is therefore the truth here, not a placeholder
 * — and it is why the auto-resolve path (§6: exactly one eligible handle)
 * applies rather than the owner-choice path.
 *
 * When multi-account connections land, this is the one function that changes:
 * returning several handles makes the AS require an explicit owner choice
 * automatically, because that rule lives in resolution, not here.
 */
export function singleInstanceInventory(
  subjectId: string,
  sourceId: string,
): { eligibleFor(streamName: string): string[] } {
  const connector = sourceId.split("/").filter(Boolean).pop() ?? sourceId;
  const handle = `${connector}:${subjectId}`;
  return { eligibleFor: () => [handle] };
}
