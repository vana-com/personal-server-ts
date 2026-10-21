/**
 * One publication policy: what origin a NON-OWNER's publication carries.
 *
 * On a PDPP-enabled server every non-owner publication is PDPP-origin: a
 * direct write (JSON or binary, any lineage or none) and a builder-registered
 * question's computed output (its question text is builder-supplied input).
 * A lineage list is a claim the app makes, not evidence of what it read, and
 * a grant binding cannot show an app was never exposed. So there is no
 * per-writer exemption and no lookup that could fail open.
 *
 * On a PDPP-disabled server no PDPP data exists, so legacy classification
 * stands. If the enabled state is unknown (not supplied, or the check throws)
 * the publication is PDPP-origin. Owner writes and owner compute are not
 * decided here: they keep classification by observed sources.
 */
export type PdppEnabled = boolean | (() => boolean);

export function nonOwnerPublicationIsPdpp(
  pdppEnabled: PdppEnabled | undefined,
): boolean {
  try {
    const enabled =
      typeof pdppEnabled === "function" ? pdppEnabled() : pdppEnabled;
    return enabled !== false;
  } catch {
    return true;
  }
}
