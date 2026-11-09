/**
 * Whether the legacy import and retire may act for this account now: the ONE
 * place that decides it. Every host asks here, never reads a flag itself.
 *
 * The answer is the shared account-mode authority's, read for the owner the
 * caller acts for. `AccountModeReader` is the one method this package needs
 * of it, with the authority's own three values: only `switched` lets the
 * import or retire act. `unswitched` and `unknown` (an owner the authority has
 * not heard of, or a caller that names the wrong one) never do.
 */
export interface AccountModeReader {
  read(requestOwner: string): AccountMode;
}

/**
 * What the authority knows of an owner. `unknown` is NOT `unswitched`: it
 * means no decision, so nothing acts on it and nothing is reported as zero.
 */
export type AccountMode = "switched" | "unswitched" | "unknown";

/**
 * What the authority says of `owner`. The ONE place the owner is lowercased
 * on its way to the mode authority: an owner is checksum-cased where a host
 * recovers it, the authority keys owners in lowercase, and an exact-match
 * reader would answer `unknown` for a mixed-case one.
 */
export function accountModeOf(
  mode: AccountModeReader,
  owner: string,
): AccountMode {
  return mode.read(owner.toLowerCase());
}

export function legacyRetireSwitched(
  mode: AccountModeReader,
  owner: string,
): boolean {
  return accountModeOf(mode, owner) === "switched";
}
