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
  read(requestOwner: string): "switched" | "unswitched" | "unknown";
}

export function legacyRetireSwitched(
  mode: AccountModeReader,
  owner: string,
): boolean {
  return mode.read(owner) === "switched";
}
