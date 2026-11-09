/**
 * Whether the legacy import and retire may act for this account now: the ONE
 * place that decides it. Every host asks here, never reads a flag itself.
 *
 * This body is a stand-in. It reads the host's stream-sync write flag, which
 * says the writer is on in this process, not that the Account is switched. An
 * unswitched Account must neither import nor retire, so this must read the
 * shared mode module's decision before the retire work merges.
 */
export function legacyRetireSwitched(config: {
  readonly streamSync?: { readonly write?: boolean } | undefined;
}): boolean {
  return config.streamSync?.write === true;
}
