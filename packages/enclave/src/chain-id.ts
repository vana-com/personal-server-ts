/** The chains a fleet deployment may serve.
 *
 * A deployment serves exactly one of them: `CHAIN_ID` travels in the measured,
 * signed fleet config, so a misrouted value (a mainnet controller aimed at the
 * Moksha Gateway, or the reverse) fails closed at config verification rather
 * than at the first Gateway call. Kept dependency-free and outside `agent/` so
 * the security-config verifier can share it without importing the agent.
 */

export const MAINNET_CHAIN_ID = 1_480;
export const MOKSHA_CHAIN_ID = 14_800;

export type SupportedChainId = typeof MAINNET_CHAIN_ID | typeof MOKSHA_CHAIN_ID;

/** e.g. `isSupportedChain(1337)` is false, so callers reject before any I/O. */
export function isSupportedChain(value: number): value is SupportedChainId {
  return value === MAINNET_CHAIN_ID || value === MOKSHA_CHAIN_ID;
}
