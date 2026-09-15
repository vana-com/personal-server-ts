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

/** The one production Gateway a mainnet fleet may be signed against. Moksha is
 * deliberately unpinned: preview fleets run against their own Gateway hosts. */
export const MAINNET_GATEWAY_ORIGIN = "https://dp-rpc.vana.org";

/** e.g. `isSupportedChain(1337)` is false, so callers reject before any I/O. */
export function isSupportedChain(value: number): value is SupportedChainId {
  return value === MAINNET_CHAIN_ID || value === MOKSHA_CHAIN_ID;
}

/** Exact match on the signed bytes: `Number()` would also accept "0x5c8",
 * " 1480" and "1480.0" as mainnet, none of which a renderer ever emits. */
export function readSignedChain(
  value: string | undefined,
): SupportedChainId | undefined {
  if (value === String(MAINNET_CHAIN_ID)) return MAINNET_CHAIN_ID;
  if (value === String(MOKSHA_CHAIN_ID)) return MOKSHA_CHAIN_ID;

  return undefined;
}
