/**
 * The old spawn-time flag (`streamSync.write` with `streamSync.refuseLegacyWrites`)
 * as evidence.
 *
 * It used to decide the mode. It cannot any more: a flag fixed at spawn cannot
 * tell "the Account said Off" from "nobody told this server", and a stale value
 * can disagree with the Account either way. It is still readable, and what it
 * says is `unknown`: it never mints an Off, and it never latches On.
 */

import type { ModeEvidenceInput } from "./authority.js";

export interface LegacyStreamSyncFlag {
  write?: boolean;
  refuseLegacyWrites?: boolean;
}

export function legacyFlagEvidence(
  _flag: LegacyStreamSyncFlag | undefined,
  owner: string,
  nowWallMs: number,
): ModeEvidenceInput {
  return {
    owner,
    authOwner: owner,
    state: "unknown",
    fetchStartedAt: nowWallMs,
    rawStatus: null,
  };
}
