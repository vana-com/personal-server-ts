import {
  createLegacyWriteSeal,
  type LegacyWriteSeal,
  type SealAuthority,
} from "@opendatalabs/personal-server-ts-core/storage/legacy-write-seal";
import type { RefuseDecision } from "@opendatalabs/personal-server-ts-core/sync/account-mode";

const UNKNOWN: RefuseDecision = {
  kind: "refuse",
  code: "ACCOUNT_MODE_UNKNOWN",
  status: 503,
};

/**
 * The absence of an account-mode authority, not a second one. A server built
 * without one has nobody to ask what the account chose, so every legacy write
 * is refused as unknown (retryable 503) and every removal still runs. Only
 * code paths that build a server without a host (tests, embedders) land here;
 * the host always passes its authority's seal.
 */
const NO_AUTHORITY: SealAuthority = {
  read: () => UNKNOWN,
  commitLegacy: async () => ({ ok: false, decision: UNKNOWN }),
  commitRemoval: async (work) => work(),
};

export function unwiredLegacyWriteSeal(): LegacyWriteSeal {
  return createLegacyWriteSeal({ authority: NO_AUTHORITY, owner: undefined });
}
