/**
 * Has this writer ever been exposed to PDPP data?
 *
 * A lineage list is a claim the app makes, not evidence of what it read. For
 * a non-owner write the server cannot see the app's inputs, so it classifies
 * the WRITER instead: a builder bound to any PDPP grant, ever, may hold PDPP
 * data, so everything it writes is PDPP-origin whatever it cites. Exposure is
 * durable history, not current permission: bindings are append-only and carry
 * no revocation, so a revoked or expired grant still counts.
 *
 * Residual risk this cannot close: an unexposed builder may hold data it read
 * through the pre-#452 chain-grant bypass and cite only a legacy scope. The
 * server cannot prove what that app read.
 */

import type { PdppGrantBindingStore } from "./pdpp-binding-store.js";

export type WriterExposurePolicy =
  /** No PDPP surface exists on this server, so no PDPP data exists. */
  | { kind: "pdpp-disabled" }
  /** PDPP is enabled; the lookup answers from durable grant history. */
  | {
      kind: "lookup";
      hasExposure(builder: `0x${string}`): boolean | Promise<boolean>;
    };

/** A lookup over the append-only PDPP grant binding store. */
export function writerExposureFromBindings(
  bindings: Pick<PdppGrantBindingStore, "hasBindingForGrantee">,
): WriterExposurePolicy {
  return {
    kind: "lookup",
    hasExposure: (builder) => bindings.hasBindingForGrantee(builder),
  };
}

/**
 * True unless the server can show the writer was never exposed. A missing
 * policy (PDPP enabled but no mapping store wired) and a failing lookup both
 * count as exposed. Only an explicit `pdpp-disabled` policy answers false
 * without a lookup.
 */
export async function writerHasPdppExposure(
  policy: WriterExposurePolicy | undefined,
  builder: `0x${string}`,
): Promise<boolean> {
  if (!policy) return true;
  if (policy.kind === "pdpp-disabled") return false;
  try {
    return await policy.hasExposure(builder);
  } catch {
    return true;
  }
}
