import { timingSafeEqual } from "node:crypto";
import { getCollateralAndVerify } from "@phala/dcap-qvl";
import type { FleetPeerIdentity } from "./contracts.js";
import type { FleetPeerVerifier } from "./peer.js";
export interface FleetPeerPolicy {
  identity: Omit<FleetPeerIdentity, "nodeIncarnation">;
  mrTd: string;
  rtmrs: [string, string, string, string];
  /** Explicitly reviewed Intel advisory status policy; default requires UpToDate. */
  allowedTcbStatuses?: string[];
}
/** Full Intel chain/quote/TCB verification plus exact approved boot measurements.
 * Pinning all RTMRs binds app/instance/compose to measured startup; returned
 * untrusted identity claims alone can never enroll a peer.
 */
export function createDcapPeerVerifier(
  policies: FleetPeerPolicy[],
): FleetPeerVerifier {
  return async (evidence, reportData, identity) => {
    const policy = policies.find((p) =>
      Object.entries(p.identity).every(
        ([k, v]) => identity[k as keyof FleetPeerIdentity] === v,
      ),
    );
    if (!policy || !identity.nodeIncarnation)
      throw new Error("Peer not admitted");
    if (typeof evidence.quote !== "string" || evidence.quote.length > 256_000)
      throw new Error("Invalid peer quote");
    const verified = await getCollateralAndVerify(
      Buffer.from(evidence.quote, "base64"),
    );
    if (!(policy.allowedTcbStatuses ?? ["UpToDate"]).includes(verified.status))
      throw new Error("Peer TCB rejected");
    const report = verified.report.asTd10() ?? verified.report.asTd15()?.base;
    if (!report) throw new Error("Peer must attest Intel TDX");
    if (
      report.reportData.length !== reportData.length ||
      !timingSafeEqual(report.reportData, reportData)
    )
      throw new Error("Peer key/challenge binding rejected");
    const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString("hex");
    if (
      hex(report.mrTd) !== policy.mrTd ||
      [report.rtMr0, report.rtMr1, report.rtMr2, report.rtMr3].some(
        (r, i) => hex(r) !== policy.rtmrs[i],
      )
    )
      throw new Error("Peer measurements rejected");
    // TD DEBUG bit must never be admitted, even with operator-supplied hashes.
    if ((report.tdAttributes[0]! & 1) !== 0)
      throw new Error("Debug TDX forbidden");
  };
}
