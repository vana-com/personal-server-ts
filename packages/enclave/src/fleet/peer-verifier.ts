import { createHash, timingSafeEqual } from "node:crypto";
import { getCollateralAndVerify } from "@phala/dcap-qvl";
import type { FleetPeerIdentity } from "./contracts.js";
import type { FleetPeerVerifier } from "./peer.js";
interface FleetPeerPolicyBase {
  identity: Omit<FleetPeerIdentity, "nodeIncarnation">;
  mrTd: string;
  /** Explicitly reviewed Intel advisory status policy; default requires UpToDate. */
  allowedTcbStatuses?: string[];
}
export type FleetPeerPolicy = FleetPeerPolicyBase &
  (
    | { measurementMode?: "exact"; rtmrs: [string, string, string, string] }
    | {
        measurementMode: "dstack-0.5.9-events";
        rtmrs: [string, string, string];
        osImageHash: string;
        keyProviderSpki: string;
      }
  );
const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString("hex");
const isHex = (value: unknown, bytes?: number): value is string =>
  typeof value === "string" &&
  /^(?:[0-9a-f]{2})*$/.test(value) &&
  (bytes === undefined || value.length === bytes * 2);
interface DstackEvent {
  imr: number;
  event_type: number;
  digest: string;
  event: string;
  event_payload: string;
}
function runtimeEventDigest(event: DstackEvent): string {
  const type = Buffer.alloc(4);
  type.writeUInt32LE(event.event_type);
  return createHash("sha384")
    .update(type)
    .update(":")
    .update(event.event)
    .update(":")
    .update(Buffer.from(event.event_payload, "hex"))
    .digest("hex");
}
/** Authenticate payload semantics only after replaying the supplied log to the
 * verified quote. mr-kms may rotate under the exact approved KMS CA; this mode
 * deliberately does not pin the measurement of each KMS VM instance. */
function verifyDstackEvents(
  log: string | undefined,
  registers: Uint8Array[],
  policy: Extract<FleetPeerPolicy, { measurementMode: "dstack-0.5.9-events" }>,
): void {
  const reject = () => new Error("Peer runtime events rejected");
  if (typeof log !== "string" || Buffer.byteLength(log) > 512_000)
    throw reject();
  const entries: unknown = JSON.parse(log);
  if (!Array.isArray(entries) || entries.length < 10 || entries.length > 1024)
    throw reject();
  const replayed: Buffer[] = Array.from({ length: 4 }, () => Buffer.alloc(48));
  const runtime: DstackEvent[] = [];
  for (const value of entries) {
    if (
      !value ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      Object.keys(value).length !== 5 ||
      !["imr", "event_type", "digest", "event", "event_payload"].every((k) =>
        Object.hasOwn(value, k),
      ) ||
      !Number.isInteger(value.imr) ||
      value.imr < 0 ||
      value.imr > 3 ||
      !Number.isInteger(value.event_type) ||
      value.event_type < 0 ||
      value.event_type > 0xffffffff ||
      !(isHex(value.digest, 48) || (value.imr === 3 && value.digest === "")) ||
      typeof value.event !== "string" ||
      value.event.length > 256 ||
      !isHex(value.event_payload) ||
      value.event_payload.length > 64 * 1024
    )
      throw reject();
    let event = value as DstackEvent;
    // GetQuote omits runtime digests; certificate TCB logs include them.
    // Reconstruct only this documented runtime representation, then authenticate
    // it through the same full replay and exact event profile below.
    if (event.imr === 3 && event.digest === "")
      event = { ...event, digest: runtimeEventDigest(event) };
    replayed[event.imr] = createHash("sha384")
      .update(replayed[event.imr]!)
      .update(Buffer.from(event.digest, "hex"))
      .digest();
    if (event.imr === 3) runtime.push(event);
  }
  if (
    replayed.some((r, i) => !r.equals(registers[i]!)) ||
    runtime.length !== 10
  )
    throw reject();
  if (
    !isHex(policy.identity.appId, 20) ||
    !isHex(policy.identity.instanceId, 20) ||
    !isHex(policy.identity.composeHash, 32) ||
    !isHex(policy.osImageHash, 32) ||
    !isHex(policy.keyProviderSpki) ||
    !policy.keyProviderSpki
  )
    throw reject();
  const expected = [
    ["system-preparing", ""],
    ["app-id", policy.identity.appId],
    ["compose-hash", policy.identity.composeHash],
    ["instance-id", policy.identity.instanceId],
    ["boot-mr-done", ""],
    ["mr-kms", null],
    ["os-image-hash", policy.osImageHash],
    [
      "key-provider",
      Buffer.from(
        JSON.stringify({ name: "kms", id: policy.keyProviderSpki }),
      ).toString("hex"),
    ],
    ["storage-fs", Buffer.from("zfs").toString("hex")],
    ["system-ready", ""],
  ];
  for (const [i, event] of runtime.entries()) {
    if (
      event.event_type !== 0x08000001 ||
      event.event !== expected[i]![0] ||
      (i === 5
        ? !isHex(event.event_payload, 32)
        : event.event_payload !== expected[i]![1])
    )
      throw reject();
    if (runtimeEventDigest(event) !== event.digest) throw reject();
  }
}
/** Full Intel chain/quote/TCB verification plus exact approved boot measurements.
 * Exact mode pins all registers. Explicit dstack event mode authenticates all
 * runtime events against RTMR3 and pins the KMS CA that may rotate its instances.
 * Untrusted metadata alone can never enroll a peer.
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
    const registers = [report.rtMr0, report.rtMr1, report.rtMr2, report.rtMr3];
    const eventMode = policy.measurementMode === "dstack-0.5.9-events";
    if (
      (!eventMode &&
        policy.measurementMode !== undefined &&
        policy.measurementMode !== "exact") ||
      policy.rtmrs.length !== (eventMode ? 3 : 4) ||
      hex(report.mrTd) !== policy.mrTd ||
      policy.rtmrs.some((r, i) => !isHex(r, 48) || hex(registers[i]!) !== r)
    )
      throw new Error("Peer measurements rejected");
    // TD DEBUG bit must never be admitted, even with operator-supplied hashes.
    if ((report.tdAttributes[0]! & 1) !== 0)
      throw new Error("Debug TDX forbidden");
    if (policy.measurementMode === "dstack-0.5.9-events")
      verifyDstackEvents(evidence.eventLog, registers, policy);
  };
}
