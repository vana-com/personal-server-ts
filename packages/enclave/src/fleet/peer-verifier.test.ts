import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { beforeEach, expect, it, vi } from "vitest";
import { getCollateralAndVerify } from "@phala/dcap-qvl";
import {
  createDcapPeerVerifier,
  type FleetPeerPolicy,
} from "./peer-verifier.js";
vi.mock("@phala/dcap-qvl", () => ({ getCollateralAndVerify: vi.fn() }));
interface Event {
  imr: number;
  event_type: number;
  digest: string;
  event: string;
  event_payload: string;
}
interface Fixture {
  mrtd: string;
  rtmr0: string;
  rtmr1: string;
  rtmr2: string;
  rtmr3: string;
  event_log: Event[];
}
const fixture = (name: string): Fixture =>
  JSON.parse(
    readFileSync(
      new URL(`./fixtures/dstack-0.5.9-${name}.json`, import.meta.url),
      "utf8",
    ),
  );
const before = fixture("before"),
  after = fixture("after");
const runtime = before.event_log.filter((e) => e.imr === 3);
const identity = {
  role: "controller" as const,
  nodeId: "controller",
  nodeIncarnation: "fresh-boot",
  appId: runtime[1]!.event_payload,
  composeHash: runtime[2]!.event_payload,
  instanceId: runtime[3]!.event_payload,
};
const { nodeIncarnation: _incarnation, ...pinnedIdentity } = identity;
const policy = {
  identity: pinnedIdentity,
  measurementMode: "dstack-0.5.9-events",
  mrTd: before.mrtd,
  rtmrs: [before.rtmr0, before.rtmr1, before.rtmr2],
  osImageHash: runtime[6]!.event_payload,
  keyProviderSpki: JSON.parse(
    Buffer.from(runtime[7]!.event_payload, "hex").toString("utf8"),
  ).id as string,
} satisfies FleetPeerPolicy;
const challenge = Buffer.alloc(64, 7);
function verified(f: Fixture) {
  return {
    status: "UpToDate",
    report: {
      asTd10: () => ({
        mrTd: Buffer.from(f.mrtd, "hex"),
        rtMr0: Buffer.from(f.rtmr0, "hex"),
        rtMr1: Buffer.from(f.rtmr1, "hex"),
        rtMr2: Buffer.from(f.rtmr2, "hex"),
        rtMr3: Buffer.from(f.rtmr3, "hex"),
        reportData: challenge,
        tdAttributes: Buffer.alloc(8),
      }),
      asTd15: () => undefined,
    },
  };
}
function evidence(f: Fixture) {
  return {
    quote: Buffer.from("QVL unit fixture").toString("base64"),
    eventLog: JSON.stringify(f.event_log),
  };
}
beforeEach(() => {
  vi.mocked(getCollateralAndVerify).mockReset();
});
it("accepts the real before/after event fixtures only under explicit approved KMS CA rotation policy", async () => {
  expect(before.rtmr3).not.toBe(after.rtmr3);
  const verify = createDcapPeerVerifier([policy]);
  for (const f of [before, after]) {
    vi.mocked(getCollateralAndVerify).mockResolvedValue(verified(f) as never);
    await expect(
      verify(evidence(f), challenge, identity),
    ).resolves.toBeUndefined();
  }
});

function remeasure(f: Fixture): void {
  let register: Buffer = Buffer.alloc(48);
  for (const event of f.event_log.filter((e) => e.imr === 3)) {
    const type = Buffer.alloc(4);
    type.writeUInt32LE(event.event_type);
    event.digest = createHash("sha384")
      .update(type)
      .update(":")
      .update(event.event)
      .update(":")
      .update(Buffer.from(event.event_payload, "hex"))
      .digest("hex");
    register = createHash("sha384")
      .update(register)
      .update(Buffer.from(event.digest, "hex"))
      .digest();
  }
  f.rtmr3 = register.toString("hex");
}
it("rejects event payload lies even when the old digest/log replay still matches the quote", async () => {
  const f = structuredClone(after);
  f.event_log.find((e) => e.event === "mr-kms")!.event_payload = "11".repeat(
    32,
  );
  vi.mocked(getCollateralAndVerify).mockResolvedValue(verified(after) as never);
  await expect(
    createDcapPeerVerifier([policy])(evidence(f), challenge, identity),
  ).rejects.toThrow("Peer runtime events rejected");
});
it("rejects a repeated mr-kms event with the exact message central maps to a code", async () => {
  const f = structuredClone(after);
  const index = f.event_log.findIndex((entry) => entry.event === "mr-kms");
  f.event_log.splice(index + 1, 0, structuredClone(f.event_log[index]!));
  remeasure(f);
  vi.mocked(getCollateralAndVerify).mockResolvedValue(verified(f) as never);
  // Central's closed allow-list keys PEER_EVENTS_REJECTED on this exact string.
  await expect(
    createDcapPeerVerifier([policy])(evidence(f), challenge, identity),
  ).rejects.toThrow(/^Peer runtime events rejected$/);
});
it("rejects reordered, duplicate, missing, unknown and unapproved events even with matching quoted replay", async () => {
  const changes: ((events: Event[]) => void)[] = [
    (e) => {
      const a = e.findIndex((x) => x.event === "app-id");
      [e[a], e[a + 1]] = [e[a + 1]!, e[a]!];
    },
    (e) => {
      e.push({ ...e.at(-1)! });
    },
    (e) => {
      e.pop();
    },
    (e) => {
      e.at(-1)!.event = "unknown-event";
    },
    (e) => {
      e.find((x) => x.event === "system-preparing")!.event_payload = "01";
    },
    (e) => {
      e.find((x) => x.event === "mr-kms")!.event_payload = "01";
    },
    (e) => {
      e.find((x) => x.event === "key-provider")!.event_payload = Buffer.from(
        JSON.stringify({ name: "kms", id: "00" }),
      ).toString("hex");
    },
    (e) => {
      e.find((x) => x.event === "storage-fs")!.event_payload =
        Buffer.from("ext4").toString("hex");
    },
    (e) => {
      e.find((x) => x.event === "os-image-hash")!.event_payload = "11".repeat(
        32,
      );
    },
    (e) => {
      e.find((x) => x.event === "app-id")!.event_payload = "11".repeat(20);
    },
    (e) => {
      e.find((x) => x.event === "compose-hash")!.event_payload = "11".repeat(
        32,
      );
    },
    (e) => {
      e.find((x) => x.event === "instance-id")!.event_payload = "11".repeat(20);
    },
    (e) => {
      e.at(-1)!.event_type = 1;
    },
  ];
  for (const change of changes) {
    const f = structuredClone(after);
    change(f.event_log);
    remeasure(f);
    vi.mocked(getCollateralAndVerify).mockResolvedValue(verified(f) as never);
    await expect(
      createDcapPeerVerifier([policy])(evidence(f), challenge, identity),
    ).rejects.toThrow("Peer runtime events rejected");
  }
});
it("requires the supplied event log to match this verified quote and all pinned firmware registers", async () => {
  vi.mocked(getCollateralAndVerify).mockResolvedValue(verified(after) as never);
  for (const eventLog of [
    undefined,
    JSON.stringify(before.event_log),
    "[]",
    "x".repeat(512001),
  ])
    await expect(
      createDcapPeerVerifier([policy])(
        { ...evidence(after), eventLog },
        challenge,
        identity,
      ),
    ).rejects.toThrow();
  const invalidFirmware = structuredClone(after);
  invalidFirmware.rtmr0 = "11".repeat(48);
  vi.mocked(getCollateralAndVerify).mockResolvedValue(
    verified(invalidFirmware) as never,
  );
  await expect(
    createDcapPeerVerifier([policy])(
      evidence(invalidFirmware),
      challenge,
      identity,
    ),
  ).rejects.toThrow("Peer measurements rejected");
  vi.mocked(getCollateralAndVerify).mockResolvedValue(verified(after) as never);
  await expect(
    createDcapPeerVerifier([{ ...policy, keyProviderSpki: "00" }])(
      evidence(after),
      challenge,
      identity,
    ),
  ).rejects.toThrow();
});
it("retains exact four-register policy and the quote, challenge, TCB and debug gates", async () => {
  const exact: FleetPeerPolicy = {
    identity: pinnedIdentity,
    mrTd: before.mrtd,
    rtmrs: [before.rtmr0, before.rtmr1, before.rtmr2, before.rtmr3],
  };
  vi.mocked(getCollateralAndVerify).mockResolvedValue(
    verified(before) as never,
  );
  await expect(
    createDcapPeerVerifier([exact])(
      { quote: evidence(before).quote },
      challenge,
      identity,
    ),
  ).resolves.toBeUndefined();
  vi.mocked(getCollateralAndVerify).mockResolvedValue(verified(after) as never);
  await expect(
    createDcapPeerVerifier([exact])(evidence(after), challenge, identity),
  ).rejects.toThrow("Peer measurements rejected");
  const verifier = createDcapPeerVerifier([policy]);
  await expect(
    verifier(evidence(after), Buffer.alloc(64, 8), identity),
  ).rejects.toThrow("Peer key/challenge binding rejected");
  const badStatus = verified(after);
  badStatus.status = "OutOfDate";
  vi.mocked(getCollateralAndVerify).mockResolvedValue(badStatus as never);
  await expect(verifier(evidence(after), challenge, identity)).rejects.toThrow(
    "Peer TCB rejected",
  );
  const debug = verified(after);
  const report = debug.report.asTd10();
  report.tdAttributes[0] = 1;
  debug.report.asTd10 = () => report;
  vi.mocked(getCollateralAndVerify).mockResolvedValue(debug as never);
  await expect(verifier(evidence(after), challenge, identity)).rejects.toThrow(
    "Debug TDX forbidden",
  );
  vi.mocked(getCollateralAndVerify).mockImplementation(() => {
    throw new Error("Invalid Intel chain");
  });
  await expect(verifier(evidence(after), challenge, identity)).rejects.toThrow(
    "Invalid Intel chain",
  );
});

it("verifies the real GetQuote wire log with empty runtime digests against all quoted registers", async () => {
  const raw = fixture("getquote");
  const events = raw.event_log.filter((entry) => entry.imr === 3);
  expect(events).toHaveLength(10);
  expect(events.every((entry) => entry.digest === "")).toBe(true);
  const liveIdentity = {
    ...identity,
    appId: events[1]!.event_payload,
    composeHash: events[2]!.event_payload,
    instanceId: events[3]!.event_payload,
  };
  const livePolicy = {
    ...policy,
    identity: {
      ...policy.identity,
      appId: liveIdentity.appId,
      composeHash: liveIdentity.composeHash,
      instanceId: liveIdentity.instanceId,
    },
  };
  vi.mocked(getCollateralAndVerify).mockResolvedValue(verified(raw) as never);
  await expect(
    createDcapPeerVerifier([livePolicy])(
      evidence(raw),
      challenge,
      liveIdentity,
    ),
  ).resolves.toBeUndefined();
});

it.each([
  "changed payload",
  "reordered events",
  "mismatched supplied digest",
  "empty firmware digest",
  "missing digest field",
  "extra runtime record",
])("rejects %s in the real raw GetQuote representation", async (change) => {
  const quoted = fixture("getquote"),
    altered = structuredClone(quoted);
  const runtime = quoted.event_log.filter((entry) => entry.imr === 3);
  const liveIdentity = {
    ...identity,
    appId: runtime[1]!.event_payload,
    composeHash: runtime[2]!.event_payload,
    instanceId: runtime[3]!.event_payload,
  };
  const livePolicy = {
    ...policy,
    identity: {
      ...policy.identity,
      appId: liveIdentity.appId,
      composeHash: liveIdentity.composeHash,
      instanceId: liveIdentity.instanceId,
    },
  };
  const start = altered.event_log.findIndex((entry) => entry.imr === 3);
  if (change === "changed payload")
    altered.event_log[start + 1]!.event_payload = "00".repeat(20);
  if (change === "reordered events")
    [altered.event_log[start], altered.event_log[start + 1]] = [
      altered.event_log[start + 1]!,
      altered.event_log[start]!,
    ];
  if (change === "mismatched supplied digest")
    altered.event_log[start]!.digest = "00".repeat(48);
  if (change === "empty firmware digest") altered.event_log[0]!.digest = "";
  if (change === "missing digest field")
    Reflect.deleteProperty(altered.event_log[start]!, "digest");
  if (change === "extra runtime record")
    altered.event_log.push({ ...altered.event_log[start]! });
  vi.mocked(getCollateralAndVerify).mockResolvedValue(
    verified(quoted) as never,
  );
  await expect(
    createDcapPeerVerifier([livePolicy])(
      evidence(altered),
      challenge,
      liveIdentity,
    ),
  ).rejects.toThrow("Peer runtime events rejected");
});
