import { expect, it } from "vitest";
import {
  replicaAwaitingFinality,
  type ReplicaRegistrationEvidence,
} from "./dpv2.js";
const owner = `0x${"1".repeat(40)}`;
const scope = "scope";
const dataHash = `0x${"2".repeat(64)}`;
const metadataHash = `0x${"3".repeat(64)}`;
function waiting(): ReplicaRegistrationEvidence {
  return {
    pending: false,
    head: {
      owner,
      scope,
      version: "1",
      dataHash,
      metadataHash,
      deleted: false,
    },
    chain: {
      owner,
      scope,
      version: "1",
      currentVersion: "0",
      status: "None",
      commitment: `0x${"0".repeat(64)}`,
      chainId: 14800,
      registry: `0x${"4".repeat(40)}`,
      blockNumber: 123n,
      blockHash: `0x${"5".repeat(64)}`,
      blockTimestamp: 1000n,
    },
  };
}
it("distinguishes expected finality waiting from optimistic disagreements", () => {
  const expected = { owner, scope, dataHash, metadataHash };
  expect(replicaAwaitingFinality(waiting(), expected)).toBe(true);
  const changes: ((e: ReplicaRegistrationEvidence) => void)[] = [
    (e) => {
      e.head = null;
    },
    (e) => {
      e.chain = null;
    },
    (e) => {
      e.head!.deleted = true;
    },
    (e) => {
      e.head!.version = "2";
    },
    (e) => {
      e.head!.scope = "other";
    },
    (e) => {
      e.chain!.scope = "other";
    },
    (e) => {
      e.head!.owner = `0x${"9".repeat(40)}`;
    },
    (e) => {
      e.chain!.status = "Inactive";
    },
    (e) => {
      e.head!.dataHash = `0x${"7".repeat(64)}`;
    },
    (e) => {
      e.chain!.commitment = `0x${"8".repeat(64)}`;
    },
  ];
  for (const change of changes) {
    const e = waiting();
    change(e);
    expect(replicaAwaitingFinality(e, expected)).toBe(false);
  }
});
