import { expect, it } from "vitest";
import {
  replicaAwaitingFinality,
  replicaChainCommitment,
  replicaRegistrationInactive,
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
  const expected = { owner, scope, version: 1, dataHash, metadataHash };
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
      e.head!.version = "0";
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
it("waits on finality of a later slot while the chain holds earlier versions", () => {
  const e = waiting();
  e.head!.version = "4";
  e.chain = {
    ...e.chain!,
    version: "4",
    currentVersion: "3",
    status: "Active",
  };
  const slot = { owner, scope, version: 4, dataHash, metadataHash };
  expect(replicaAwaitingFinality(e, slot)).toBe(true);
  // A later head implies this slot is registered: its own hashes are then
  // checked only by the finalized commitment, never against another version.
  e.head = { ...e.head!, version: "5", dataHash: `0x${"7".repeat(64)}` };
  expect(replicaAwaitingFinality(e, slot)).toBe(true);
  // The head is the slot the chain already holds: no registration is in flight.
  e.head!.version = "3";
  expect(replicaAwaitingFinality(e, slot)).toBe(false);
});
it("an inactive finalized slot is a Wait for a receiver that has not fetched it", () => {
  const commitment = replicaChainCommitment(dataHash, metadataHash);
  const e = waiting();
  e.chain = {
    ...e.chain!,
    currentVersion: "1",
    status: "Unavailable",
    commitment,
  };
  const unfetched = { owner, scope, version: 1 };
  const fetched = { ...unfetched, dataHash, metadataHash };
  expect(replicaRegistrationInactive(e, unfetched)).toBe(true);
  expect(replicaRegistrationInactive(e, fetched)).toBe(true);
  // No finalized commitment at the slot: nothing is registered to reactivate.
  e.chain.commitment = `0x${"0".repeat(64)}`;
  expect(replicaRegistrationInactive(e, unfetched)).toBe(false);
  // A different finalized commitment is a conflict for a receiver that knows
  // the expected pair, never a Wait.
  e.chain.commitment = `0x${"8".repeat(64)}`;
  expect(replicaRegistrationInactive(e, fetched)).toBe(false);
  // Active again: no longer inactive.
  e.chain = { ...e.chain, status: "Active", commitment };
  expect(replicaRegistrationInactive(e, unfetched)).toBe(false);
});
