/** Test doubles for replica writer authority. Never wire these into a host. */
import { bytesToHex, sha256, stringToBytes } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import {
  ReplicaRosterUnavailableError,
  type ReplicaRosterPort,
  type ReplicaRosterRecord,
} from "./roster.js";
import type {
  ReplicaBatchAuthority,
  ReplicaBatchFacts,
  ReplicaBatchSigner,
} from "./writer-identity.js";

const random32 = () =>
  bytesToHex(globalThis.crypto.getRandomValues(new Uint8Array(32)));

/**
 * Framing-only: a well-formed statement for `facts` with an invalid
 * signature. Tests of byte framing use it; no receiver authorizes it.
 */
export async function unsignedReplicaBatch(
  facts: ReplicaBatchFacts,
): Promise<ReplicaBatchAuthority> {
  const digest = (value: string) => `0x${value.replace(/^sha256:/, "")}`;
  return {
    chainId: 1,
    statement: {
      owner: `0x${"0".repeat(39)}1`,
      server: `0x${"0".repeat(39)}2`,
      serverId: `0x${"0".repeat(64)}`,
      environment: "dev",
      writerNonce: `0x${"0".repeat(32)}`,
      batch: facts.batch,
      sequence: facts.sequence,
      previous: facts.previous
        ? digest(facts.previous.digest)
        : `0x${"0".repeat(64)}`,
      digest: digest(facts.digest),
      totalBytes: facts.totalBytes,
      count: facts.count,
    },
    signature: `0x${"0".repeat(130)}`,
  };
}

/** An in-memory gateway roster with registration, revocation and outages. */
export function createTestReplicaRoster() {
  const records = new Map<string, ReplicaRosterRecord>();
  let available = true;
  let reads = 0;
  const port: ReplicaRosterPort = {
    async server(address) {
      reads++;
      if (!available) throw new ReplicaRosterUnavailableError();
      const record = records.get(address.toLowerCase());
      return record ? { ...record } : null;
    },
  };
  return {
    port,
    get reads() {
      return reads;
    },
    setAvailable(value: boolean) {
      available = value;
    },
    /** Register, or re-register a revoked address under a new id. */
    register(address: string, owner: string, id: string = random32()) {
      records.set(address.toLowerCase(), { owner, id, revokedAt: null });
      return id;
    },
    deregister(address: string) {
      const record = records.get(address.toLowerCase())!;
      records.set(address.toLowerCase(), {
        ...record,
        revokedAt: "2026-10-27T00:00:00.000Z",
      });
    },
  };
}

/**
 * A device's server key: a real secp256k1 account, like `key.json`. A name
 * gives the same key in every process.
 */
export function createTestReplicaSigner(name?: string): ReplicaBatchSigner & {
  address: `0x${string}`;
} {
  const account = privateKeyToAccount(
    name === undefined
      ? generatePrivateKey()
      : sha256(stringToBytes(`replica-test-signer:${name}`)),
  );
  return {
    address: account.address,
    signTypedData: (params) => account.signTypedData(params),
  };
}
