/** Writer authority for replica tests. Never wire these into a host. */
import type { Database } from "better-sqlite3";
import {
  type createTestReplicaRoster,
  createTestReplicaSigner,
} from "@opendatalabs/personal-server-ts-core/replication/writer-identity.test-utils";
import {
  deriveReplicaWriters,
  randomReplicaWriterNonce,
  signReplicaBatch,
  type ReplicaBatchFacts,
} from "@opendatalabs/personal-server-ts-core/replication/writer-identity";
import { establishReplicaWriterIdentity } from "./pdpp-replica-writer-identity.js";

export const REPLICA_TEST_CHAIN_ID = 14800;
export type TestReplicaRoster = ReturnType<typeof createTestReplicaRoster>;

/**
 * One device's worker `authority` dependency over a shared test roster. A
 * name gives the same server key in every process.
 */
export function replicaTestAuthority(roster: TestReplicaRoster, name?: string) {
  const signer = createTestReplicaSigner(name);
  return {
    signer,
    roster: roster.port,
    chainId: REPLICA_TEST_CHAIN_ID,
    environment: "dev" as const,
  };
}

/**
 * Register the device under `owner` and establish its writer identity. Call
 * it before `beginBaseline`, like the first enable.
 */
export function enableReplicaTestIdentity(
  db: Database,
  input: {
    owner: string;
    roster: TestReplicaRoster;
    authority: ReturnType<typeof replicaTestAuthority>;
    /** Fixed registration id and nonce, for seeded runs. */
    serverId?: string;
    nonce?: string;
  },
) {
  const { address } = input.authority.signer;
  const id = input.roster.register(address, input.owner, input.serverId);
  return establishReplicaWriterIdentity(db, {
    owner: input.owner,
    server: address,
    record: { owner: input.owner, id, revokedAt: null },
    nonce: input.nonce,
  });
}

/**
 * A registered remote device for tests that build its batches by hand:
 * fragments use `writers.transport`, operations name `writers.operation`,
 * and `sign` is the fragmenter's `sign`.
 */
export function remoteReplicaTestWriter(
  roster: TestReplicaRoster,
  owner: string,
) {
  const signer = createTestReplicaSigner();
  const seed = {
    owner: owner.toLowerCase(),
    server: signer.address.toLowerCase(),
    serverId: roster.register(signer.address, owner),
    writerNonce: randomReplicaWriterNonce(),
  };
  return {
    signer,
    seed,
    writers: deriveReplicaWriters(seed),
    sign: (facts: ReplicaBatchFacts) =>
      signReplicaBatch({
        signer,
        partition: {
          owner,
          chainId: REPLICA_TEST_CHAIN_ID,
          environment: "dev",
        },
        seed,
        facts,
      }),
  };
}
