/**
 * Who may write (host contract §3). A device signs each batch with its
 * registered PS server key. Writer ids are derived from that signer, so a
 * receiver checks them from the signature and the roster alone. Nothing is
 * bound on first contact.
 */
import { z } from "zod";
import {
  bytesToHex,
  concatBytes,
  hexToBytes,
  recoverTypedDataAddress,
  sha256,
  stringToBytes,
  type Hex,
} from "viem";
import {
  ReplicaRosterUnavailableError,
  type ReplicaRosterRecord,
} from "./roster.js";

export const REPLICA_WRITER_DOMAIN = "vana-pdpp-replica-writer-v1";
export type ReplicaWriterRole = "transport" | "operation";
export type ReplicaEnvironment = "dev" | "prod";

const address = z.string().regex(/^0x[0-9a-f]{40}$/);
const bytes32 = z.string().regex(/^0x[0-9a-f]{64}$/);
const bytes16 = z.string().regex(/^0x[0-9a-f]{32}$/);
const uint = (max: number) => z.number().int().min(1).max(max);
const UINT32_MAX = 2 ** 32 - 1;

/** Everything a writer id is derived from. Hex values are lowercase. */
export const replicaWriterSeedSchema = z.strictObject({
  /** The owner wallet. */
  owner: address,
  /** The signing server address. */
  server: address,
  /** The signer's gateway registration id: its incarnation. */
  serverId: bytes32,
  /** Disclosed in every statement; rotated on reset, new database and restore. */
  writerNonce: bytes16,
});
export type ReplicaWriterSeed = z.infer<typeof replicaWriterSeedSchema>;
export interface ReplicaWriters {
  transport: string;
  operation: string;
}

/**
 * writerId(role) = first 16 bytes of SHA-256 over the length-prefixed domain
 * tag, owner, server, serverId, role and writer nonce. Each field is its byte
 * length (4 bytes, big-endian) then its bytes. 32 lowercase hex characters.
 */
export function deriveReplicaWriterId(
  seed: ReplicaWriterSeed,
  role: ReplicaWriterRole,
): string {
  const s = replicaWriterSeedSchema.parse(seed);
  const fields = [
    stringToBytes(REPLICA_WRITER_DOMAIN),
    hexToBytes(s.owner as Hex),
    hexToBytes(s.server as Hex),
    hexToBytes(s.serverId as Hex),
    stringToBytes(role),
    hexToBytes(s.writerNonce as Hex),
  ];
  const framed = concatBytes(
    fields.flatMap((field) => {
      const length = new Uint8Array(4);
      new DataView(length.buffer).setUint32(0, field.length);
      return [length, field];
    }),
  );
  return sha256(framed, "hex").slice(2, 34);
}

/** The transport and operation writers of one seed. They always come as a pair. */
export function deriveReplicaWriters(seed: ReplicaWriterSeed): ReplicaWriters {
  return {
    transport: deriveReplicaWriterId(seed, "transport"),
    operation: deriveReplicaWriterId(seed, "operation"),
  };
}

/** A fresh 16-byte writer nonce. */
export function randomReplicaWriterNonce(): string {
  return bytesToHex(globalThis.crypto.getRandomValues(new Uint8Array(16)));
}

/** The signed batch statement (EIP-712 `PdppReplicaBatch`). */
export const replicaBatchStatementSchema = z.strictObject({
  owner: address,
  server: address,
  serverId: bytes32,
  environment: z.enum(["dev", "prod"]),
  writerNonce: bytes16,
  batch: z.string().regex(/^[a-f0-9]{32}$/),
  sequence: uint(Number.MAX_SAFE_INTEGER),
  /** Digest of the previous batch, or zero for sequence 1. */
  previous: bytes32,
  /** SHA-256 of the assembled batch. */
  digest: bytes32,
  totalBytes: uint(Number.MAX_SAFE_INTEGER),
  count: uint(UINT32_MAX),
});
export type ReplicaBatchStatement = z.infer<typeof replicaBatchStatementSchema>;

/** The statement, its signature and the EIP-712 domain chain it was signed for. */
export const replicaBatchAuthoritySchema = z.strictObject({
  chainId: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
  statement: replicaBatchStatementSchema,
  signature: z.string().regex(/^0x[0-9a-f]{130}$/),
});
export type ReplicaBatchAuthority = z.infer<typeof replicaBatchAuthoritySchema>;

const BATCH_TYPES = {
  PdppReplicaBatch: [
    { name: "owner", type: "address" },
    { name: "server", type: "address" },
    { name: "serverId", type: "bytes32" },
    { name: "environment", type: "string" },
    { name: "writerNonce", type: "bytes16" },
    { name: "batch", type: "string" },
    { name: "sequence", type: "uint64" },
    { name: "previous", type: "bytes32" },
    { name: "digest", type: "bytes32" },
    { name: "totalBytes", type: "uint64" },
    { name: "count", type: "uint32" },
  ],
} as const;

/** EIP-712 typed data for one statement: domain "Vana PDPP Replica", version "1". */
export function replicaBatchTypedData(
  chainId: number,
  statement: ReplicaBatchStatement,
) {
  return {
    domain: { name: "Vana PDPP Replica", version: "1", chainId },
    types: BATCH_TYPES,
    primaryType: "PdppReplicaBatch" as const,
    message: {
      ...statement,
      owner: statement.owner as Hex,
      server: statement.server as Hex,
      serverId: statement.serverId as Hex,
      writerNonce: statement.writerNonce as Hex,
      previous: statement.previous as Hex,
      digest: statement.digest as Hex,
      sequence: BigInt(statement.sequence),
      totalBytes: BigInt(statement.totalBytes),
      count: statement.count,
    },
  };
}

/** The registered PS server key: Node `key.json` or the Lite server identity. */
export interface ReplicaBatchSigner {
  address: string;
  signTypedData(
    params: ReturnType<typeof replicaBatchTypedData>,
  ): Promise<`0x${string}`>;
}

/** What one receiver accepts: its own owner, chain and environment. */
export interface ReplicaPartition {
  owner: string;
  chainId: number;
  environment: ReplicaEnvironment;
}

/** What the carrier claims about a batch; the statement must sign exactly this. */
export interface ReplicaBatchFacts {
  batch: string;
  sequence: number;
  previous: { batch: string; digest: string } | null;
  /** `sha256:<hex>` of the assembled batch. */
  digest: string;
  totalBytes: number;
  count: number;
}

const ZERO32 = `0x${"0".repeat(64)}`;
const digestBytes = (digest: string) => `0x${digest.replace(/^sha256:/, "")}`;

function statementOf(
  partition: ReplicaPartition,
  seed: ReplicaWriterSeed,
  facts: ReplicaBatchFacts,
): ReplicaBatchStatement {
  return replicaBatchStatementSchema.parse({
    ...seed,
    environment: partition.environment,
    batch: facts.batch,
    sequence: facts.sequence,
    previous: facts.previous ? digestBytes(facts.previous.digest) : ZERO32,
    digest: digestBytes(facts.digest),
    totalBytes: facts.totalBytes,
    count: facts.count,
  });
}

/** Sign one batch with the server key. The signer must be the seed's server. */
export async function signReplicaBatch(input: {
  signer: ReplicaBatchSigner;
  partition: ReplicaPartition;
  seed: ReplicaWriterSeed;
  facts: ReplicaBatchFacts;
}): Promise<ReplicaBatchAuthority> {
  const { signer, partition, seed } = input;
  if (
    signer.address.toLowerCase() !== seed.server ||
    partition.owner.toLowerCase() !== seed.owner
  )
    throw new Error("replica signer is not the writer seed's server");
  const statement = statementOf(partition, seed, input.facts);
  const signature = await signer.signTypedData(
    replicaBatchTypedData(partition.chainId, statement),
  );
  return replicaBatchAuthoritySchema.parse({
    chainId: partition.chainId,
    statement,
    signature: signature.toLowerCase(),
  });
}

/** Typed refusals; each one quarantines only the item that failed. */
export type ReplicaAuthorityRefusal =
  | "signature_invalid"
  | "partition_mismatch"
  | "server_not_registered"
  | "roster_owner_mismatch"
  | "writer_mismatch";

export type ReplicaAuthorityVerdict =
  | {
      tag: "authorized";
      seed: ReplicaWriterSeed;
      writers: ReplicaWriters;
    }
  | { tag: "refused"; reason: ReplicaAuthorityRefusal }
  /** The roster could not be read and no fresh answer is cached. */
  | { tag: "wait"; server: string };

// Recovery is pure; one batch's fragments share a statement.
const recovered = new Map<string, string>();
async function recoverSigner(authority: ReplicaBatchAuthority) {
  const key = JSON.stringify(authority);
  let signer = recovered.get(key);
  if (signer === undefined) {
    signer = (
      await recoverTypedDataAddress({
        ...replicaBatchTypedData(authority.chainId, authority.statement),
        signature: authority.signature as Hex,
      })
    ).toLowerCase();
    recovered.set(key, signer);
    if (recovered.size > 1024) recovered.delete(recovered.keys().next().value!);
  }
  return signer;
}

/**
 * Receiver checks 2-5 of host contract §3.4, in order. The carrier supplies
 * its claimed facts and transport writer, so this does not depend on how the
 * carrier names objects (per-fragment scopes or a per-sync manifest).
 * `roster` throws when it cannot answer; that is a Wait, never acceptance.
 */
export async function authorizeReplicaBatch(input: {
  authority: unknown;
  facts: ReplicaBatchFacts;
  transportWriter: string;
  receiver: ReplicaPartition;
  roster: (server: `0x${string}`) => Promise<ReplicaRosterRecord | null>;
}): Promise<ReplicaAuthorityVerdict> {
  const refused = (reason: ReplicaAuthorityRefusal) =>
    ({ tag: "refused", reason }) as const;
  // 2. The signer signed exactly these facts.
  const parsed = replicaBatchAuthoritySchema.safeParse(input.authority);
  if (!parsed.success) return refused("signature_invalid");
  const authority = parsed.data;
  const { statement } = authority;
  const { facts } = input;
  if (
    statement.batch !== facts.batch ||
    statement.sequence !== facts.sequence ||
    statement.previous !==
      (facts.previous ? digestBytes(facts.previous.digest) : ZERO32) ||
    statement.digest !== digestBytes(facts.digest) ||
    statement.totalBytes !== facts.totalBytes ||
    statement.count !== facts.count
  )
    return refused("signature_invalid");
  let signer: string;
  try {
    signer = await recoverSigner(authority);
  } catch {
    return refused("signature_invalid");
  }
  if (signer !== statement.server) return refused("signature_invalid");
  // 3. Partition.
  if (
    statement.owner !== input.receiver.owner.toLowerCase() ||
    authority.chainId !== input.receiver.chainId ||
    statement.environment !== input.receiver.environment
  )
    return refused("partition_mismatch");
  // 4. Roster: registered now, this incarnation, under this owner.
  let record: ReplicaRosterRecord | null;
  try {
    record = await input.roster(statement.server as `0x${string}`);
  } catch (error) {
    if (error instanceof ReplicaRosterUnavailableError)
      return { tag: "wait", server: statement.server };
    throw error;
  }
  if (!record) return refused("server_not_registered");
  if (record.owner.toLowerCase() !== statement.owner)
    return refused("roster_owner_mismatch");
  if (
    record.revokedAt !== null ||
    record.id.toLowerCase() !== statement.serverId
  )
    return refused("server_not_registered");
  // 5. The carrier's writer is the one this signer derives.
  const seed = replicaWriterSeedSchema.parse({
    owner: statement.owner,
    server: statement.server,
    serverId: statement.serverId,
    writerNonce: statement.writerNonce,
  });
  const writers = deriveReplicaWriters(seed);
  if (input.transportWriter !== writers.transport)
    return refused("writer_mismatch");
  return { tag: "authorized", seed, writers };
}

/** Check 7: every operation of an authorized batch names its operation writer. */
export function replicaOperationWriterRefusal(
  operations: readonly { revision: { writerId: string } }[],
  writers: ReplicaWriters,
): "writer_mismatch" | undefined {
  return operations.every((op) => op.revision.writerId === writers.operation)
    ? undefined
    : "writer_mismatch";
}
