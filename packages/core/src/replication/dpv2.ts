import {
  decryptWithPassword,
  deriveScopeKey,
  encryptWithPassword,
  type GatewayClient,
} from "@opendatalabs/vana-sdk/browser";
import { bytesToHex } from "viem";
import type { StorageAdapter } from "../storage/adapters/interface.js";
import type { DataPointFeedPort } from "../ports/index.js";
import type { ServerSigner } from "../signing/signer.js";
import type { PreparedFragment } from "./transport.js";

export interface ReplicaCommitment {
  owner: string;
  scope: string;
  version: string;
  dataHash: string;
  metadataHash: string;
  deleted: boolean;
}
/** All three sources are mandatory. A denormalized GET head alone is insufficient. */
export interface ReplicaRegistrationEvidence {
  head: ReplicaCommitment | null;
  history: ReplicaCommitment | null;
  chain: ReplicaCommitment | null;
  pending: boolean;
}
export interface ReplicaTransportPort {
  encrypt(scope: string, plaintext: Uint8Array): Promise<Uint8Array>;
  decrypt(scope: string, encrypted: Uint8Array): Promise<Uint8Array>;
  evidence(scope: string): Promise<ReplicaRegistrationEvidence>;
  put(fragment: PreparedFragment): Promise<void>;
  register(fragment: PreparedFragment): Promise<void>;
  get(scope: string): Promise<Uint8Array>;
  list(
    cursor: string | null,
  ): Promise<{ scopes: string[]; cursor: string | null }>;
}

/** Uses existing DPv2 crypto, storage keying, AddData signing and owner feed. No file-head rebase. */
export function createDpv2ReplicaTransport(deps: {
  owner: `0x${string}`;
  masterKey: Uint8Array;
  storage: StorageAdapter;
  gateway: Pick<GatewayClient, "registerDataPoint">;
  feed: DataPointFeedPort;
  signer: Pick<ServerSigner, "signAddData">;
  /** Host verifies version history + finalized chain as well as the head, including absence.
   * SDK head-only lookup cannot implement this port. No production fallback is allowed. */
  evidence: (scope: string) => Promise<ReplicaRegistrationEvidence>;
}): ReplicaTransportPort {
  const password = (scope: string) =>
    bytesToHex(deriveScopeKey(deps.masterKey, scope)).slice(2);
  return {
    encrypt: (scope, bytes) => encryptWithPassword(bytes, password(scope)),
    decrypt: (scope, bytes) => decryptWithPassword(bytes, password(scope)),
    evidence: deps.evidence,
    async put(fragment) {
      await deps.storage.upload(`${fragment.scope}/1`, fragment.encrypted);
    },
    async register(fragment) {
      const msg = {
        ownerAddress: deps.owner,
        scope: fragment.scope,
        dataHash: fragment.dataHash,
        metadataHash: fragment.metadataHash,
        expectedVersion: 1n,
      };
      await deps.gateway.registerDataPoint({
        ...msg,
        expectedVersion: "1",
        signature: await deps.signer.signAddData(msg),
      });
    },
    get: (scope) => deps.storage.download(deps.storage.urlForKey(`${scope}/1`)),
    async list(cursor) {
      const page = await deps.feed.listDataPointsByOwner(deps.owner, cursor, {
        includeDeleted: true,
      });
      // The subsequent evidence lookup verifies owner, version, settlement and deletion.
      return {
        scopes: page.dataPoints.map((p) => p.scope),
        cursor: page.cursor,
      };
    },
  };
}

export function replicaRegistrationState(
  evidence: ReplicaRegistrationEvidence,
  expected: {
    owner: string;
    scope: string;
    dataHash?: string;
    metadataHash?: string;
  },
): "absent" | "pending" | "confirmed" | "conflict" {
  const rows = [evidence.head, evidence.history, evidence.chain];
  const present = rows.filter((r): r is ReplicaCommitment => r !== null);
  for (const row of present) {
    if (
      row.owner !== expected.owner ||
      row.scope !== expected.scope ||
      row.version !== "1" ||
      row.deleted ||
      (expected.dataHash !== undefined && row.dataHash !== expected.dataHash) ||
      (expected.metadataHash !== undefined &&
        row.metadataHash !== expected.metadataHash)
    )
      return "conflict";
  }
  if (
    present.some(
      (r) =>
        r.dataHash !== present[0]!.dataHash ||
        r.metadataHash !== present[0]!.metadataHash,
    )
  )
    return "conflict";
  if (evidence.pending) return "pending";
  if (present.length === 0) return "absent";
  return present.length === 3 ? "confirmed" : "conflict";
}
