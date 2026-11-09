/**
 * The minimal fixtures a publish needs, without the rest of oracle.test-utils.
 * The publish runs in a child process whose peak is measured, so its module
 * graph must stay small: loading the whole test-utils graph costs ~350 MiB of
 * heap and makes every forced GC slow. Behaviour matches the test-utils
 * versions these copy (same keys, same exclusive-version registry semantics).
 */

import { privateKeyToAccount } from "viem/accounts";
import {
  bindStreamSyncHome,
  streamSyncHashes,
  type RegistryPostResult,
  type SignedRegistryPost,
  type StreamSyncFiles,
  type StreamSyncRegistry,
  type StreamSyncSigner,
  type StreamSyncWriter,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import { createServerSigner } from "@opendatalabs/personal-server-ts-core/signing";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import {
  TOMBSTONE_DATA_LABEL,
  TOMBSTONE_METADATA_LABEL,
  keccakHex,
  parseScope,
  utf8,
  type ControlRead,
  type HeadProfile,
} from "@opendatalabs/personal-server-ts-stream-sync";

/** Anvil's well-known test accounts #0 (owner) and #2 (registered server). */
export const OWNER_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
export const SERVER_KEY =
  "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";
export const OWNER = privateKeyToAccount(OWNER_KEY).address;
/** OWNER_KEY's signature over the master-key message (deterministic). */
export const OWNER_SIGNATURE =
  "0x1f5c9b3bafc291e8ea7aa4e0c5700a109e68aa2431fdbea08b49f9bf91b5c7db2aaa192de5cdf866e5f9f5f39502a66bd696a1399a537eac8ffb826c00e4e1d51b";

const GATEWAY = ServerConfigSchema.parse({}).gateway;
const GATEWAY_CONFIG = {
  chainId: GATEWAY.chainId,
  contracts: GATEWAY.contracts,
};

export const PROFILE: HeadProfile = { key: null, version: "1.0.0" };
export const SHAPE = { primaryKey: ["id"], profile: PROFILE } as const;

export function accountSigner(key: `0x${string}`): StreamSyncSigner {
  const account = privateKeyToAccount(key);
  return createServerSigner(
    {
      address: account.address,
      publicKey: account.publicKey,
      signTypedData: (params) =>
        account.signTypedData(
          params as Parameters<typeof account.signTypedData>[0],
        ),
      signMessage: (message) => account.signMessage({ message }),
    },
    GATEWAY_CONFIG,
  );
}

interface Version {
  readonly dataHash: string;
  readonly metadataHash: string;
}

/**
 * Exclusive-version semantics of the gateway: POST at `current + 1` writes;
 * the identical row at an existing version answers 2xx and writes nothing
 * (replay); anything else is 409 with the latest version.
 */
export function createFakeStreamSyncRegistry(): StreamSyncRegistry {
  const rows = new Map<string, Version[]>();
  const tombstone = async () => ({
    dataHash: await keccakHex(
      streamSyncHashes.keccak256,
      utf8(TOMBSTONE_DATA_LABEL),
    ),
    metadataHash: await keccakHex(
      streamSyncHashes.keccak256,
      utf8(TOMBSTONE_METADATA_LABEL),
    ),
  });
  const read = async (scope: string): Promise<ControlRead> => {
    const versions = rows.get(scope);
    if (!versions || versions.length === 0) return { found: false };
    const head = versions[versions.length - 1]!;
    const t = await tombstone();
    return {
      found: true,
      version: versions.length,
      dataHash: head.dataHash,
      metadataHash: head.metadataHash,
      deleted:
        head.dataHash === t.dataHash && head.metadataHash === t.metadataHash,
    };
  };
  return {
    read,
    async post(request: SignedRegistryPost): Promise<RegistryPostResult> {
      const versions = rows.get(request.scope) ?? [];
      const version = Number(request.expectedVersion);
      const existing = versions[version - 1];
      if (
        existing &&
        existing.dataHash === request.dataHash &&
        existing.metadataHash === request.metadataHash
      ) {
        return { kind: "committed" };
      }
      if (version !== versions.length + 1) {
        return { kind: "conflict", latestVersion: String(versions.length) };
      }
      versions.push({
        dataHash: request.dataHash,
        metadataHash: request.metadataHash,
      });
      rows.set(request.scope, versions);
      return { kind: "committed" };
    },
    async listControlRows() {
      const out: { scope: string; read: ControlRead }[] = [];
      for (const scope of rows.keys()) {
        if (parseScope(scope)?.kind === "control") {
          out.push({ scope, read: await read(scope) });
        }
      }
      return out;
    },
  };
}

/** A home for the device's files, bound to the test owner. */
export function testStreamSyncHome(files: StreamSyncFiles) {
  return bindStreamSyncHome({
    ownerAddress: OWNER,
    network: "test",
    open: () => files,
  });
}

export function finishedOutcome(
  status: Awaited<ReturnType<StreamSyncWriter["status"]>>,
  runId: string,
) {
  return status.finished.find((r) => r.runId === runId) ?? null;
}
