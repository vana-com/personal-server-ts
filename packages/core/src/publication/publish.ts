import {
  DataFileEnvelopeSchema,
  decryptWithPassword,
  deriveScopeKey,
  encryptWithPassword,
  type DataFileEnvelope,
  type GatewayClient,
} from "@opendatalabs/vana-sdk/browser";
import { keccak256, stringToHex } from "viem";
import { isTombstoneRecord } from "../sync/tombstone.js";
import { readStoredLineage } from "../lineage/lineage.js";
import type { LineageGatewayPort } from "../lineage/gateway.js";
import type { ServerSigner } from "../signing/signer.js";
import {
  StoredBlobConflictError,
  type StorageAdapter,
} from "../storage/adapters/interface.js";

export interface PublicationRecord {
  id: string;
  expectedVersion: string;
  dataHash: string;
  metadataHash: string;
  deletedAt?: string | null;
  addedAt?: string;
}
export interface PublicationFence {
  generation: string;
  head: PublicationRecord | null;
}
export type PublicationContentClass = "canonical" | "legacy";
export interface PublicationRegistrationAuthority {
  /** Serialize the remote head change with local canonical takeover. */
  withRegistration<T>(
    scope: string,
    contentClass: PublicationContentClass,
    register: () => Promise<T>,
  ): Promise<T>;
}
export class HistoryOnlyVersionError extends Error {
  readonly code = "HISTORY_ONLY_VERSION";
  constructor(readonly scope: string) {
    super(`Legacy version for ${scope} is retained as history`);
    this.name = "HistoryOnlyVersionError";
  }
}
type Registration = Parameters<GatewayClient["registerDataPoint"]>[0] & {
  lineage?: readonly string[];
  lineageSignature?: string;
};
/** Proposed gateway contract; the legacy SDK is NOT this capability. */
export interface FencedPublicationPort {
  read(input: {
    ownerAddress: string;
    scope: string;
  }): Promise<PublicationFence>;
  commit(
    input: Registration & {
      mode: "register" | "adopt";
      fence: PublicationFence;
    },
  ): Promise<{ dataPointId: string; fence: PublicationFence }>;
}

export class NeedsFencedPublicationError extends Error {
  readonly code = "NEEDS_FENCED_PUBLICATION";
  constructor(
    readonly scope: string,
    readonly reason: string,
    readonly retryable: boolean = true,
  ) {
    super(`Needs fenced publication for ${scope}: ${reason}`);
    this.name = "NeedsFencedPublicationError";
  }
}

export interface PublicationResult {
  version: bigint;
  url: string;
  dataPointId: string;
  sizeBytes: number;
  dataHash: string;
  metadataHash: string;
}
export interface PublishOptions {
  ownerAddress: string;
  envelope: DataFileEnvelope;
  preferredVersion: bigint;
  masterKey: Uint8Array;
  storageAdapter: StorageAdapter;
  signer: Pick<ServerSigner, "signAddData"> &
    Partial<Pick<ServerSigner, "signLineageAttestation">>;
  gateway: Pick<GatewayClient, "registerDataPoint">;
  lineageGateway?: Pick<LineageGatewayPort, "registerDataPoint">;
  fencedPublication?: FencedPublicationPort;
  registrationAuthority?: PublicationRegistrationAuthority;
  publicationClass?: PublicationContentClass;
  /** Undefined means the caller has no initial registry observation. */
  head?: PublicationRecord | null;
  readHead(): Promise<PublicationRecord | null>;
  /** Caller applies its own local tombstone/drop semantics on every read. */
  checkHead?(head: PublicationRecord | null): Promise<void>;
  acknowledgedDeletionVersion?: bigint;
}

const sameHash = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();
function metadata(scope: string, collectedAt: string, sizeBytes: number) {
  return keccak256(
    stringToHex(JSON.stringify({ scope, collectedAt, sizeBytes })),
  );
}

/** Full-envelope preparation and verification for the shared publication owner. */
export async function publishVersion(
  options: PublishOptions,
): Promise<PublicationResult> {
  const { envelope, storageAdapter } = options;
  const { scope } = envelope;
  const password = Array.from(
    deriveScopeKey(options.masterKey, scope),
    (byte) => byte.toString(16).padStart(2, "0"),
  ).join("");
  const plaintext = new TextEncoder().encode(JSON.stringify(envelope));
  const lineage = readStoredLineage(envelope.data as Record<string, unknown>);
  function candidate(
    env: DataFileEnvelope,
    bytes: Uint8Array,
    hash: `0x${string}`,
  ): PublicationCandidate {
    return {
      dataHash: hash,
      metadataHash: metadata(scope, env.collectedAt, bytes.byteLength),
      sizeBytes: bytes.byteLength,
      lineage: readStoredLineage(env.data as Record<string, unknown>),
    };
  }
  return publishPreparedVersion({
    ...options,
    scope,
    storageAdapter,
    async prepare() {
      const encrypted = await encryptWithPassword(plaintext, password);
      return {
        encrypted,
        wanted: {
          ...candidate(envelope, encrypted, keccak256(plaintext)),
          lineage,
        },
        async verifyStored(bytes) {
          const clear = await decryptWithPassword(bytes, password);
          const env = DataFileEnvelopeSchema.parse(
            JSON.parse(new TextDecoder().decode(clear)),
          );
          if (
            env.scope !== scope ||
            !Number.isFinite(Date.parse(env.collectedAt))
          )
            throw new Error("Publication envelope scope/timestamp mismatch");
          return candidate(env, bytes, keccak256(clear));
        },
      };
    },
  });
}

export interface PublicationCandidate {
  dataHash: `0x${string}`;
  metadataHash: `0x${string}`;
  sizeBytes: number;
  lineage: ReturnType<typeof readStoredLineage>;
}
export interface PreparedPublication {
  encrypted: Uint8Array;
  wanted: PublicationCandidate;
  /** Authenticate the complete stored envelope and derive its commitments.
   * A bounded host may instead prove byte equality with its authenticated journal.
   */
  verifyStored(bytes: Uint8Array): Promise<PublicationCandidate>;
}
export interface PreparedPublishOptions extends Omit<
  PublishOptions,
  "envelope" | "masterKey"
> {
  scope: string;
  /** Called only after the initial deletion/fence check. */
  prepare(): Promise<PreparedPublication>;
}

/** Single reserve/upload/register/recover policy for full and bounded hosts.
 * No deletion/reclaim effect is permitted here. Retries derive evidence from
 * storage and the registry, never from an abandoned attempt's local URL. */
export async function publishPreparedVersion(
  options: PreparedPublishOptions,
): Promise<PublicationResult> {
  const { scope, storageAdapter, fencedPublication, signer } = options;
  const isDeleted = (row: PublicationRecord) =>
    Boolean(row.deletedAt) || isTombstoneRecord(row);
  let fence = await fencedPublication?.read({
    ownerAddress: options.ownerAddress,
    scope,
  });
  let head = fence ? fence.head : options.head;
  await options.checkHead?.(head ?? null);
  function requireFence(reason: string): PublicationFence {
    if (!fence) throw new NeedsFencedPublicationError(scope, reason);
    return fence;
  }
  function checkDeletion() {
    if (!head || !isDeleted(head)) return;
    requireFence("publication crosses a deletion");
    if (options.acknowledgedDeletionVersion !== BigInt(head.expectedVersion))
      throw new NeedsFencedPublicationError(
        scope,
        "tombstone was not acknowledged by this publication",
      );
  }
  checkDeletion();
  const { encrypted, wanted, verifyStored } = await options.prepare();
  const wantedHash = wanted.dataHash;
  const keyUrl = (version: bigint) =>
    storageAdapter.urlForKey(`${scope}/${version}`);
  async function readCandidate(version: bigint): Promise<PublicationCandidate> {
    const bytes = await storageAdapter.download(keyUrl(version));
    return verifyStored(bytes);
  }
  async function commit(
    version: bigint,
    value: PublicationCandidate,
    mode: "register" | "adopt",
  ) {
    const request = {
      ownerAddress: options.ownerAddress,
      scope,
      dataHash: value.dataHash,
      metadataHash: value.metadataHash,
      expectedVersion: String(version),
      signature: await signer.signAddData({
        ownerAddress: options.ownerAddress as `0x${string}`,
        scope,
        dataHash: value.dataHash,
        metadataHash: value.metadataHash,
        expectedVersion: version,
      }),
    };
    const lineage = value.lineage;
    let lineageFields:
      { lineage: readonly string[]; lineageSignature: string } | undefined;
    if (lineage) {
      if (
        !signer.signLineageAttestation ||
        (!fencedPublication && !options.lineageGateway)
      )
        throw new Error(
          `Cannot register derivative ${scope}: lineage registration needs a gateway URL (lineageGateway is not configured)`,
        );
      lineageFields = {
        lineage: lineage.sources,
        lineageSignature: await signer.signLineageAttestation({
          ownerAddress: options.ownerAddress as `0x${string}`,
          scope,
          expectedVersion: version,
          dataHash: value.dataHash,
          sources: lineage.sources,
        }),
      };
    }
    const register = async (): Promise<string | undefined> => {
      if (fencedPublication) {
        const previous = requireFence("registration/adoption");
        const result = await fencedPublication.commit({
          ...request,
          ...lineageFields,
          mode,
          fence: previous,
        });
        const registered = result.fence.head;
        if (
          result.fence.generation !== previous.generation ||
          !registered ||
          isDeleted(registered) ||
          registered.expectedVersion !== String(version) ||
          !sameHash(registered.dataHash, value.dataHash) ||
          !sameHash(registered.metadataHash, value.metadataHash) ||
          registered.id !== result.dataPointId
        )
          throw new Error("Gateway returned inconsistent publication evidence");
        fence = result.fence;
        head = registered;
        return result.dataPointId;
      }
      if (mode === "adopt") {
        // No remote effect: the caller verified the live row's stored bytes.
        return head?.id;
      }
      const result = lineageFields
        ? await options.lineageGateway!.registerDataPoint({
            ...request,
            ...lineageFields,
          })
        : await options.gateway.registerDataPoint(request);
      return result.dataPointId;
    };
    const id: string | undefined =
      (mode === "register" || Boolean(fencedPublication)) &&
      options.registrationAuthority
        ? await options.registrationAuthority.withRegistration(
            scope,
            options.publicationClass ?? "canonical",
            register,
          )
        : await register();
    if (!id)
      throw new Error(
        `Gateway registerDataPoint did not return a dataPointId for ${scope} version ${version}`,
      );
    return {
      version,
      url: keyUrl(version),
      dataPointId: id,
      sizeBytes: value.sizeBytes,
      dataHash: value.dataHash,
      metadataHash: value.metadataHash,
    };
  }
  // An observed head decides the next version. A local version ahead of the
  // registry would leave our bytes at a future key that later wedges it.
  let version =
    head === undefined
      ? options.preferredVersion
      : BigInt(head?.expectedVersion ?? "0") + 1n;
  let rebased = false;
  for (let step = 0; step < 4; step++) {
    checkDeletion();
    if (head && !isDeleted(head) && sameHash(head.dataHash, wantedHash)) {
      version = BigInt(head.expectedVersion);
      const url = keyUrl(version);
      if (!(await storageAdapter.exists(url))) {
        // Recreating bytes can race a delete's cleanup; that needs the fence.
        requireFence("healing a committed version's missing bytes");
        if (!sameHash(wanted.metadataHash, head.metadataHash))
          throw new Error(
            "Missing committed blob cannot be healed: metadata commitment mismatch",
          );
        try {
          await storageAdapter.upload(`${scope}/${version}`, encrypted);
        } catch (error) {
          if (!(error instanceof StoredBlobConflictError)) throw error;
        }
      }
      const value = await readCandidate(version);
      if (
        !sameHash(value.dataHash, head.dataHash) ||
        !sameHash(value.metadataHash, head.metadataHash)
      )
        throw new Error("Adopted publication commitment mismatch");
      return commit(version, value, "adopt");
    }
    if (fence) version = BigInt(head?.expectedVersion ?? "0") + 1n;
    if (head && BigInt(head.expectedVersion) >= version)
      version = BigInt(head.expectedVersion) + 1n;
    let value = wanted;
    try {
      await storageAdapter.upload(`${scope}/${version}`, encrypted);
    } catch (error) {
      if (!(error instanceof StoredBlobConflictError)) throw error;
      value = await readCandidate(version);
      // Unfenced, resume only our own content: registering it is the same
      // registration a fresh upload would make. A foreign occupant needs
      // adopt-then-supersede, which needs the fence.
      if (!sameHash(value.dataHash, wantedHash))
        requireFence("resuming an occupied unregistered version");
    }
    try {
      const result = await commit(version, value, "register");
      if (sameHash(value.dataHash, wantedHash)) return result;
      // Verified foreign reservation is now committed. Supersede in this
      // generation, using the returned fence; never re-read across a delete.
      version++;
    } catch (error) {
      if (
        fencedPublication ||
        !(error instanceof Error) ||
        !/Gateway error: 409\b/.test(error.message)
      )
        throw error;
      if (rebased) throw error;
      rebased = true;
      head = await options.readHead();
      await options.checkHead?.(head);
      checkDeletion();
      const next = parseGatewayNextVersion(error.message);
      if (!head && next === null) throw error;
      const observedNext = BigInt(head?.expectedVersion ?? "0") + 1n;
      if (next !== null && BigInt(next) > observedNext)
        requireFence(
          "gateway version hint advances beyond the observed registry head",
        );
      version = observedNext;
    }
  }
  throw new Error(`Publication contention for ${scope}; retry next cycle`);
}

/** Legacy gateway conflict hints; fenced recovery never guesses from text. */
export function parseGatewayNextVersion(message: string): number | null {
  const nextValid = message.match(/next valid version is (\d+)/i);
  if (nextValid) return Number(nextValid[1]);
  const effectiveMax = message.match(/effective max \((\d+)/i);
  if (effectiveMax) return Number(effectiveMax[1]) + 1;
  const storedValue = message.match(
    /strictly greater than the stored value (\d+)/i,
  );
  return storedValue ? Number(storedValue[1]) + 1 : null;
}
