import { z } from "zod";
import { encodeAbiParameters, keccak256, parseAbi, type Hex } from "viem";
import type { ReplicaRegistrationEvidence } from "./dpv2.js";

const bytes32 = z.string().regex(/^0x[0-9a-fA-F]{64}$/);
const address = z.string().regex(/^0x[0-9a-fA-F]{40}$/);
const zero = `0x${"0".repeat(64)}`;
const abi = parseAbi([
  "function dataPoints(address ownerAddress, string scope) view returns ((bytes32 id, address owner, string scope, uint8 status, uint256 currentVersion, bytes32 currentCommitment, uint256 createdAt, uint256 modifiedAt, uint256 totalAccesses))",
  "function currentVersion(address ownerAddress, string scope) view returns (uint256)",
  "function dataCommitment(address ownerAddress, string scope, uint256 version_) view returns (bytes32)",
]);

/** A viem PublicClient satisfies this port. RPC errors must propagate, not become zero. */
export interface ReplicaEvidenceRpc {
  getChainId(): Promise<number>;
  getBlock(
    input: { blockTag: "finalized" } | { blockNumber: bigint },
  ): Promise<{
    number: bigint | null;
    hash: Hex | null;
    timestamp: bigint;
  }>;
  readContract(input: {
    address: Hex;
    abi: typeof abi;
    functionName: "currentVersion" | "dataCommitment" | "dataPoints";
    args: readonly [Hex, string] | readonly [Hex, string, bigint];
    blockNumber: bigint;
  }): Promise<unknown>;
}

/** Every failure is retryable by transport workers. No error is evidence of absence. */
export class ReplicaEvidenceUnavailableError extends Error {
  readonly retryable = true;
  constructor(cause: unknown) {
    super("replica finalized evidence unavailable", { cause });
    this.name = "ReplicaEvidenceUnavailableError";
  }
}

const uint256 = z
  .bigint()
  .min(0n)
  .max((1n << 256n) - 1n);
const dataPointInfoSchema = z.object({
  id: bytes32,
  owner: address,
  scope: z.string(),
  status: z.number().int().min(0).max(3),
  currentVersion: uint256,
  currentCommitment: bytes32,
  createdAt: uint256,
  modifiedAt: uint256,
  totalAccesses: uint256,
});
const statuses = ["None", "Active", "Inactive", "Unavailable"] as const;

const headSchema = z.object({
  id: bytes32,
  ownerAddress: address,
  scope: z.string().min(1),
  expectedVersion: z.string().regex(/^[1-9][0-9]*$/),
  // Gateway uses active/inactive/unavailable. A deleted alias also refuses serving.
  state: z.enum(["active", "inactive", "unavailable", "deleted"]).optional(),
  dataHash: bytes32,
  metadataHash: bytes32,
  deletedAt: z.string().datetime({ offset: true }).nullable().optional(),
});

/** Independent finalized commitment verification replaces Gateway HEAD proof verification.
 * The configured RPC/chain/registry are trusted; the Gateway is not trusted to supply hashes.
 * Gateway omission or optimistic head mutations can delay progress; only finalized slot facts quarantine.
 */
export function createReplicaEvidenceAdapter(deps: {
  owner: Hex;
  registry: Hex;
  chainId: number;
  rpc: ReplicaEvidenceRpc;
  gatewayUrl: string;
  fetch?: typeof globalThis.fetch;
  now?: () => number;
  /** Includes ordinary chain finality lag; default 30 minutes. Never use latest as fallback. */
  maxFinalizedAgeSeconds?: number;
}): (scope: string, version: number) => Promise<ReplicaRegistrationEvidence> {
  return async (scope, version) => {
    try {
      address.parse(deps.owner);
      address.parse(deps.registry);
      const maxAge = deps.maxFinalizedAgeSeconds ?? 1800;
      if (
        !Number.isSafeInteger(deps.chainId) ||
        deps.chainId <= 0 ||
        /^0x0{40}$/i.test(deps.registry) ||
        !scope ||
        !Number.isSafeInteger(version) ||
        version < 1 ||
        !Number.isFinite(maxAge) ||
        maxAge <= 0
      )
        throw new Error("invalid evidence configuration");
      const base = new URL(deps.gatewayUrl);
      if (base.protocol !== "https:" && base.protocol !== "http:")
        throw new Error("invalid Gateway URL");
      if ((await deps.rpc.getChainId()) !== deps.chainId)
        throw new Error("wrong chain");
      const block = await deps.rpc.getBlock({ blockTag: "finalized" });
      if (
        typeof block.number !== "bigint" ||
        block.number < 0n ||
        !bytes32.safeParse(block.hash).success ||
        typeof block.timestamp !== "bigint" ||
        block.timestamp < 0n
      )
        throw new Error("missing finalized block");
      const checkFreshness = () => {
        const age = (deps.now ?? Date.now)() / 1000 - Number(block.timestamp);
        if (!Number.isFinite(age) || age < -60 || age > maxAge)
          throw new Error("stale finalized block");
      };
      checkFreshness();
      const id = keccak256(
        encodeAbiParameters(
          [{ type: "address" }, { type: "string" }],
          [deps.owner, scope],
        ),
      );
      const [currentVersion, commitment, rawInfo] = await Promise.all([
        deps.rpc.readContract({
          address: deps.registry,
          abi,
          functionName: "currentVersion",
          args: [deps.owner, scope],
          blockNumber: block.number,
        }),
        deps.rpc.readContract({
          address: deps.registry,
          abi,
          functionName: "dataCommitment",
          args: [deps.owner, scope, BigInt(version)],
          blockNumber: block.number,
        }),
        deps.rpc.readContract({
          address: deps.registry,
          abi,
          functionName: "dataPoints",
          args: [deps.owner, scope],
          blockNumber: block.number,
        }),
      ]);
      if (
        typeof currentVersion !== "bigint" ||
        currentVersion < 0n ||
        currentVersion > (1n << 256n) - 1n ||
        !bytes32.safeParse(commitment).success ||
        currentVersion < BigInt(version) !==
          ((commitment as string).toLowerCase() === zero)
      )
        throw new Error("invalid registry result");
      const info = dataPointInfoSchema.parse(rawInfo);
      if (
        info.id.toLowerCase() !== id ||
        info.currentVersion !== currentVersion
      )
        throw new Error("inconsistent registry identity/version");
      if (currentVersion === 0n) {
        // The contract computes id even for a missing mapping; all stored fields are default.
        if (
          !/^0x0{40}$/i.test(info.owner) ||
          info.scope !== "" ||
          info.status !== 0 ||
          info.currentCommitment.toLowerCase() !== zero ||
          info.createdAt !== 0n ||
          info.modifiedAt !== 0n ||
          info.totalAccesses !== 0n
        )
          throw new Error("invalid absent registry row");
      } else if (
        info.owner.toLowerCase() !== deps.owner.toLowerCase() ||
        info.scope !== scope ||
        (currentVersion === BigInt(version) &&
          info.currentCommitment.toLowerCase() !==
            (commitment as string).toLowerCase())
      )
        throw new Error("inconsistent registry row");
      base.pathname = `${base.pathname.replace(/\/$/, "")}/v1/data/${id}`;
      base.search = "?includeDeleted=true";
      base.hash = "";
      const response = await (deps.fetch ?? globalThis.fetch)(base.toString());
      let head: ReplicaRegistrationEvidence["head"] = null;
      if (response.status === 404) {
        // A missing deployment/route is not the Gateway's precise unknown-head response.
        z.object({ error: z.literal("Data point not found") }).parse(
          await response.json(),
        );
      } else {
        if (!response.ok && response.status !== 410)
          throw new Error(`Gateway HTTP ${response.status}`);
        const envelope = z
          .object({ data: headSchema })
          .parse(await response.json());
        const row = envelope.data;
        // Validate all identity fields independently; never infer scope/owner from the requested URL.
        if (
          row.id.toLowerCase() !== id ||
          row.ownerAddress.toLowerCase() !== deps.owner.toLowerCase() ||
          row.scope !== scope
        )
          throw new Error("Gateway identity mismatch");
        if (response.status === 410 && !row.deletedAt)
          throw new Error("unbound Gateway tombstone");
        head = {
          owner: deps.owner,
          scope: row.scope,
          version: row.expectedVersion,
          dataHash: row.dataHash.toLowerCase(),
          metadataHash: row.metadataHash.toLowerCase(),
          deleted:
            row.deletedAt != null ||
            (row.state !== undefined && row.state !== "active"),
        };
      }
      // A number-pinned read must still match the finalized hash after all I/O.
      const pinned = await deps.rpc.getBlock({ blockNumber: block.number });
      if (
        pinned.number !== block.number ||
        pinned.hash !== block.hash ||
        pinned.timestamp !== block.timestamp
      )
        throw new Error("finalized block changed");
      checkFreshness();
      return {
        head,
        chain: {
          owner: deps.owner,
          scope,
          version: String(version),
          currentVersion: currentVersion.toString(),
          status: statuses[info.status]!,
          commitment: commitment as Hex,
          chainId: deps.chainId,
          registry: deps.registry,
          blockNumber: block.number,
          blockHash: block.hash!,
          blockTimestamp: block.timestamp,
        },
        pending: false,
      };
    } catch (cause) {
      throw new ReplicaEvidenceUnavailableError(cause);
    }
  };
}
