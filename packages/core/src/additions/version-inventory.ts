import { readBoundedJson, type ByteBudget } from "./budget.js";
import {
  encodeAbiParameters,
  getAddress,
  keccak256,
  stringToBytes,
} from "viem";
import { z } from "zod";
import type { RequestSigner } from "../signing/request-signer.js";

// Gateway contract: data-gateway/docs/version-inventory.md at 228bbf1cd6893a5b34da248832d8861f245d6d3d.
const uint256 = z
  .string()
  .regex(/^(0|[1-9][0-9]{0,77})$/)
  .refine((value) => BigInt(value) < 2n ** 256n);
const hash = z
  .string()
  .regex(/^0x[0-9a-fA-F]{64}$/)
  .transform((value) => value.toLowerCase());
const address = z.string().regex(/^0x[0-9a-fA-F]{40}$/);
const timestamp = z.iso.datetime();
const scopeSchema = z.string().refine((value) => {
  const length = new TextEncoder().encode(value).length;
  return length > 0 && length <= 256;
});
const commitments = z.object({
  expectedVersion: uint256,
  dataHash: hash,
  metadataHash: hash,
  status: z.string().min(1),
});
const headSchema = commitments.extend({ deletedAt: timestamp.nullable() });
const versionSchema = commitments.extend({
  addedAt: timestamp,
  isTombstone: z.boolean(),
});
const pageSchema = z.object({
  data: z.object({
    dataPointId: hash,
    ownerAddress: address,
    scope: scopeSchema,
    head: headSchema.nullable(),
    versions: z.array(versionSchema),
  }),
  pagination: z.object({
    limit: z.number().int().min(1).max(1000),
    hasMore: z.boolean(),
    nextAfter: uint256.nullable(),
  }),
});
const scopesSchema = z.object({
  data: z.object({
    dataPoints: z.array(
      z.object({
        id: hash,
        ownerAddress: address,
        scope: scopeSchema,
        deletedAt: timestamp.nullable(),
      }),
    ),
  }),
  pagination: z.object({
    limit: z.number().int().min(1).max(1000),
    hasMore: z.boolean(),
    nextCursor: z.string().min(1).nullable(),
  }),
});
const tombstoneData = keccak256(stringToBytes("vana.data-point.tombstone.v1"));
const tombstoneMetadata = keccak256(
  stringToBytes("vana.data-point.tombstone.metadata.v1"),
);

export type InventoryHead = z.infer<typeof headSchema>;
export type InventoryVersion = z.infer<typeof versionSchema>;
export interface VersionInventory {
  head: InventoryHead | null;
  versions: InventoryVersion[];
}
export interface InventoryReadOptions {
  signal?: AbortSignal;
  maxPages?: number;
  budget?: ByteBudget;
}

/** Owner-wallet reads only. Registered Personal Server signatures do not authorize this API. */
export function createVersionInventoryClient(options: {
  gatewayUrl: string;
  ownerAddress: string;
  ownerSigner: RequestSigner;
  /** A host signer that settles on cancellation; wallet prompts must not outlive recovery. */
  boundedOwnerSigner?: (
    params: Parameters<RequestSigner["signRequest"]>[0],
    signal?: AbortSignal,
  ) => Promise<string>;
  fetch?: typeof globalThis.fetch;
}) {
  const origin = new URL(options.gatewayUrl).origin;
  const owner = getAddress(options.ownerAddress).toLowerCase();
  const fetcher = options.fetch ?? globalThis.fetch;
  const idFor = (scope: string) =>
    keccak256(
      encodeAbiParameters(
        [{ type: "address" }, { type: "string" }],
        [getAddress(owner), scope],
      ),
    );

  async function read(
    uri: string,
    signal?: AbortSignal,
    authenticated = true,
    budget?: ByteBudget,
  ): Promise<unknown> {
    signal =
      signal && budget?.signal
        ? AbortSignal.any([signal, budget.signal])
        : (signal ?? budget?.signal);
    signal?.throwIfAborted();
    budget?.charge();
    if (authenticated && budget && !options.boundedOwnerSigner)
      throw new Error("Bounded inventory signing capability unavailable");
    const signing = {
      aud: origin,
      method: "GET",
      uri,
      nonce: crypto.randomUUID(),
    };
    const authorization = authenticated
      ? budget && options.boundedOwnerSigner
        ? await options.boundedOwnerSigner(signing, signal)
        : await options.ownerSigner.signRequest(signing)
      : undefined;
    signal?.throwIfAborted();
    const response = await fetcher(`${origin}${uri}`, {
      method: "GET",
      headers: authorization ? { Authorization: authorization } : {},
      signal,
      cache: "no-store",
    });
    if (!response.ok) {
      await response.body?.cancel();
      throw new Error(`Gateway inventory request failed (${response.status})`);
    }
    return readBoundedJson(response, budget);
  }

  async function page(
    scope: string,
    paging: {
      after?: string;
      limit?: number;
      signal?: AbortSignal;
      budget?: ByteBudget;
    } = {},
  ) {
    scopeSchema.parse(scope);
    const after = uint256.parse(paging.after ?? "0");
    const limit = z
      .number()
      .int()
      .min(1)
      .max(1000)
      .parse(paging.limit ?? 100);
    const id = idFor(scope);
    const uri = `/v1/data/${id}/versions?${new URLSearchParams({ user: owner, scope, after, limit: String(limit) })}`;
    const result = pageSchema.parse(
      await read(uri, paging.signal, true, paging.budget),
    );
    if (
      result.data.dataPointId !== id ||
      result.data.ownerAddress.toLowerCase() !== owner ||
      result.data.scope !== scope ||
      result.pagination.limit !== limit
    )
      throw new Error("Gateway inventory response does not match request");
    let previous = BigInt(after);
    for (const version of result.data.versions) {
      if (BigInt(version.expectedVersion) <= previous)
        throw new Error(
          "Gateway inventory versions are not strictly increasing",
        );
      previous = BigInt(version.expectedVersion);
      const tombstone =
        version.dataHash === tombstoneData &&
        version.metadataHash === tombstoneMetadata;
      if (version.isTombstone !== tombstone)
        throw new Error("Gateway inventory tombstone commitments do not match");
    }
    const last = result.data.versions.at(-1)?.expectedVersion ?? null;
    if (
      result.data.versions.length > limit ||
      (result.pagination.hasMore
        ? last === null || result.pagination.nextAfter !== last
        : result.pagination.nextAfter !== null)
    )
      throw new Error("Gateway inventory cursor does not match page");
    return result;
  }

  /** One bounded traversal, not a completeness certificate. Re-read and compare before certifying coverage. */
  async function list(
    scope: string,
    readOptions: InventoryReadOptions = {},
  ): Promise<VersionInventory> {
    const maxPages = z
      .number()
      .int()
      .positive()
      .parse(readOptions.maxPages ?? 1000);
    let after = "0";
    let head: InventoryHead | null = null;
    const versions: InventoryVersion[] = [];
    for (let count = 0; count < maxPages; count++) {
      const result = await page(scope, {
        after,
        signal: readOptions.signal,
        budget: readOptions.budget,
      });
      if (
        count > 0 &&
        JSON.stringify(head) !== JSON.stringify(result.data.head)
      )
        throw new Error("Gateway inventory head changed during traversal");
      head = result.data.head;
      versions.push(...result.data.versions);
      if (!result.pagination.hasMore) return { head, versions };
      const next = result.pagination.nextAfter;
      if (next === null)
        throw new Error("Gateway inventory missing next cursor");
      after = next;
    }
    throw new Error("Gateway inventory page budget exceeded");
  }

  /** Public owner scope feed includes deleted rows; reserved system scopes are excluded by Gateway. */
  async function listScopes(
    readOptions: InventoryReadOptions = {},
  ): Promise<string[]> {
    const maxPages = z
      .number()
      .int()
      .positive()
      .parse(readOptions.maxPages ?? 1000);
    const scopes = new Set<string>();
    const cursors = new Set<string>();
    let cursor: string | null = null;
    for (let count = 0; count < maxPages; count++) {
      const query = new URLSearchParams({
        user: owner,
        includeDeleted: "true",
        limit: "100",
      });
      if (cursor !== null) query.set("cursor", cursor);
      const result = scopesSchema.parse(
        await read(
          `/v1/data?${query}`,
          readOptions.signal,
          false,
          readOptions.budget,
        ),
      );
      if (
        result.pagination.limit !== 100 ||
        result.data.dataPoints.length > 100
      )
        throw new Error("Gateway scope page does not match request");
      for (const row of result.data.dataPoints) {
        if (
          row.ownerAddress.toLowerCase() !== owner ||
          row.id !== idFor(row.scope) ||
          row.scope.startsWith("vana.system.")
        )
          throw new Error("Gateway scope response does not match owner scope");
        scopes.add(row.scope);
      }
      if (!result.pagination.hasMore) {
        if (result.pagination.nextCursor !== null)
          throw new Error("Gateway scope cursor contradicts final page");
        return [...scopes].sort();
      }
      const next = result.pagination.nextCursor;
      if (
        next === null ||
        cursors.has(next) ||
        result.data.dataPoints.length === 0
      )
        throw new Error("Gateway scope cursor did not advance");
      cursors.add(next);
      cursor = next;
    }
    throw new Error("Gateway scope page budget exceeded");
  }
  return { page, list, listScopes };
}
export type VersionInventoryClient = ReturnType<
  typeof createVersionInventoryClient
>;
