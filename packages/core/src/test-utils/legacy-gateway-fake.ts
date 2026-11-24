/**
 * An in-memory gateway and storage for tests of a legacy delete after the
 * switch to stream sync. It answers the two requests a legacy delete makes:
 *
 *   DELETE {gateway}/v1/data/:id                       the tombstone
 *   DELETE {storage}/v1/chains/:chain/blobs/:owner/:scope/:version
 *
 * The cutover rule it enforces is policy v3 of the gateway: an owner who
 * switched under it admits one legacy write, the exact tombstone over a live
 * head, signed by the owner or by a registered, non-revoked server. A v1
 * owner admits none (`owner_stream_sync_required`). An owner with no receipt
 * has not switched: every write is admitted, as before the switch.
 *
 * A signature is the text `signed-by:<role>`; `signerFor(role)` makes the
 * `signAddData` of a `ServerSigner`. The fake checks nothing else of it.
 */

import { computeDataPointId } from "../sync/data-point-id.js";
import {
  TOMBSTONE_DATA_HASH,
  TOMBSTONE_METADATA_HASH,
} from "../sync/tombstone.js";
import type { DataPointFeedPort, DataPointFeedRecord } from "../ports/index.js";

export type FakeSignerRole = "owner" | "server" | "revoked" | "unregistered";
export type FakeCutover = "none" | "v1" | "v3";

export const FAKE_GATEWAY = "https://gateway.fake";
export const FAKE_STORAGE = "https://storage.fake";
export const FAKE_CHAIN_ID = 14800;

interface Head {
  version: number;
  dataHash: string;
  metadataHash: string;
  deletedAt: string | null;
}

export interface LegacyGatewayFakeOptions {
  owner: string;
  /** The owner's cutover receipt: none (unswitched), policy v1, or policy v3. */
  cutover: FakeCutover;
  /** Who signs the tombstones of this port (default: a registered server). */
  signer?: FakeSignerRole;
}

export function createLegacyGatewayFake(options: LegacyGatewayFakeOptions) {
  const heads = new Map<string, Head>();
  const blobs = new Set<string>();
  /** Every request that reached the fake, in order. */
  const requests: { method: string; url: string; scope?: string }[] = [];
  /** Tombstone versions the gateway stored, by scope (a repeat would show twice). */
  const tombstones = new Map<string, number[]>();
  const state = {
    cutover: options.cutover,
    signer: options.signer ?? ("server" as FakeSignerRole),
    /** Awaited before the gateway handles a tombstone: lets a test interleave. */
    beforeTombstone: undefined as
      undefined | ((scope: string) => Promise<void>),
    /** Storage answers 429 for the next N blob deletes. */
    storageRateLimited: 0,
    /** The gateway answers 503 for the next N tombstones. */
    gatewayDown: 0,
  };
  const idOf = (scope: string) => computeDataPointId(options.owner, scope);
  const iso = () => "2026-11-23T00:00:00.000Z";

  function recordOf(scope: string, head: Head): DataPointFeedRecord {
    return {
      id: idOf(scope),
      ownerAddress: options.owner,
      scope,
      dataHash: head.dataHash,
      metadataHash: head.metadataHash,
      expectedVersion: String(head.version),
      addedAt: iso(),
      deletedAt: head.deletedAt,
    };
  }

  const feed: DataPointFeedPort = {
    async getDataPoint({ scope }) {
      const head = heads.get(scope);
      return head ? recordOf(scope, head) : null;
    },
    async listDataPointsByOwner() {
      return {
        dataPoints: [...heads].map(([scope, head]) => recordOf(scope, head)),
        cursor: null,
      };
    },
  };

  const json = (status: number, body: unknown) =>
    new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });

  async function tombstone(request: {
    scope: string;
    expectedVersion: string;
    role: FakeSignerRole;
  }): Promise<Response> {
    await state.beforeTombstone?.(request.scope);
    if (state.gatewayDown > 0) {
      state.gatewayDown -= 1;
      return json(503, { success: false, error: "gateway unavailable" });
    }
    if (request.role === "revoked" || request.role === "unregistered") {
      return json(401, {
        success: false,
        error:
          "Invalid signature: signer is not the owner or a registered server",
        code:
          request.role === "revoked" ? "server_revoked" : "server_unregistered",
      });
    }
    const head = heads.get(request.scope);
    if (!head)
      return json(404, { success: false, error: "Unknown data point" });
    if (head.deletedAt !== null)
      return json(200, {
        data: {
          dataPointId: idOf(request.scope),
          expectedVersion: String(head.version),
          deletedAt: head.deletedAt,
        },
      });
    if (state.cutover === "v1")
      return json(409, {
        success: false,
        code: "owner_stream_sync_required",
        policyVersion: 1,
        receipt: { policyVersion: 1 },
      });
    if (BigInt(request.expectedVersion) !== BigInt(head.version + 1))
      return json(409, {
        success: false,
        error: "Version conflict",
        currentExpectedVersion: String(head.version),
        nextExpectedVersion: String(head.version + 1),
      });
    head.version += 1;
    head.dataHash = TOMBSTONE_DATA_HASH;
    head.metadataHash = TOMBSTONE_METADATA_HASH;
    head.deletedAt = iso();
    tombstones.set(request.scope, [
      ...(tombstones.get(request.scope) ?? []),
      head.version,
    ]);
    return json(200, {
      data: {
        dataPointId: idOf(request.scope),
        expectedVersion: String(head.version),
        deletedAt: head.deletedAt,
      },
    });
  }

  const fetchImpl = (async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (url.startsWith(FAKE_GATEWAY) && method === "DELETE") {
      const body = JSON.parse(String(init?.body)) as {
        scope: string;
        expectedVersion: string;
      };
      requests.push({ method, url, scope: body.scope });
      const authorization = new Headers(init?.headers).get("authorization");
      const role = /signed-by:(\w+)/.exec(authorization ?? "")?.[1] as
        FakeSignerRole | undefined;
      return tombstone({
        scope: body.scope,
        expectedVersion: body.expectedVersion,
        role: role ?? "unregistered",
      });
    }
    if (url.startsWith(FAKE_STORAGE) && method === "DELETE") {
      const key = decodeURIComponent(
        url.slice(
          `${FAKE_STORAGE}/v1/chains/${FAKE_CHAIN_ID}/blobs/${options.owner.toLowerCase()}/`
            .length,
        ),
      );
      requests.push({ method, url });
      if (state.storageRateLimited > 0) {
        state.storageRateLimited -= 1;
        return new Response("", { status: 429, statusText: "Too Many" });
      }
      return blobs.delete(key)
        ? new Response("", { status: 200 })
        : new Response("", { status: 404 });
    }
    throw new Error(`fake gateway: unexpected ${method} ${url}`);
  }) as unknown as typeof fetch;

  return {
    feed,
    fetch: fetchImpl,
    state,
    requests,
    tombstones,
    owner: options.owner,
    /** A registered legacy point at `version`, with its blobs in storage. */
    seed(scope: string, version = 1) {
      heads.set(scope, {
        version,
        dataHash: `0x${"aa".repeat(32)}`,
        metadataHash: `0x${"bb".repeat(32)}`,
        deletedAt: null,
      });
      for (let v = 1; v <= version; v++) blobs.add(blobKey(scope, v));
    },
    /** A write to the legacy scope that moved its head (a new lifetime's write). */
    moveHead(scope: string) {
      const head = heads.get(scope)!;
      head.version += 1;
      head.dataHash = `0x${"cc".repeat(32)}`;
      blobs.add(blobKey(scope, head.version));
    },
    head: (scope: string) => heads.get(scope) ?? null,
    isLive: (scope: string) => {
      const head = heads.get(scope);
      return head !== undefined && head.deletedAt === null;
    },
    hasBlob: (scope: string, version: number) =>
      blobs.has(blobKey(scope, version)),
    blobCount: (scope: string) =>
      [...blobs].filter((key) => key.startsWith(`${scope}/`)).length,
    /** `ServerSigner.signAddData`: the signature names who signed. */
    signer: {
      signAddData: async () =>
        `0xsigned-by:${state.signer}` as unknown as `0x${string}`,
    },
  };
}

function blobKey(scope: string, version: number) {
  return `${scope}/${version}`;
}

export type LegacyGatewayFake = ReturnType<typeof createLegacyGatewayFake>;
