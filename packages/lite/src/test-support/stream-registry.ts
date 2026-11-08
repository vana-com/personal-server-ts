import { vi } from "vitest";
import { computeDataPointId } from "@opendatalabs/personal-server-ts-core/sync";

interface FakeRow {
  scope: string;
  dataHash: string;
  metadataHash: string;
  expectedVersion: string;
  addedAt: string;
  deletedAt: null;
}

/**
 * The registry: exclusive versions per scope, the single-row read by data
 * point id, and the listing. Any other URL answers 404.
 */
export function fakeRegistry(ownerAddress: string) {
  const rows = new Map<string, FakeRow>();
  // Blob storage (the vana-storage paths the writer PUTs and the reader GETs).
  const blobs = new Map<string, Uint8Array>();
  const byId = (id: string) =>
    [...rows.values()].find(
      (row) => computeDataPointId(ownerAddress, row.scope) === id,
    );
  const fetchImpl = vi.fn(
    async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input));
      if (init?.method === "PUT") {
        const bytes = new Uint8Array(
          await new Response(init.body).arrayBuffer(),
        );
        blobs.set(url.pathname, bytes);
        return Response.json({
          url: url.pathname,
          key: url.pathname,
          etag: `"${bytes.length}"`,
          size: bytes.length,
        });
      }
      if (blobs.has(url.pathname)) {
        return new Response(blobs.get(url.pathname)!);
      }
      if (init?.method === "POST") {
        const body = JSON.parse(String(init.body)) as {
          scope: string;
          dataHash: string;
          metadataHash: string;
          expectedVersion: string | number;
        };
        const current = Number(rows.get(body.scope)?.expectedVersion ?? 0);
        if (Number(body.expectedVersion) !== current + 1) {
          return Response.json(
            { latestVersion: String(current) },
            { status: 409 },
          );
        }
        rows.set(body.scope, {
          scope: body.scope,
          dataHash: body.dataHash,
          metadataHash: body.metadataHash,
          expectedVersion: String(current + 1),
          addedAt: new Date(1_800_000_000_000 + current * 1000).toISOString(),
          deletedAt: null,
        });
        return new Response(null, { status: 201 });
      }
      if (url.pathname === "/v1/data") {
        return Response.json({
          data: { dataPoints: [...rows.values()] },
          pagination: { hasMore: false, nextCursor: null },
        });
      }
      const single = url.pathname.match(/^\/v1\/data\/([^/]+)$/);
      if (single) {
        const row = byId(single[1]!);
        return row
          ? Response.json({ data: row })
          : new Response(null, { status: 404 });
      }
      return new Response(null, { status: 404 });
    },
  );
  /** What the listing feed shows the reader: every row the registry holds. */
  const feed = (): FakeRow[] => [...rows.values()];
  return { fetchImpl, feed };
}
