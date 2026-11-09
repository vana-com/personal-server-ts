import { expect, it } from "vitest";
import {
  controlScope,
  streamScope,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { createGatewayStreamSyncRegistry } from "./registry.js";

const hash = (byte: string) => `0x${byte.repeat(32)}`;
const row = (scope: string, version: number, deletedAt?: string) => ({
  scope,
  expectedVersion: String(version),
  dataHash: hash("aa"),
  metadataHash: hash("bb"),
  ...(deletedAt ? { deletedAt } : {}),
});

/** A gateway listing in two pages, with rows of several kinds and connectors. */
function registryOverPages(pages: unknown[][]) {
  const urls: string[] = [];
  const registry = createGatewayStreamSyncRegistry({
    gatewayUrl: "https://gateway.test",
    ownerAddress: "0x" + "11".repeat(20),
    listPageSize: 2,
    fetch: (async (url: string) => {
      urls.push(url);
      const index = new URL(url).searchParams.get("cursor") === "next" ? 1 : 0;
      return new Response(
        JSON.stringify({
          data: { dataPoints: pages[index] },
          pagination: {
            hasMore: index + 1 < pages.length,
            nextCursor: index + 1 < pages.length ? "next" : null,
          },
        }),
      );
    }) as typeof fetch,
  });
  return { registry, urls };
}

it("lists the stream rows of one connector across pages, deleted or not", async () => {
  const { registry, urls } = registryOverPages([
    [
      row(streamScope("acme", "", "items"), 3),
      row(controlScope("acme", ""), 1),
    ],
    [
      row(streamScope("acme", "0123456789abcdef", "orders"), 2, "2026-01-01"),
      row(streamScope("other", "", "items"), 1),
      row("not-a-stream-sync-scope", 1),
    ],
  ]);
  const rows = await registry.listStreamRows("acme");
  expect(rows.map((entry) => entry.scope)).toEqual([
    streamScope("acme", "", "items"),
    streamScope("acme", "0123456789abcdef", "orders"),
  ]);
  expect(rows[1]!.read).toMatchObject({ found: true, deleted: true });
  expect(urls).toHaveLength(2);
  expect(urls[0]).toContain("includeDeleted=true");
});

it("still lists control rows only", async () => {
  const { registry } = registryOverPages([
    [
      row(streamScope("acme", "", "items"), 3),
      row(controlScope("acme", ""), 1),
    ],
  ]);
  expect(
    (await registry.listControlRows()).map((entry) => entry.scope),
  ).toEqual([controlScope("acme", "")]);
});

/** One listing response with the given `pagination` marker. */
function registryWithMarker(pagination: unknown) {
  return createGatewayStreamSyncRegistry({
    gatewayUrl: "https://gateway.test",
    ownerAddress: "0x" + "11".repeat(20),
    fetch: (async () =>
      new Response(
        JSON.stringify({
          data: { dataPoints: [row(streamScope("acme", "", "items"), 1)] },
          ...(pagination === undefined ? {} : { pagination }),
        }),
      )) as typeof fetch,
  });
}

it.each([
  ["has no pagination marker", undefined],
  [
    "says more rows follow but gives no cursor",
    { hasMore: true, nextCursor: null },
  ],
  [
    "says more rows follow with an empty cursor",
    { hasMore: true, nextCursor: "" },
  ],
  ["gives neither flag nor cursor", {}],
])(
  "a listing that %s fails instead of ending early (mutant: LISTING_TRUNCATED_SILENTLY)",
  async (_name, pagination) => {
    const registry = registryWithMarker(pagination);
    await expect(registry.listStreamRows("acme")).rejects.toThrow(
      /registry listing/,
    );
    await expect(registry.listControlRows()).rejects.toThrow(
      /registry listing/,
    );
  },
);

it("a listing that says it is complete ends", async () => {
  const registry = registryWithMarker({ hasMore: false, nextCursor: null });
  expect(await registry.listStreamRows("acme")).toHaveLength(1);
});
