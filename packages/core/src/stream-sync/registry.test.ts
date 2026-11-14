import { describe, expect, it } from "vitest";
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

// --- batch commit and `requires` ---

import { AmbiguousRegistryReplyError, RegistryRefusedError } from "./ports.js";

const OWNER = "0x" + "11".repeat(20);
const batchRequest = {
  ownerAddress: OWNER,
  rows: ["a", "b"].map((name) => ({
    scope: `pdpp.x~.${name}`,
    dataHash: hash("aa") as `0x${string}`,
    metadataHash: hash("bb") as `0x${string}`,
    expectedVersion: "2",
    signature: `0x${"cc".repeat(65)}` as `0x${string}`,
  })),
  requires: [
    { scope: "pdpp.x~", expectedVersion: "1", notDeleted: true as const },
  ],
};

function gatewayAnswering(answer: () => Response | Promise<Response>) {
  const sent: { url: string; body: unknown }[] = [];
  const registry = createGatewayStreamSyncRegistry({
    gatewayUrl: "https://gateway.test/",
    ownerAddress: OWNER,
    fetch: (async (url: string, init?: RequestInit) => {
      sent.push({ url, body: JSON.parse(String(init?.body)) });
      return answer();
    }) as typeof fetch,
  });
  return { registry, sent };
}

const results200 = (statuses: Record<string, object>) =>
  new Response(
    JSON.stringify({
      success: true,
      results: Object.entries(statuses).map(([scope, rest]) => ({
        scope,
        ...rest,
      })),
      requires: { ok: true },
    }),
  );

it("sends every row and every condition in one request and reads one result per row", async () => {
  const { registry, sent } = gatewayAnswering(() =>
    results200({
      "pdpp.x~.b": {
        status: 409,
        reason: "stale",
        latestVersion: "2",
        latestDataHash: hash("aa"),
      },
      "pdpp.x~.a": { status: 201, version: "2" },
    }),
  );
  const result = await registry.postBatch!(batchRequest);
  expect(sent).toHaveLength(1);
  expect(sent[0]!.url).toBe("https://gateway.test/v1/data/batch");
  expect(sent[0]!.body).toEqual({
    ownerAddress: OWNER,
    rows: batchRequest.rows,
    requires: batchRequest.requires,
  });
  // Results come back in request order, whatever order the gateway lists them.
  expect(result).toEqual({
    kind: "rows",
    rows: [
      { kind: "committed" },
      { kind: "conflict", latestVersion: "2", latestDataHash: hash("aa") },
    ],
  });
});

it("sends each row's head fence and each condition's data hash as given, and omits them when absent", async () => {
  const { registry, sent } = gatewayAnswering(() =>
    results200({
      "pdpp.x~.a": { status: 201, version: "2" },
      "pdpp.x~.b": { status: 201, version: "2" },
    }),
  );
  await registry.postBatch!({
    ownerAddress: OWNER,
    rows: [
      {
        ...batchRequest.rows[0]!,
        expectedHeadDataHash: hash("dd") as `0x${string}`,
      },
      batchRequest.rows[1]!,
    ],
    requires: [
      {
        scope: "pdpp.x~",
        expectedVersion: "1",
        notDeleted: true as const,
        expectedDataHash: hash("ee") as `0x${string}`,
      },
      { scope: "pdpp.x~.c", expectedVersion: "1", notDeleted: true as const },
    ],
  });
  const body = sent[0]!.body as {
    rows: Record<string, unknown>[];
    requires: Record<string, unknown>[];
  };
  expect(body.rows[0]!.expectedHeadDataHash).toBe(hash("dd"));
  expect("expectedHeadDataHash" in body.rows[1]!).toBe(false);
  expect(body.requires[0]!.expectedDataHash).toBe(hash("ee"));
  expect("expectedDataHash" in body.requires[1]!).toBe(false);
});

it.each([
  ["deleted", true],
  ["absent", false],
  ["version-mismatch", false],
  ["data-hash-mismatch", false],
] as const)(
  "the final failure body's reason %s is read (a reason of 'deleted' is a delete)",
  async (reason, deleted) => {
    const { registry } = gatewayAnswering(
      () =>
        new Response(
          JSON.stringify({
            error: "precondition_failed",
            requires: {
              reason,
              scope: "pdpp.x~.a",
              expectedVersion: "1",
              expectedDataHash: hash("ee"),
              latestVersion: "2",
              latestDataHash: hash("ff"),
              deleted: false,
            },
          }),
          { status: 409 },
        ),
    );
    expect(await registry.postBatch!(batchRequest)).toEqual({
      kind: "precondition_failed",
      failure: expect.objectContaining({
        scope: "pdpp.x~.a",
        reason,
        deleted,
      }),
    });
  },
);

it.each([404, 405])(
  "a %s on the batch route is remembered: later calls send nothing",
  async (status) => {
    const { registry, sent } = gatewayAnswering(
      () => new Response("{}", { status }),
    );
    expect(await registry.postBatch!(batchRequest)).toEqual({
      kind: "unsupported",
    });
    expect(await registry.postBatch!(batchRequest)).toEqual({
      kind: "unsupported",
    });
    expect(sent).toHaveLength(1);
  },
);

it.each([
  [
    "the batch route's body",
    {
      success: false,
      requires: { ok: false, scope: "c", version: "3", deleted: true },
    },
    { scope: "c", latestVersion: "3", deleted: true },
  ],
  [
    "the single write's body",
    {
      error: "precondition_failed",
      requires: {
        scope: "c",
        expectedVersion: "1",
        latestVersion: "3",
        deleted: false,
      },
    },
    { scope: "c", latestVersion: "3", deleted: false },
  ],
  [
    "a missing row",
    {
      success: false,
      requires: { ok: false, scope: "c", version: null, deleted: false },
    },
    { scope: "c", latestVersion: null, deleted: false },
  ],
  ["no detail", { success: false }, null],
])(
  "a 409 from the batch route is a failed condition: %s",
  async (_n, body, failure) => {
    const { registry } = gatewayAnswering(
      () => new Response(JSON.stringify(body), { status: 409 }),
    );
    expect(await registry.postBatch!(batchRequest)).toEqual({
      kind: "precondition_failed",
      failure,
    });
  },
);

it("a reply that did not say whether the rows landed is ambiguous, a refusal is not", async () => {
  for (const status of [500, 503, 429]) {
    const { registry } = gatewayAnswering(() => new Response("{}", { status }));
    await expect(registry.postBatch!(batchRequest)).rejects.toBeInstanceOf(
      AmbiguousRegistryReplyError,
    );
  }
  const refused = gatewayAnswering(
    () => new Response('{"error":"bad"}', { status: 400 }),
  );
  await expect(
    refused.registry.postBatch!(batchRequest),
  ).rejects.toBeInstanceOf(RegistryRefusedError);
  const dropped = createGatewayStreamSyncRegistry({
    gatewayUrl: "https://gateway.test",
    ownerAddress: OWNER,
    fetch: (async () => {
      throw new TypeError("fetch failed");
    }) as typeof fetch,
  });
  await expect(dropped.postBatch!(batchRequest)).rejects.toBeInstanceOf(
    AmbiguousRegistryReplyError,
  );
  // A 200 that does not answer every row cannot be read as published.
  const partial = gatewayAnswering(() =>
    results200({ "pdpp.x~.a": { status: 201 } }),
  );
  await expect(
    partial.registry.postBatch!(batchRequest),
  ).rejects.toBeInstanceOf(AmbiguousRegistryReplyError);
  const notJson = gatewayAnswering(() => new Response("<html>"));
  await expect(
    notJson.registry.postBatch!(batchRequest),
  ).rejects.toBeInstanceOf(AmbiguousRegistryReplyError);
});

describe("requires on the single write", () => {
  const post = {
    ownerAddress: OWNER,
    scope: "pdpp.x~.a",
    dataHash: hash("aa") as `0x${string}`,
    metadataHash: hash("bb") as `0x${string}`,
    expectedVersion: "2",
    signature: `0x${"cc".repeat(65)}` as `0x${string}`,
  };

  it("sends requires and maps a failed condition apart from a stale version", async () => {
    const failed = gatewayAnswering(
      () =>
        new Response(
          JSON.stringify({
            error: "precondition_failed",
            requires: { scope: "pdpp.x~", latestVersion: "2", deleted: true },
          }),
          { status: 409 },
        ),
    );
    expect(
      await failed.registry.postConditional!({
        ...post,
        requires: batchRequest.requires,
      }),
    ).toEqual({
      kind: "precondition_failed",
      failure: { scope: "pdpp.x~", latestVersion: "2", deleted: true },
    });
    expect(failed.sent[0]!.body).toMatchObject({
      requires: batchRequest.requires,
      exclusive: true,
    });
    const stale = gatewayAnswering(
      () =>
        new Response(JSON.stringify({ success: false, latestVersion: "5" }), {
          status: 409,
        }),
    );
    expect(
      await stale.registry.postConditional!({
        ...post,
        requires: batchRequest.requires,
      }),
    ).toEqual({ kind: "conflict", latestVersion: "5" });
  });

  it("a write without requires sends none, and its 409 stays a conflict", async () => {
    const { registry, sent } = gatewayAnswering(
      () => new Response(JSON.stringify({ latestVersion: 4 }), { status: 409 }),
    );
    expect(await registry.post(post)).toEqual({
      kind: "conflict",
      latestVersion: "4",
    });
    expect("requires" in (sent[0]!.body as object)).toBe(false);
  });
});

describe("probeChange", () => {
  const newest = (changedAt: unknown, version = 3) => ({
    id: hash("cd"),
    scope: streamScope("acme", "", "items"),
    expectedVersion: String(version),
    dataHash: hash("aa"),
    metadataHash: hash("bb"),
    ...(changedAt === undefined ? {} : { changedAt }),
  });

  function probing(responses: Array<unknown[] | Response>) {
    const urls: string[] = [];
    let call = 0;
    const registry = createGatewayStreamSyncRegistry({
      gatewayUrl: "https://gateway.test",
      ownerAddress: "0x" + "11".repeat(20),
      fetch: (async (url: string) => {
        urls.push(url);
        const next = responses[Math.min(call, responses.length - 1)]!;
        call += 1;
        if (next instanceof Response) return next.clone();
        return new Response(
          JSON.stringify({
            data: { dataPoints: next },
            pagination: { hasMore: next.length > 0, nextCursor: "n" },
          }),
        );
      }) as typeof fetch,
    });
    return { registry, urls };
  }

  it("asks for the owner's newest row with one request, however many rows exist", async () => {
    const { registry, urls } = probing([[newest("2026-11-14T10:00:00.000Z")]]);
    const marker = await registry.probeChange!();
    expect(urls).toHaveLength(1);
    const query = new URL(urls[0]!).searchParams;
    expect(query.get("limit")).toBe("1");
    expect(query.get("includeDeleted")).toBe("true");
    expect(query.get("user")).toBe("0x" + "11".repeat(20));
    expect(query.has("cursor")).toBe(false);
    expect(marker).toEqual(expect.any(String));
  });

  it("moves with the newest change and stays put without one", async () => {
    const at = (iso: string, version?: number) => [newest(iso, version)];
    const { registry } = probing([
      at("2026-11-14T10:00:00.000Z"),
      at("2026-11-14T10:00:00.000Z"),
      at("2026-11-14T10:00:07.000Z", 4),
    ]);
    const first = await registry.probeChange!();
    expect(await registry.probeChange!()).toBe(first);
    expect(await registry.probeChange!()).not.toBe(first);
  });

  it("is null for an owner with no rows", async () => {
    const { registry } = probing([[]]);
    expect(await registry.probeChange!()).toBeNull();
  });

  it("cannot tell when the gateway sends no change time", async () => {
    const { registry } = probing([[newest(undefined)]]);
    expect(await registry.probeChange!()).toBeUndefined();
  });

  it("throws on a failed read: a failure is not 'nothing changed'", async () => {
    const { registry } = probing([new Response("no", { status: 503 })]);
    await expect(registry.probeChange!()).rejects.toThrow(/503/);
  });
});
