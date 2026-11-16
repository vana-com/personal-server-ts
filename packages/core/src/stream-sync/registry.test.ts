import { describe, expect, it } from "vitest";
import {
  controlScope,
  streamScope,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { createGatewayStreamSyncRegistry } from "./registry.js";
import { RegistryUnavailableError } from "./ports.js";

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

import {
  AmbiguousRegistryReplyError,
  RegistryBatchRouteMissingError,
  RegistryRefusedError,
} from "./ports.js";

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

it("sends every row and every condition in one request; a 200 is a commit of every row", async () => {
  const { registry, sent } = gatewayAnswering(() =>
    results200({
      "pdpp.x~.a": { status: 201, version: "2" },
      "pdpp.x~.b": { status: 201, version: "2" },
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
  expect(result).toEqual({ kind: "committed" });
});

it("a 409 conflict wrote nothing: one answer per row in request order, the loser with its winner, a replay stored, the rest not written", async () => {
  const { registry } = gatewayAnswering(
    () =>
      new Response(
        JSON.stringify({
          success: false,
          error: "conflict",
          results: [
            {
              scope: "pdpp.x~.b",
              status: 409,
              reason: "stale",
              latestVersion: "2",
              latestDataHash: hash("aa"),
            },
            { scope: "pdpp.x~.a", status: 424 },
          ],
        }),
        { status: 409 },
      ),
  );
  expect(await registry.postBatch!(batchRequest)).toEqual({
    kind: "refused",
    rows: [
      { kind: "not_written" },
      { kind: "conflict", latestVersion: "2", latestDataHash: hash("aa") },
    ],
  });
  const replay = gatewayAnswering(
    () =>
      new Response(
        JSON.stringify({
          success: false,
          error: "conflict",
          results: [
            { scope: "pdpp.x~.a", status: 201, version: "2" },
            {
              scope: "pdpp.x~.b",
              status: 409,
              reason: "stale",
              latestVersion: "2",
              latestDataHash: hash("aa"),
            },
          ],
        }),
        { status: 409 },
      ),
  );
  expect(await replay.registry.postBatch!(batchRequest)).toEqual({
    kind: "refused",
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
  "a %s on the batch route is a gateway without the batch contract: the call fails closed",
  async (status) => {
    const { registry } = gatewayAnswering(() => new Response("{}", { status }));
    await expect(registry.postBatch!(batchRequest)).rejects.toBeInstanceOf(
      RegistryBatchRouteMissingError,
    );
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
  // A 2xx that does not say it committed (a proxy's page) is no commit.
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

  it("hands the caller's abort signal to the request, so a stalled read can be ended", async () => {
    const seen: Array<AbortSignal | null | undefined> = [];
    const registry = createGatewayStreamSyncRegistry({
      gatewayUrl: "https://gateway.test",
      ownerAddress: "0x" + "11".repeat(20),
      fetch: (async (_url: string, init?: RequestInit) => {
        seen.push(init?.signal);
        return new Response(JSON.stringify({ data: { dataPoints: [] } }));
      }) as typeof fetch,
    });
    const controller = new AbortController();
    await registry.probeChange!(controller.signal);
    expect(seen).toHaveLength(1);
    controller.abort();
    expect(seen[0]?.aborted).toBe(true);
  });

  it("throws on a failed read: a failure is not 'nothing changed'", async () => {
    const { registry } = probing([new Response("no", { status: 503 })]);
    await expect(registry.probeChange!()).rejects.toThrow(/503/);
  });
});

describe("waitForChange", () => {
  const owner = "0x" + "11".repeat(20);

  function waiting(respond: (url: string) => Response | Promise<Response>) {
    const urls: string[] = [];
    const signals: Array<AbortSignal | undefined> = [];
    const registry = createGatewayStreamSyncRegistry({
      gatewayUrl: "https://gateway.test/",
      ownerAddress: owner,
      fetch: (async (url: string, init?: RequestInit) => {
        urls.push(url);
        signals.push(init?.signal ?? undefined);
        return respond(url);
      }) as typeof fetch,
    });
    return { registry, urls, signals };
  }

  it("holds a request on the change route with the owner, cursor and wait in seconds", async () => {
    const { registry, urls, signals } = waiting(
      () => new Response(JSON.stringify({ seq: "12", changed: true })),
    );
    const controller = new AbortController();
    const answer = await registry.waitForChange!(
      "9",
      25_000,
      controller.signal,
    );
    expect(answer).toEqual({ seq: "12", changed: true });
    const url = new URL(urls[0]!);
    expect(url.origin + url.pathname).toBe(
      "https://gateway.test/v1/data/changes",
    );
    expect(url.searchParams.get("user")).toBe(owner);
    expect(url.searchParams.get("after")).toBe("9");
    expect(url.searchParams.get("wait")).toBe("25");
    expect(signals[0]).toBe(controller.signal);
  });

  it("sends no cursor when it has none", async () => {
    const { registry, urls } = waiting(
      () => new Response(JSON.stringify({ seq: "0", changed: true })),
    );
    await registry.waitForChange!(
      undefined,
      25_000,
      new AbortController().signal,
    );
    expect(new URL(urls[0]!).searchParams.has("after")).toBe(false);
  });

  it("says the gateway has no change route on 404 or 405", async () => {
    for (const status of [404, 405]) {
      const { registry } = waiting(() => new Response("no", { status }));
      await expect(
        registry.waitForChange!("1", 25_000, new AbortController().signal),
      ).rejects.toMatchObject({ name: "ChangeFeedAbsentError" });
    }
  });

  it("reads the legacy handler's 400 for the id `changes` as 'no change route'", async () => {
    // A gateway without the route hands the path to its `/v1/data/:dataPointId`
    // handler, which refuses the id `changes` with a 400 that names dataPointId.
    for (const after of [undefined, "9"]) {
      const { registry } = waiting(
        () =>
          new Response(
            JSON.stringify({
              error:
                "Invalid dataPointId: must be a valid bytes32 hex string (0x-prefixed, 64 hex chars)",
            }),
            { status: 400 },
          ),
      );
      await expect(
        registry.waitForChange!(after, 25_000, new AbortController().signal),
      ).rejects.toMatchObject({ name: "ChangeFeedAbsentError" });
    }
  });

  it.each([
    [
      "the change route's own refusal",
      JSON.stringify({ error: "Invalid user: expected an 0x address" }),
    ],
    [
      "a message that only mentions dataPointId",
      JSON.stringify({ error: "dataPointId lookup temporarily unavailable" }),
    ],
    ["a body that is not JSON", "bad request"],
    ["an empty body", ""],
  ])("does not read a 400 with %s as an absent route", async (_name, body) => {
    const { registry } = waiting(() => new Response(body, { status: 400 }));
    const failure = await registry.waitForChange!(
      undefined,
      25_000,
      new AbortController().signal,
    ).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(Error);
    expect((failure as Error).name).not.toBe("ChangeFeedAbsentError");
  });

  it("asks again after a first 400 that was not an absence, and uses the answer", async () => {
    let calls = 0;
    const { registry, urls } = waiting(() => {
      calls += 1;
      return calls === 1
        ? new Response(
            JSON.stringify({ error: "Invalid user: expected an 0x address" }),
            {
              status: 400,
            },
          )
        : new Response(JSON.stringify({ seq: "4", changed: true }));
    });
    await expect(
      registry.waitForChange!(undefined, 25_000, new AbortController().signal),
    ).rejects.toThrow(/400/);
    await expect(
      registry.waitForChange!(undefined, 25_000, new AbortController().signal),
    ).resolves.toEqual({ seq: "4", changed: true });
    expect(urls).toHaveLength(2);
  });

  it("remembers no absence: a gateway upgraded to have the route is found by the next ask", async () => {
    let upgraded = false;
    const { registry, urls } = waiting(() =>
      upgraded
        ? new Response(JSON.stringify({ seq: "1", changed: true }))
        : new Response("no", { status: 404 }),
    );
    await expect(
      registry.waitForChange!(undefined, 25_000, new AbortController().signal),
    ).rejects.toMatchObject({ name: "ChangeFeedAbsentError" });
    upgraded = true;
    await expect(
      registry.waitForChange!(undefined, 25_000, new AbortController().signal),
    ).resolves.toEqual({ seq: "1", changed: true });
    expect(urls).toHaveLength(2);
  });

  it("keeps asking after a failure that does not say the route is absent", async () => {
    const { registry, urls } = waiting(
      () => new Response("down", { status: 503 }),
    );
    for (let attempt = 0; attempt < 3; attempt += 1) {
      await expect(
        registry.waitForChange!("1", 25_000, new AbortController().signal),
      ).rejects.toThrow(/503/);
    }
    expect(urls).toHaveLength(3);
  });

  it("throws on any other failure, and on an answer that is not a sequence", async () => {
    const down = waiting(() => new Response("no", { status: 503 }));
    await expect(
      down.registry.waitForChange!("1", 25_000, new AbortController().signal),
    ).rejects.toThrow(/503/);
    for (const body of [
      {},
      { seq: 7, changed: true },
      { seq: "x", changed: true },
      { seq: "7" },
    ]) {
      const bad = waiting(() => new Response(JSON.stringify(body)));
      await expect(
        bad.registry.waitForChange!("1", 25_000, new AbortController().signal),
      ).rejects.toThrow(/change answer/);
    }
  });
});

describe("an unreachable registry is told apart from a refusing one", () => {
  const over = (fetch: unknown) =>
    createGatewayStreamSyncRegistry({
      gatewayUrl: "https://gateway.test",
      ownerAddress: "0x" + "11".repeat(20),
      fetch: fetch as typeof globalThis.fetch,
    });
  const scope = controlScope("acme", "");
  const refuse = (status: number) => async () => new Response("", { status });
  it.each([
    [
      "a network failure",
      async () => Promise.reject(new TypeError("fetch failed")),
    ],
    [
      "a timeout",
      async () => Promise.reject(new DOMException("timed out", "TimeoutError")),
    ],
    ["a 503", refuse(503)],
  ])(
    "read and listing reject with RegistryUnavailableError on %s",
    async (_name, fetch) => {
      await expect(over(fetch).read(scope)).rejects.toBeInstanceOf(
        RegistryUnavailableError,
      );
      await expect(over(fetch).listStreamRows("acme")).rejects.toBeInstanceOf(
        RegistryUnavailableError,
      );
      await expect(over(fetch).listControlRows()).rejects.toBeInstanceOf(
        RegistryUnavailableError,
      );
    },
  );
  it("a 4xx is not unavailability", async () => {
    for (const status of [400, 401, 403]) {
      const error = await over(refuse(status))
        .read(scope)
        .catch((e: unknown) => e);
      expect(error).toBeInstanceOf(Error);
      expect(error).not.toBeInstanceOf(RegistryUnavailableError);
      const listing = await over(refuse(status))
        .listStreamRows("acme")
        .catch((e: unknown) => e);
      expect(listing).not.toBeInstanceOf(RegistryUnavailableError);
    }
    expect(await over(refuse(404)).read(scope)).toEqual({ found: false });
  });

  // A 200 whose body stream fails after the headers: the connection dropped
  // or a timeout fired while the body was read.
  const failingBody = (error: unknown) => () =>
    new Response(
      new ReadableStream({
        start(controller) {
          controller.error(error);
        },
      }),
      { status: 200 },
    );
  const page = (hasMore: boolean) =>
    new Response(
      JSON.stringify({
        data: { dataPoints: [] },
        pagination: hasMore
          ? { hasMore: true, nextCursor: "next" }
          : { hasMore: false },
      }),
      { status: 200 },
    );
  const listings = {
    listStreamRows: (r: ReturnType<typeof over>) => r.listStreamRows("acme"),
    listControlRows: (r: ReturnType<typeof over>) => r.listControlRows(),
    listOwnerRows: (r: ReturnType<typeof over>) => r.listOwnerRows!(),
  };
  it.each([
    ["a network error", new TypeError("terminated")],
    ["a timeout", new DOMException("timed out", "TimeoutError")],
    ["an abort", new DOMException("aborted", "AbortError")],
  ])(
    "a body that fails after the headers (%s) is unavailability, for read and every listing",
    async (_name, failure) => {
      await expect(
        over(failingBody(failure)).read(scope),
      ).rejects.toBeInstanceOf(RegistryUnavailableError);
      for (const list of Object.values(listings))
        await expect(list(over(failingBody(failure)))).rejects.toBeInstanceOf(
          RegistryUnavailableError,
        );
    },
  );
  it("a body that fails on a later listing page is unavailability", async () => {
    for (const list of Object.values(listings)) {
      let calls = 0;
      const registry = over(() =>
        ++calls === 1 ? page(true) : failingBody(new TypeError("terminated"))(),
      );
      await expect(list(registry)).rejects.toBeInstanceOf(
        RegistryUnavailableError,
      );
      expect(calls).toBe(2);
    }
  });
  it("a body that arrives whole but is not JSON is a plain error, not unavailability", async () => {
    const malformed = () => new Response('{"data": {', { status: 200 });
    const read = await over(malformed)
      .read(scope)
      .catch((e: unknown) => e);
    expect(read).toBeInstanceOf(SyntaxError);
    expect(read).not.toBeInstanceOf(RegistryUnavailableError);
    for (const list of Object.values(listings)) {
      const error = await list(over(malformed)).catch((e: unknown) => e);
      expect(error).toBeInstanceOf(SyntaxError);
      expect(error).not.toBeInstanceOf(RegistryUnavailableError);
    }
    // A later page that is malformed is not unavailability either.
    let calls = 0;
    const later = await over(() => (++calls === 1 ? page(true) : malformed()))
      .listStreamRows("acme")
      .catch((e: unknown) => e);
    expect(later).toBeInstanceOf(SyntaxError);
  });
  it("a listing with no pagination marker is a plain error, not unavailability", async () => {
    const error = await over(
      () =>
        new Response(JSON.stringify({ data: { dataPoints: [] } }), {
          status: 200,
        }),
    )
      .listStreamRows("acme")
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(Error);
    expect(error).not.toBeInstanceOf(RegistryUnavailableError);
  });
});

describe("listings of concurrent callers", () => {
  const owner = `0x${"11".repeat(20)}` as const;
  /** A fetch whose listings answer only when released, in the order begun. */
  function held() {
    const begun: { release: (rows: string[]) => void }[] = [];
    const fetch = (() =>
      new Promise<Response>((resolve) => {
        begun.push({
          release: (scopes) =>
            resolve(
              new Response(
                JSON.stringify({
                  data: {
                    dataPoints: scopes.map((scope) => ({
                      scope,
                      expectedVersion: "1",
                      dataHash: `0x${"aa".repeat(32)}`,
                      metadataHash: `0x${"bb".repeat(32)}`,
                      deleted: false,
                    })),
                  },
                  pagination: { hasMore: false },
                }),
                { status: 200 },
              ),
            ),
        });
      })) as unknown as typeof fetch;
    return { begun, fetch };
  }
  const registryOver = (fetch: typeof globalThis.fetch) =>
    createGatewayStreamSyncRegistry({
      gatewayUrl: "https://gateway.test",
      ownerAddress: owner,
      fetch,
    });

  it("a call made while a listing is out waits for a listing that begins after it, and callers that arrive meanwhile share that one", async () => {
    const { begun, fetch } = held();
    const registry = registryOver(fetch);
    const first = registry.listControlRows();
    await new Promise((resolve) => setTimeout(resolve, 0));
    const second = registry.listControlRows();
    const third = registry.listStreamRows("acme");
    await new Promise((resolve) => setTimeout(resolve, 0));
    // One request is out: the later calls did not take it, and began none.
    expect(begun).toHaveLength(1);
    begun[0]!.release(["pdpp.acme~"]);
    expect((await first).map((r) => r.scope)).toEqual(["pdpp.acme~"]);
    await new Promise((resolve) => setTimeout(resolve, 0));
    // The later calls share one listing, begun after the first one ended.
    expect(begun).toHaveLength(2);
    begun[1]!.release(["pdpp.acme~", streamScope("acme", "", "s1")]);
    expect((await second).map((r) => r.scope)).toEqual(["pdpp.acme~"]);
    expect((await third).length).toBe(1);
    expect(begun).toHaveLength(2);
  });

  it("calls made in one run of code share one listing: no write can land between them", async () => {
    const { begun, fetch } = held();
    const registry = registryOver(fetch);
    const controls = registry.listControlRows();
    const streams = registry.listStreamRows("acme");
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(begun).toHaveLength(1);
    begun[0]!.release(["pdpp.acme~", streamScope("acme", "", "s1")]);
    expect((await controls).map((r) => r.scope)).toEqual(["pdpp.acme~"]);
    expect((await streams).map((r) => r.scope)).toEqual([
      streamScope("acme", "", "s1"),
    ]);
    // A call in a later run of code does not take that listing.
    const later = registry.listControlRows();
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(begun).toHaveLength(2);
    begun[1]!.release([]);
    expect(await later).toEqual([]);
  });

  it("a failed listing fails its own callers and not the ones waiting for the next", async () => {
    let calls = 0;
    const fetch = (async () => {
      if (++calls === 1) throw new TypeError("terminated");
      return new Response(
        JSON.stringify({
          data: { dataPoints: [] },
          pagination: { hasMore: false },
        }),
        { status: 200 },
      );
    }) as unknown as typeof globalThis.fetch;
    const registry = registryOver(fetch);
    const first = registry.listControlRows();
    await Promise.resolve();
    const second = registry.listControlRows();
    await expect(first).rejects.toBeInstanceOf(RegistryUnavailableError);
    await expect(second).resolves.toEqual([]);
    expect(calls).toBe(2);
  });
});
