import { afterEach, describe, expect, it } from "vitest";
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
  statSync,
  readFileSync,
} from "node:fs";
import { createHash } from "node:crypto";
import pino from "pino";
import { createGatewayClient } from "@opendatalabs/vana-sdk/node";
import {
  createReplicaOwnerLegacyRoutes,
  openReplicaOwnerLegacyStorage,
} from "./pdpp-replica-owner-legacy-routes.js";
import { createAccessLogWriter } from "../packages/server/src/logging/access-log.js";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  createTestWallet,
  buildWeb3SignedHeader,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import {
  createOwnerComposition,
  evaluateConnectorReadiness,
  loadCompositionSource,
} from "./pdpp-replica-owner-composition.js";
import {
  computeS256Challenge,
  PDPP_DATA_ACCESS_TYPE_V02,
} from "@opendatalabs/personal-server-ts-core/pdpp";

const roots: string[] = [];
const hosts: Awaited<ReturnType<typeof createOwnerComposition>>[] = [];
afterEach(async () => {
  for (const host of hosts.splice(0)) await host.close();
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});
const origin = "http://127.0.0.1:3286";
const accountOrigin = "http://localhost:3084";
async function setup() {
  const root = mkdtempSync(join(tmpdir(), "composition-test-"));
  roots.push(root);
  const owner = createTestWallet(0);
  const host = await createOwnerComposition({
    root,
    owner: owner.address,
    origin,
    accountOrigin,
    clientId: "exact-requester",
    redirectUri: "http://localhost:3284/callback",
  });
  hosts.push(host);
  return { host, owner };
}
const sourceId = "https://replica-journey.invalid/declaration";

it("reuses the existing authority with an exact verified dynamic declaration and zero synthetic records", async () => {
  const { host: previous, owner } = await setup();
  const root = roots.at(-1)!;
  const originalBody = JSON.stringify({ source_id: sourceId });
  const proof = await buildWeb3SignedHeader({
    wallet: owner,
    aud: origin,
    method: "POST",
    uri: "/pdpp/v1/owner/token",
    body: new TextEncoder().encode(originalBody),
  });
  const previousToken = (
    await (
      await previous.app.request("/pdpp/v1/owner/token", {
        method: "POST",
        headers: { authorization: proof, "content-type": "application/json" },
        body: originalBody,
      })
    ).json()
  ).access_token;
  const authorityInode = statSync(join(root, "auth.sqlite")).ino;
  await previous.close();
  hosts.splice(hosts.indexOf(previous), 1);
  const document = readFileSync(
    new URL(
      "./fixtures/strava-browser-source-declaration.json",
      import.meta.url,
    ),
    "utf8",
  );
  const declarationPath = join(root, "source-declaration.json");
  writeFileSync(declarationPath, document);
  const declarationSha256 = createHash("sha256").update(document).digest("hex");
  expect(() =>
    loadCompositionSource({
      declarationPath,
      declarationSha256: "0".repeat(64),
      methodId: "strava-browser",
      connectionId: "actual-owned-connection",
    }),
  ).toThrow();
  const source = loadCompositionSource({
    declarationPath,
    declarationSha256,
    methodId: "strava-browser",
    connectionId: "actual-owned-connection",
  });
  await expect(
    createOwnerComposition({
      root: join(root, "missing-authority"),
      owner: owner.address,
      origin,
      accountOrigin,
      clientId: "exact-requester",
      redirectUri: "http://localhost:3284/callback",
      source,
    }),
  ).rejects.toThrow(/existing auth.sqlite/);
  await expect(
    createOwnerComposition({
      root,
      owner: createTestWallet(1).address,
      origin,
      accountOrigin,
      clientId: "exact-requester",
      redirectUri: "http://localhost:3284/callback",
      source,
    }),
  ).rejects.toThrow(/configured owner/);
  const real = await createOwnerComposition({
    root,
    owner: owner.address,
    origin,
    accountOrigin,
    clientId: "exact-requester",
    redirectUri: "http://localhost:3284/callback",
    source,
    legacyRoutesFactory: (ports) => {
      const storage = openReplicaOwnerLegacyStorage({ root: ports.root });
      return {
        routes: createReplicaOwnerLegacyRoutes({
          ...storage,
          logger: pino({ level: "silent" }),
          serverOwner: ports.serverOwner,
          serverOrigin: ports.serverOrigin,
          serverSigner: ports.serverSigner,
          gatewayConfig: ports.gatewayConfig,
          gateway: createGatewayClient("https://dp-rpc-dev.vana.org"),
          accessLogWriter: createAccessLogWriter(join(ports.root, "logs")),
          granteeAddress: "0x2222222222222222222222222222222222222222",
        }),
        close: () => storage.close(),
      };
    },
  });
  hosts.push(real);
  const state = await (await real.app.request("/composition/state")).json();
  expect(statSync(join(root, "auth.sqlite")).ino).toBe(authorityInode);
  expect(state.source_id).toBe("https://registry.pdpp.dev/sources/strava");
  expect(state.instances).toEqual([]);
  expect(state.streams.map((stream: { name: string }) => stream.name)).toEqual([
    "activities",
  ]);
  expect(state.window).toBeUndefined();
  expect(state.mode).toBe("connector");
  expect(state.ingestion.method).toBe("strava-browser");
  expect(state.ingestion.binding_generation).toBeNull();
  expect(state.canonical_records).toBe(0);
  expect(state.confirmed).toBeUndefined();
  expect(
    (
      await real.app.request(
        "/pdpp/v1/streams/activities/records/ingest?method=strava-browser&binding_generation=1",
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: "[]",
        },
      )
    ).status,
  ).toBe(401);
  expect(
    (
      await real.app.request("/composition/ingest", {
        method: "POST",
        headers: {
          origin: "http://evil.invalid",
          "content-type": "application/json",
        },
        body: "[]",
      })
    ).status,
  ).toBe(403);
  const introspection = await real.app.request("/pdpp/v1/introspect", {
    method: "POST",
    headers: {
      authorization: `Bearer ${previousToken}`,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({ token: previousToken }).toString(),
  });
  expect(introspection.status).toBe(200);
  expect((await introspection.json()).active).toBe(true);
  const { openReplicaRuntime, digest, serverAccount } =
    await import("./pdpp-replica-live-journey.js");
  const runtime = await openReplicaRuntime({
    root: join(root, "offline-collector-A"),
    owner: owner.address,
    master: Array(32).fill(1),
    serverKey: `0x${"01".repeat(32)}`,
    scriptSha256: digest(
      readFileSync(new URL("./pdpp-replica-live-journey.ts", import.meta.url)),
    ),
    source,
  });
  await real.attachCollector(runtime, serverAccount(`0x${"01".repeat(32)}`));
  const mounted = await (await real.app.request("/composition/state")).json();
  expect(mounted.connection_id).toBe("actual-owned-connection");
  expect(mounted.binding_generation).toBe(1);
  expect(mounted.instances).toEqual(["actual-owned-connection"]);
  expect(mounted.canonical_records).toBe(0);
  expect(
    (
      await real.app.request("/composition/ingest", {
        method: "POST",
        headers: { origin: accountOrigin, "content-type": "application/json" },
        body: "[]",
      })
    ).status,
  ).toBe(404);
  const issueBody = JSON.stringify({
    source_id: "https://registry.pdpp.dev/sources/strava",
  });
  async function issueSourceToken() {
    const authorization = await buildWeb3SignedHeader({
      wallet: owner,
      aud: origin,
      method: "POST",
      uri: "/pdpp/v1/owner/token",
      body: new TextEncoder().encode(issueBody),
    });
    const response = await real.app.request("/pdpp/v1/owner/token", {
      method: "POST",
      headers: { authorization, "content-type": "application/json" },
      body: issueBody,
    });
    expect(response.status).toBe(200);
    return (await response.json()).access_token as string;
  }
  const credential = await issueSourceToken();
  expect((await real.app.request("/v1/data/strava.activities")).status).toBe(
    401,
  );
  expect(
    (
      await real.app.request("/v1/grants", {
        method: "POST",
        headers: {
          authorization: `Bearer ${credential}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          granteeAddress: "0x2222222222222222222222222222222222222222",
          scopes: ["strava.activities"],
        }),
      })
    ).status,
  ).toBe(401);
  const readProof = await buildWeb3SignedHeader({
    wallet: owner,
    aud: origin,
    method: "GET",
    uri: "/v1/data/strava.activities",
  });
  expect(
    (
      await real.app.request("/v1/data/strava.activities", {
        headers: { authorization: readProof },
      })
    ).status,
  ).toBe(404);
  const envelope = {
    instance: "actual-owned-connection",
    stream: "activities",
    key: "offline-test-only",
    data: {
      id: "offline-test-only",
      start_date: "2026-10-01",
      start_time: "2026-10-01T08:30:00",
      start_time_basis: "local",
      freshness: "live",
      exported_at: null,
      distance_m: 1234.5,
    },
    emitted_at: "2026-10-21T01:00:00Z",
  };
  const ingestUrl = mounted.ingestion.streams[0].url;
  expect(ingestUrl).toBe(
    origin +
      "/pdpp/v1/streams/activities/records/ingest?method=strava-browser&binding_generation=1",
  );
  const ingest = (token: string | undefined, input: unknown, url = ingestUrl) =>
    real.app.request(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(token && { authorization: `Bearer ${token}` }),
      },
      body: JSON.stringify(input),
    });
  expect((await ingest(undefined, envelope)).status).toBe(401);
  expect((await ingest(previousToken, envelope)).status).toBe(401);
  expect(
    (await ingest(credential, { ...envelope, instance: "unowned" })).status,
  ).toBe(401);
  expect(
    (
      await ingest(
        credential,
        envelope,
        origin + "/pdpp/v1/streams/activities/records/ingest",
      )
    ).status,
  ).toBe(400);
  expect(
    (
      await ingest(
        credential,
        envelope,
        origin +
          "/pdpp/v1/streams/activities/records/ingest?method=export&binding_generation=1",
      )
    ).status,
  ).toBe(409);
  expect(
    (
      await ingest(
        credential,
        envelope,
        origin +
          "/pdpp/v1/streams/activities/records/ingest?method=strava-browser&binding_generation=2",
      )
    ).status,
  ).toBe(409);
  const foreignOwnerProof = await buildWeb3SignedHeader({
    wallet: createTestWallet(1),
    aud: origin,
    method: "POST",
    uri: "/pdpp/v1/owner/token",
    body: new TextEncoder().encode(issueBody),
  });
  expect(
    (
      await real.app.request("/pdpp/v1/owner/token", {
        method: "POST",
        headers: {
          authorization: foreignOwnerProof,
          "content-type": "application/json",
        },
        body: issueBody,
      })
    ).status,
  ).toBe(401);
  expect(
    (await (await real.app.request("/composition/state")).json())
      .canonical_records,
  ).toBe(0);
  const accepted = await ingest(credential, envelope);
  expect(accepted.status).toBe(200);
  expect((await accepted.json()).accepted).toBe(1);
  expect(runtime.snapshot().canonicalRows).toEqual([
    {
      instance: envelope.instance,
      stream: envelope.stream,
      record_key: envelope.key,
      data: envelope.data,
      emitted_at: envelope.emitted_at,
      deleted: 0,
      blob_id: null,
    },
  ]);
  await issueSourceToken();
  expect(
    (await (await real.app.request("/composition/state")).json())
      .canonical_records,
  ).toBe(1);

  // Offline transport proof: the row A accepted through its normal owner
  // ingest must be exportable by A and importable by an independent B that
  // is bound to the same declaration, with no network transport involved.
  const receiverB = await openReplicaRuntime({
    root: join(root, "offline-receiver-B"),
    owner: owner.address,
    master: Array(32).fill(1),
    serverKey: `0x${"02".repeat(32)}`,
    scriptSha256: digest(
      readFileSync(new URL("./pdpp-replica-live-journey.ts", import.meta.url)),
    ),
    source,
  });
  try {
    expect(receiverB.snapshot().canonicalRows).toEqual([]);
    const operations = [
      ...runtime.store.replication.readBaselinePage({ limit: 1000 }).operations,
      ...runtime.store.replication.readTailPage({ limit: 1000 }).operations,
    ];
    expect(operations.filter((op) => op.kind === "upsert")).toHaveLength(1);
    const plan = receiverB.receiver.import({
      credential: "isolated-harness",
      envelope: {
        format: "vana-pdpp-replica",
        version: 1,
        owner: owner.address,
        batchId: "offline-ingest-to-import",
        operations,
      },
    });
    expect(plan.rejected).toEqual([]);
    expect(plan.conflicts).toEqual([]);
    expect(plan.pending).toEqual([]);
    expect(plan.records).toHaveLength(1);
    const fields = [
      "instance",
      "stream",
      "record_key",
      "data",
      "emitted_at",
      "deleted",
      "blob_id",
    ] as const;
    const project = (rows: readonly Record<string, unknown>[] | undefined) =>
      rows?.map((r) => Object.fromEntries(fields.map((f) => [f, r[f]])));
    expect(project(receiverB.snapshot().canonicalRows)).toEqual(
      project(runtime.snapshot().canonicalRows),
    );
    expect(receiverB.snapshot().canonicalRows).toHaveLength(1);
  } finally {
    await receiverB.close();
  }
});

it("refuses owner token issuance without normal wallet proof and requires a signed source body", async () => {
  const { host, owner } = await setup();
  const path = "/pdpp/v1/owner/token";
  const body = JSON.stringify({ source_id: sourceId });
  for (const authorization of [undefined, "Bearer fake", "Web3Signed 0x00"]) {
    const response = await host.app.request(path, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(authorization && { authorization }),
      },
      body,
    });
    expect(response.status).toBe(401);
  }
  const authorization = await buildWeb3SignedHeader({
    wallet: owner,
    aud: origin,
    method: "POST",
    uri: path,
    body: new TextEncoder().encode(body),
  });
  const valid = await host.app.request(path, {
    method: "POST",
    headers: { authorization, "content-type": "application/json" },
    body,
  });
  expect(valid.status).toBe(200);
  const credential = (await valid.json()).access_token;
  expect(typeof credential).toBe("string");
  const state = JSON.stringify(
    await (await host.app.request("/composition/state")).json(),
  );
  expect(state).not.toContain(credential);
  expect(JSON.parse(state).owner_proof_received).toBe(true);
  const missingBody = JSON.stringify({});
  const missingProof = await buildWeb3SignedHeader({
    wallet: owner,
    aud: origin,
    method: "POST",
    uri: path,
    body: new TextEncoder().encode(missingBody),
  });
  expect(
    (
      await host.app.request(path, {
        method: "POST",
        headers: {
          authorization: missingProof,
          "content-type": "application/json",
        },
        body: missingBody,
      })
    ).status,
  ).toBe(400);
  const foreignProof = await buildWeb3SignedHeader({
    wallet: createTestWallet(1),
    aud: origin,
    method: "POST",
    uri: path,
    body: new TextEncoder().encode(body),
  });
  expect(
    (
      await host.app.request(path, {
        method: "POST",
        headers: {
          authorization: foreignProof,
          "content-type": "application/json",
        },
        body,
      })
    ).status,
  ).toBe(401);
});

it("accepts only fixed owner signatures once, including concurrent submissions, with exact Account CORS", async () => {
  const { host, owner } = await setup();
  const requests = (await (await host.app.request("/composition/state")).json())
    .signing_requests;
  expect(requests).toHaveLength(3);
  const send = (body: unknown, from = accountOrigin) =>
    host.app.request("/composition/signatures", {
      method: "POST",
      headers: { origin: from, "content-type": "application/json" },
      body: JSON.stringify(body),
    });
  const master = requests.find(
    (r: { method: string }) => r.method === "personal_sign",
  );
  expect((await send({ request_id: master.request_id })).status).toBe(400);
  expect(
    (
      await send({
        request_id: master.request_id,
        signature: await createTestWallet(1).signMessage(master.message),
      })
    ).status,
  ).toBe(401);
  const signature = await owner.signMessage(master.message);
  expect(
    (
      await send(
        { request_id: master.request_id, signature },
        "http://evil.invalid",
      )
    ).status,
  ).toBe(403);
  expect(
    (
      await send({
        request_id: master.request_id,
        signature,
        message: "arbitrary",
      })
    ).status,
  ).toBe(400);
  const results = await Promise.all([
    send({ request_id: master.request_id, signature }),
    send({ request_id: master.request_id, signature }),
  ]);
  expect(results.map((r) => r.status).sort()).toEqual([200, 409]);
  expect(
    (await send({ request_id: master.request_id, signature })).status,
  ).toBe(409);
  for (const request of requests.filter(
    (r: { method: string }) => r.method === "eth_signTypedData_v4",
  )) {
    const signed = await owner.signTypedData(request.typed_data);
    expect(
      (await send({ request_id: request.request_id, signature: signed }))
        .status,
    ).toBe(200);
    const state = await (await host.app.request("/composition/state")).text();
    expect(state).not.toContain(signed);
    expect(state).not.toContain(signature);
  }
  expect(
    (await (await host.app.request("/composition/state")).json())
      .signing_requests,
  ).toEqual([]);
});

it("uses one configured issuer, exact registered callback and PKCE; never proxies writes or arbitrary paths", async () => {
  const { host, owner } = await setup();
  const metadata = await (
    await host.app.request("/.well-known/oauth-authorization-server/pdpp/v1")
  ).json();
  expect(metadata.issuer).toBe(origin);
  expect(metadata.token_endpoint).toBe(origin + "/pdpp/v1/token");
  expect(metadata.code_challenge_methods_supported).toEqual(["S256"]);
  expect(
    (await host.app.request("/pdpp/v1/streams/messages/records")).status,
  ).toBe(503);
  expect(
    (
      await host.app.request("/pdpp/v1/streams/messages/records/ingest", {
        method: "POST",
      })
    ).status,
  ).toBe(404);
  expect((await host.app.request("/pdpp/v1/arbitrary")).status).toBe(404);
  const body = JSON.stringify({ source_id: sourceId });
  const proof = await buildWeb3SignedHeader({
    wallet: owner,
    aud: origin,
    method: "POST",
    uri: "/pdpp/v1/owner/token",
    body: new TextEncoder().encode(body),
  });
  const token = (
    await (
      await host.app.request("/pdpp/v1/owner/token", {
        method: "POST",
        headers: { authorization: proof, "content-type": "application/json" },
        body,
      })
    ).json()
  ).access_token;
  const request = {
    client_id: "exact-requester",
    redirect_uri: "http://localhost:3284/callback",
    state: "real-test",
    code_challenge: computeS256Challenge(
      "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    ),
    code_challenge_method: "S256",
    authorization_details: [
      {
        type: PDPP_DATA_ACCESS_TYPE_V02,
        source: { id: sourceId },
        purpose_code: "https://replica-app.invalid/purposes/acceptance",
        access_mode: "continuous",
        retention: { max_duration: "P1D", on_expiry: "delete" },
        streams: [
          {
            name: "messages",
            necessity: "required",
            fields: ["text", "collected_at", "blob_ref"],
            minimum: { fields: ["text"] },
          },
        ],
      },
    ],
  };
  const authorize = (selection: unknown) =>
    host.app.request("/pdpp/v1/authorize", {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(selection),
    });
  expect(
    (
      await authorize({
        ...request,
        redirect_uri: "http://localhost:3284/callback?unregistered=true",
      })
    ).status,
  ).toBe(400);
  expect(
    (await authorize({ ...request, client_id: "unregistered-requester" }))
      .status,
  ).toBe(400);
  expect(
    (await authorize({ ...request, code_challenge: undefined })).status,
  ).toBe(400);
  expect((await authorize(request)).status).toBe(201);
});

describe("connector readiness receipt", () => {
  const row = {
    instance: "actual-owned-connection",
    stream: "activities",
    record_key: "run-1",
    data: { id: "run-1", distance_m: 1234.5 },
    emitted_at: "2026-10-21T01:00:00Z",
    deleted: 0,
    blob_id: "blob-1" as string | null,
  };
  const blobs = { "blob-1": { sha256: "aa".repeat(32), bytes: 7 } };
  const stored = { record_key: "run-1" } as never;
  const active = { head: null, chain: { status: "Active" } } as never;
  function evaluate(
    over: {
      a?: Record<string, unknown>;
      b?: Record<string, unknown>;
      sql?: { a?: unknown[]; b?: unknown[] };
    } = {},
  ) {
    const aRows = [row];
    return evaluateConnectorReadiness({
      sourceId: "https://registry.pdpp.dev/sources/strava",
      sql: { a: over.sql?.a ?? aRows, b: over.sql?.b ?? [{ ...row }] },
      a: {
        ownerRows: [stored],
        pending: 0,
        canonicalRows: aRows,
        blobs,
        ...over.a,
      },
      b: {
        appRows: [stored],
        canonicalRows: [{ ...row }],
        blobs: { ...blobs },
        evidence: [active],
        ...over.b,
      },
    });
  }
  const notReady = (result: ReturnType<typeof evaluate>) =>
    result.ready ? "ready" : result.reason;

  it("is ready only on an exact match, with the receipt the evidence claim rests on", () => {
    const result = evaluate();
    expect(result).toEqual({
      ready: true,
      receipt: {
        canonical_rows: 1,
        canonical_sha256: createHash("sha256")
          .update(JSON.stringify([row]))
          .digest("hex"),
        canonical_fields: [
          "instance",
          "stream",
          "record_key",
          "data",
          "emitted_at",
          "deleted",
          "blob_id",
        ],
        referenced_blobs: 1,
        records_sha256: createHash("sha256")
          .update(JSON.stringify([row]))
          .digest("hex"),
        source_id: "https://registry.pdpp.dev/sources/strava",
      },
    });
  });

  it("is not ready with zero rows, even if everything else agrees", () => {
    expect(
      notReady(
        evaluate({
          sql: { a: [], b: [] },
          a: { ownerRows: [], canonicalRows: [] },
          b: { appRows: [], canonicalRows: [] },
        }),
      ),
    ).toBe("no_rows");
  });

  it("is not ready while A still has unpublished outbound work", () => {
    expect(notReady(evaluate({ a: { pending: 1 } }))).toBe("outbound_pending");
  });

  it("is not ready when B holds one row fewer than A", () => {
    expect(notReady(evaluate({ b: { appRows: [], canonicalRows: [] } }))).toBe(
      "rows_unconfirmed",
    );
  });

  it("is not ready while a B row still carries a pending confirmation", () => {
    expect(
      notReady(
        evaluate({
          b: { appRows: [{ record_key: "run-1", confirmation: "pending" }] },
        }),
      ),
    ).toBe("rows_unconfirmed");
  });

  it.each([
    ["data", { data: { id: "run-1", distance_m: 1 } }],
    ["emitted_at", { emitted_at: "2026-10-21T02:00:00Z" }],
    ["blob_id", { blob_id: "blob-2" }],
  ])("is not ready when B differs from A in %s only", (_field, change) => {
    expect(
      notReady(evaluate({ b: { canonicalRows: [{ ...row, ...change }] } })),
    ).toBe("canonical_rows_differ");
  });

  it.each([
    ["data", { data: { id: "run-1", distance_m: 1 } }],
    ["deleted", { deleted: 1 }],
  ])(
    "is not ready when the SQL tables differ in %s although the snapshots agree",
    (_field, change) => {
      expect(notReady(evaluate({ sql: { b: [{ ...row, ...change }] } }))).toBe(
        "sql_rows_differ",
      );
    },
  );

  it("is not ready when B's SQL table is missing a row", () => {
    expect(notReady(evaluate({ sql: { b: [] } }))).toBe("sql_rows_differ");
  });

  it("is not ready when a blob digest differs", () => {
    expect(
      notReady(
        evaluate({
          b: { blobs: { "blob-1": { sha256: "cc".repeat(32), bytes: 7 } } },
        }),
      ),
    ).toBe("blobs_differ");
  });

  it("is not ready without Active chain evidence", () => {
    expect(
      notReady(
        evaluate({
          b: {
            evidence: [
              { head: null, chain: { status: "Pending" } },
              { head: null, chain: null },
            ],
          },
        }),
      ),
    ).toBe("no_active_chain");
  });
});
