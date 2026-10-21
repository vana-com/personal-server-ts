/** Dedicated dev owner only: receives its master-key signature and derives worker keys. */
import assert from "node:assert/strict";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  statSync,
} from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { isDeepStrictEqual, parseArgs } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";
import { serve } from "@hono/node-server";
import { Hono } from "hono";
import pino from "pino";
import {
  createPublicClient,
  getAddress,
  http,
  recoverMessageAddress,
  recoverTypedDataAddress,
  type Hex,
} from "viem";
import { generatePrivateKey } from "viem/accounts";
import {
  deriveMasterKey,
  MASTER_KEY_MESSAGE,
  SERVER_REGISTRATION_TYPES,
  serverRegistrationDomain,
  createGatewayClient,
} from "@opendatalabs/vana-sdk/node";
import {
  AuthorizationSessionStore,
  openPdppAuthStore,
  PdppTokenService,
  parseDeclaration,
  type DeclarationSnapshot,
} from "@opendatalabs/personal-server-ts-core/pdpp";
import {
  pdppAuthRoutes,
  pdppAsMetadataHandler,
  type PdppAuthRouteDeps,
} from "../packages/server/src/routes/pdpp-auth.js";
import { pdppWellKnownRoutes } from "../packages/server/src/routes/pdpp-well-known.js";
import {
  allowHarnessLoopback,
  config,
  Device,
  digest,
  gatewayUrl,
  installHarnessSafety,
  openReplicaRuntime,
  pause,
  rpcUrl,
  serverAccount,
  sourceId,
  storageUrl,
  type Snapshot,
} from "./pdpp-replica-live-journey.js";
import {
  assertCanonicalEquality,
  canonicalRows,
} from "./pdpp-replica-consent-live-journey.js";
import { createBodyLimit } from "../packages/server/src/middleware/body-limit.js";
import {
  buildReplicaRuntimeSource,
  type ReplicaRuntimeSource,
} from "./pdpp-replica-runtime-source.js";
import { createPdppRecordsDeps } from "../packages/server/src/pdpp/records-bootstrap.js";
import { pdppRecordsRoutes } from "../packages/server/src/routes/pdpp-records.js";
import {
  createServerSigner,
  type ServerSigner,
} from "../packages/core/src/signing/signer.js";
import { createAccessLogWriter } from "../packages/server/src/logging/access-log.js";
import {
  createReplicaOwnerLegacyRoutes,
  openReplicaOwnerLegacyStorage,
} from "./pdpp-replica-owner-legacy-routes.js";

export type CompositionLegacyPorts = {
  root: string;
  runtime: Awaited<ReturnType<typeof openReplicaRuntime>>;
  serverOwner: Hex;
  serverOrigin: string;
  account: ReturnType<typeof serverAccount>;
  serverSigner: ServerSigner;
  gatewayConfig: typeof config.gateway;
};
export type CompositionLegacyRoutesFactory = (
  ports: CompositionLegacyPorts,
) =>
  | Promise<{ routes: Hono; close?: () => void | Promise<void> }>
  | { routes: Hono; close?: () => void | Promise<void> };

export type CompositionOptions = {
  root: string;
  owner: Hex;
  origin: string;
  accountOrigin: string;
  clientId: string;
  redirectUri: string;
  source?: ReplicaRuntimeSource;
  legacyRoutesFactory?: CompositionLegacyRoutesFactory;
  granteeAddress?: Hex;
};
const fixtureDeclaration: DeclarationSnapshot = {
  source_id: sourceId,
  source_kind: "connector",
  version: "1",
  digest: "a".repeat(64),
  streams: [
    {
      name: "messages",
      fields: ["id", "text", "collected_at", "blob_ref", "private_note"],
      required_fields: ["id", "private_note"],
      primary_key: ["id"],
      consent_time_field: "collected_at",
    },
  ],
};

export function loadCompositionSource(options: {
  declarationPath: string;
  declarationSha256: string;
  methodId: string;
  connectionId: string;
}): ReplicaRuntimeSource {
  assert(
    /^[a-f0-9]{64}$/.test(options.declarationSha256),
    "An explicit declaration byte SHA-256 is required",
  );
  const bytes = readFileSync(options.declarationPath);
  assert.equal(
    digest(bytes),
    options.declarationSha256,
    "Declaration byte SHA-256 mismatch",
  );
  const document = bytes.toString("utf8");
  const wire = JSON.parse(document) as {
    source?: { id?: string };
    source_id?: string;
  };
  const id = wire.source?.id ?? wire.source_id;
  assert(id, "Declaration must identify its source");
  const parsed = parseDeclaration(document, id);
  assert(parsed.ok, "Invalid source declaration");
  const descriptor = {
    declaration: parsed.snapshot,
    document,
    methodId: options.methodId,
    connectionId: options.connectionId,
  };
  buildReplicaRuntimeSource(descriptor);
  return descriptor;
}

export type ConnectorReceipt = {
  canonical_rows: number;
  canonical_sha256: string;
  canonical_fields: string[];
  referenced_blobs: number;
  records_sha256: string;
  source_id: string;
};
export type ConnectorNotReady =
  | "no_rows"
  | "outbound_pending"
  | "rows_unconfirmed"
  | "canonical_rows_differ"
  | "oracle_mismatch"
  | "blobs_differ"
  | "no_active_chain";

/**
 * Decides whether device B has confirmed device A's real-source records.
 * Fails closed: every mismatch is "not ready" with a reason, never a throw.
 * `oracle` runs the independent SQL comparison only once the in-memory
 * snapshots already agree; its throw is a mismatch.
 */
export function evaluateConnectorReadiness(input: {
  a: Pick<Snapshot, "ownerRows" | "pending" | "canonicalRows" | "blobs">;
  b: Pick<Snapshot, "appRows" | "canonicalRows" | "blobs" | "evidence">;
  aCanonical: readonly unknown[];
  sourceId: string;
  oracle: () => { B: string; fields: string[] };
}):
  | { ready: true; receipt: ConnectorReceipt }
  | { ready: false; reason: ConnectorNotReady } {
  const { a, b } = input;
  const no = (reason: ConnectorNotReady) => ({ ready: false as const, reason });
  if (input.aCanonical.length === 0) return no("no_rows");
  if (a.pending !== 0) return no("outbound_pending");
  if (
    a.ownerRows.length === 0 ||
    b.appRows.length !== a.ownerRows.length ||
    b.appRows.some((row) => row.confirmation !== undefined)
  )
    return no("rows_unconfirmed");
  if (!b.canonicalRows || !isDeepStrictEqual(a.canonicalRows, b.canonicalRows))
    return no("canonical_rows_differ");
  let oracle: { B: string; fields: string[] };
  try {
    oracle = input.oracle();
  } catch {
    return no("oracle_mismatch");
  }
  if (!isDeepStrictEqual(a.blobs, b.blobs)) return no("blobs_differ");
  if (!b.evidence.some((entry) => entry.chain?.status === "Active"))
    return no("no_active_chain");
  return {
    ready: true,
    receipt: {
      canonical_rows: input.aCanonical.length,
      canonical_sha256: oracle.B,
      canonical_fields: oracle.fields,
      referenced_blobs: Object.keys(b.blobs).length,
      records_sha256: digest(JSON.stringify(b.canonicalRows)),
      source_id: input.sourceId,
    },
  };
}

export async function createOwnerComposition(options: CompositionOptions) {
  options = { ...options, owner: getAddress(options.owner) };
  const source = options.source
    ? buildReplicaRuntimeSource(options.source)
    : undefined;
  const sourceId = source?.sourceId ?? fixtureDeclaration.source_id;
  const declaration = source?.declaration ?? fixtureDeclaration;
  const head = execFileSync("git", ["rev-parse", "HEAD"], {
    encoding: "utf8",
  }).trim();
  const runtimeSourceHashes = Object.fromEntries(
    [
      "./pdpp-replica-owner-composition.ts",
      "./pdpp-replica-live-journey.ts",
      "./pdpp-replica-runtime-source.ts",
      "./pdpp-replica-consent-live-journey.ts",
      "./pdpp-replica-owner-legacy-routes.ts",
      "../packages/server/src/routes/pdpp-records.ts",
      "../packages/server/src/routes/pdpp-blobs.ts",
      "../packages/server/src/storage/pdpp-replication-receiver.ts",
      "../packages/server/src/pdpp/replica-authorization.ts",
    ].map((path) => [
      path,
      digest(readFileSync(new URL(path, import.meta.url))),
    ]),
  );
  const publicUrl = new URL(options.origin);
  assert(
    publicUrl.protocol === "http:" &&
      publicUrl.hostname === "127.0.0.1" &&
      publicUrl.port &&
      publicUrl.origin === options.origin,
    "Public origin must be exact loopback HTTP origin",
  );
  assert.equal(
    options.accountOrigin,
    "http://localhost:3084",
    "Only C1's Account origin is allowed",
  );
  assert(
    options.clientId.length > 0 && !/[\s\x00-\x1f]/.test(options.clientId),
    "Explicit requester client ID required",
  );
  const callback = new URL(options.redirectUri);
  assert(
    callback.protocol === "http:" &&
      ["localhost", "127.0.0.1"].includes(callback.hostname) &&
      !callback.username &&
      !callback.password &&
      !callback.hash,
    "Redirect must be an explicit local callback",
  );
  const authorityPath = join(options.root, "auth.sqlite");
  if (source) {
    assert.equal(
      options.origin,
      "http://127.0.0.1:3286",
      "Real-source upgrade preserves the existing issuer origin",
    );
    assert(
      existsSync(authorityPath) && statSync(authorityPath).isFile(),
      "Real-source mode requires the existing auth.sqlite",
    );
    // Opening an existing file read-only first prevents SQLite from silently
    // creating authority on a misspelled root and verifies the supplied DB.
    const { default: Database } = await import("better-sqlite3");
    const existing = new Database(authorityPath, {
      readonly: true,
      fileMustExist: true,
    });
    try {
      assert(
        existing
          .prepare(
            "SELECT name FROM sqlite_master WHERE name='pdpp_access_tokens'",
          )
          .get(),
        "Existing PDPP authority tables are required",
      );
      const owners = existing
        .prepare(
          "SELECT DISTINCT lower(subject_id) AS owner FROM pdpp_access_tokens UNION SELECT DISTINCT lower(subject_id) AS owner FROM pdpp_grants",
        )
        .all() as { owner: string }[];
      assert(
        owners.length === 1 && owners[0].owner === options.owner.toLowerCase(),
        "Existing authority must belong to the configured owner",
      );
    } finally {
      existing.close();
    }
  } else mkdirSync(options.root, { recursive: true, mode: 0o700 });
  const store = openPdppAuthStore(join(options.root, "auth.sqlite"));
  if (source) {
    try {
      const retained = store.getDeclaration(sourceId, declaration.version);
      if (retained)
        assert.deepEqual(
          retained,
          declaration,
          "Existing retained declaration differs from verified bytes",
        );
      const retainedDocument = store.getDeclarationDocument(
        sourceId,
        declaration.version,
      );
      if (retainedDocument !== null)
        assert.equal(
          retainedDocument,
          source.document,
          "Existing retained declaration bytes differ",
        );
      store.retainDeclaration(declaration, source.document);
    } catch (error) {
      store.close();
      throw error;
    }
  }
  const tokens = new PdppTokenService(store, { accessTokenTtlSeconds: 3600 });
  let credential: string | undefined;
  const serverKeys = [generatePrivateKey(), generatePrivateKey()];
  const runId = randomUUID();
  const typedRequests = serverKeys.map((key, index) => ({
    domain: serverRegistrationDomain(config.gateway),
    types: SERVER_REGISTRATION_TYPES,
    primaryType: "ServerRegistration" as const,
    message: {
      ownerAddress: options.owner,
      serverAddress: serverAccount(key).address,
      publicKey: serverAccount(key).publicKey,
      serverUrl: `https://replica-owner-${index}-${runId}.invalid`,
    },
  }));
  const requests = [
    {
      request_id: randomUUID(),
      method: "personal_sign" as const,
      message: MASTER_KEY_MESSAGE,
    },
    ...typedRequests.map((typed_data, index) => ({
      request_id: randomUUID(),
      method: "eth_signTypedData_v4" as const,
      device: index === 0 ? "A" : "B",
      typed_data,
    })),
  ];
  const statuses = new Map(requests.map((r) => [r.request_id, "pending"]));
  const signatures = new Map<string, Hex>();
  let phase = "awaiting_owner";
  let closed = false;
  let started = false;
  let resourceOrigin: string | undefined;
  let disallowResource: (() => void) | undefined;
  let failure: string | undefined;
  let cycleRetries = 0;
  let confirmed:
    | {
        record_id: string;
        record_sha256: string;
        canonical_sha256: string;
        blob_id: string;
        blob_sha256: string;
        blob_bytes: number;
      }
    | undefined;
  let connectorConfirmed: ConnectorReceipt | undefined;
  const devices: Device[] = [];
  let collector: Awaited<ReturnType<typeof openReplicaRuntime>> | undefined;
  let collectorRoutes: Hono | undefined;
  let legacyRoutes: Hono | undefined;
  let closeLegacy: (() => void | Promise<void>) | undefined;
  const app = new Hono();
  app.onError((_error, c) =>
    c.json({ error: "composition_request_failed" }, 500),
  );
  app.use("*", async (c, next) => {
    c.header("Cache-Control", "no-store");
    const origin = c.req.header("origin");
    if (origin && origin !== options.accountOrigin)
      return c.json({ error: "origin_refused" }, 403);
    if (origin) {
      c.header("Access-Control-Allow-Origin", options.accountOrigin);
      c.header("Vary", "Origin");
      c.header(
        "Access-Control-Allow-Headers",
        "authorization,content-type,pdpp-version",
      );
      c.header("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
      c.header("Access-Control-Allow-Private-Network", "true");
    }
    if (c.req.method === "OPTIONS") return c.body(null, 204);
    await next();
  });
  app.all("/v1/*", (c) =>
    legacyRoutes
      ? legacyRoutes.fetch(c.req.raw)
      : c.json({ error: "legacy_routes_unavailable" }, 404),
  );
  app.use("/pdpp/v1/owner/token", async (c, next) => {
    await next();
    if (c.res.status !== 200) return;
    const result = (await c.res.clone().json()) as { access_token?: string };
    if (typeof result.access_token !== "string") return;
    const context = tokens.resolveToken(result.access_token);
    if (
      context.active &&
      context.tokenKind === "owner" &&
      context.subjectId?.toLowerCase() === options.owner.toLowerCase() &&
      context.sourceId === sourceId
    ) {
      credential = result.access_token;
    }
  });
  app.use("/composition/signatures", createBodyLimit(4096));
  app.post("/composition/signatures", async (c) => {
    if (c.req.header("origin") !== options.accountOrigin)
      return c.json({ error: "origin_required" }, 403);
    if (c.req.query() && Object.keys(c.req.query()).length)
      return c.json({ error: "query_refused" }, 400);
    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "invalid_request" }, 400);
    }
    if (!body || typeof body !== "object" || Array.isArray(body))
      return c.json({ error: "invalid_request" }, 400);
    const submitted = body as Record<string, unknown>;
    if (
      Object.keys(submitted).length !== 2 ||
      typeof submitted.request_id !== "string" ||
      typeof submitted.signature !== "string" ||
      !/^0x[0-9a-fA-F]{130}$/.test(submitted.signature)
    )
      return c.json({ error: "invalid_request" }, 400);
    const request = requests.find((r) => r.request_id === submitted.request_id);
    if (!request) return c.json({ error: "unknown_request" }, 404);
    if (statuses.get(request.request_id) !== "pending")
      return c.json({ error: "request_consumed" }, 409);
    statuses.set(request.request_id, "verifying");
    const signature = submitted.signature as Hex;
    try {
      const recovered =
        request.method === "personal_sign"
          ? await recoverMessageAddress({ message: request.message, signature })
          : await recoverTypedDataAddress({ ...request.typed_data, signature });
      if (recovered.toLowerCase() !== options.owner.toLowerCase())
        throw new Error("Wrong signer");
      signatures.set(request.request_id, signature);
      statuses.set(request.request_id, "accepted");
      return c.json({ accepted: true, request_id: request.request_id });
    } catch {
      statuses.set(request.request_id, "pending");
      return c.json({ error: "owner_signature_required" }, 401);
    }
  });
  const authDeps: PdppAuthRouteDeps = {
    logger: pino({ level: "silent" }),
    store,
    tokens,
    sessions: new AuthorizationSessionStore(),
    ownerAuth: {
      serverOwner: options.owner,
      serverOrigin: () => options.origin,
    },
    issuer: () => options.origin,
    resolveDeclaration: (id) => (id === sourceId ? declaration : null),
    inventoryFor: () => ({
      eligibleFor: () =>
        source
          ? (collector?.store
              .listConnections(sourceId)
              .filter((connection) => connection.deletedAt === null)
              .map((connection) => connection.instance) ?? [])
          : ["conn", "conn-other"],
    }),
    currentSubjectId: (c) => {
      const context = tokens.resolveToken(
        c.req.header("authorization")?.replace(/^Bearer /i, "") ?? "",
      );
      return context.active &&
        context.tokenKind === "owner" &&
        context.sourceId === sourceId &&
        context.subjectId?.toLowerCase() === options.owner.toLowerCase()
        ? context.subjectId
        : null;
    },
    registeredClient: (id) =>
      id === options.clientId
        ? { client_id: id, redirect_uris: [options.redirectUri] }
        : null,
  };
  app.route("/pdpp/v1", pdppAuthRoutes(authDeps));
  // A owns the normal owner ingest route. All reads below still go to B.
  // This route never substitutes the captured introspection credential.
  if (source)
    app.post("/pdpp/v1/streams/:stream/records/ingest", async (c) => {
      const context = tokens.resolveToken(
        c.req.header("authorization")?.replace(/^Bearer /i, "") ?? "",
      );
      if (
        !context.active ||
        context.tokenKind !== "owner" ||
        context.subjectId?.toLowerCase() !== options.owner.toLowerCase() ||
        context.sourceId !== sourceId
      )
        return c.json({ error: "authentication_error" }, 401);
      if (!collectorRoutes)
        return c.json({ error: "collector_not_ready" }, 503);
      return collectorRoutes.fetch(c.req.raw);
    });
  async function attachCollector(
    runtime: Awaited<ReturnType<typeof openReplicaRuntime>>,
    account?: ReturnType<typeof serverAccount>,
  ) {
    assert(source, "Collector mount requires a real source");
    assert(!collector, "Collector already mounted");
    const binding = runtime.store.getInstanceBinding(source.connectionId);
    assert(
      binding.sourceId === sourceId &&
        binding.method === source.methodId &&
        binding.deletedAt === null &&
        binding.generation === 1,
      "Collector requires the actual fresh registered binding",
    );
    const deps = createPdppRecordsDeps({
      pdppAuth: authDeps,
      declarations: [declaration],
      db: runtime.db,
      serverOwner: options.owner,
      resource: options.origin,
      logger: pino({ level: "silent" }),
      configuredMethods: [{ sourceId, methodId: source.methodId }],
    });
    assert(deps, "Normal PDPP records bootstrap is required");
    collector = runtime;
    collectorRoutes = new Hono().route(
      "/pdpp/v1",
      pdppRecordsRoutes({
        ...deps,
        store: runtime.store,
        bindingStore: runtime.store,
        logger: pino({ level: "silent" }),
        ownerSubjectId: options.owner,
        reads: (reader) => runtime.receiver.readStore({ reader }),
      }),
    );
    if (options.legacyRoutesFactory) {
      assert(
        account,
        "Legacy routes require the same A server signing identity",
      );
      const legacy = await options.legacyRoutesFactory({
        root: dirname(runtime.db.name),
        runtime,
        serverOwner: options.owner,
        serverOrigin: options.origin,
        account,
        serverSigner: createServerSigner(account, config.gateway),
        gatewayConfig: config.gateway,
      });
      legacyRoutes = legacy.routes;
      closeLegacy = legacy.close;
    }
  }
  app.get(
    "/.well-known/oauth-authorization-server/pdpp/v1",
    pdppAsMetadataHandler(() => options.origin),
  );
  app.route(
    "/.well-known",
    pdppWellKnownRoutes({
      resource: options.origin,
      coreQueryBase: "/pdpp/v1",
      authorizationServers: [options.origin],
      selfExportSupported: false,
    }),
  );
  // All AS endpoints above remain local. This allowlist forwards GETs only,
  // preserving the actual bearer and query for B's normal grant enforcement.
  app.get("/pdpp/v1/*", async (c) => {
    const path = c.req.path;
    if (
      !/^\/pdpp\/v1\/(?:streams(?:\/[^/]+(?:\/records(?:\/[^/]+)?)?)?|blobs\/[^/]+)$/.test(
        path,
      )
    )
      return c.json({ error: "not_found" }, 404);
    if (!resourceOrigin) return c.json({ error: "replica_not_ready" }, 503);
    const headers = new Headers();
    for (const key of [
      "authorization",
      "pdpp-version",
      "accept",
      "range",
      "if-none-match",
    ]) {
      const value = c.req.header(key);
      if (value) headers.set(key, value);
    }
    try {
      const target = new URL(path + new URL(c.req.url).search, resourceOrigin);
      assert.equal(target.origin, resourceOrigin);
      const response = await fetch(target, {
        headers,
        redirect: "error",
        signal: AbortSignal.timeout(25000),
      });
      const returned = new Headers(response.headers);
      // Discovery must point at the stable public composition, never B's port.
      const challenge = returned.get("www-authenticate");
      if (challenge)
        returned.set(
          "www-authenticate",
          challenge.replaceAll(resourceOrigin, options.origin),
        );
      returned.set("cache-control", "no-store");
      returned.delete("set-cookie");
      return new Response(response.body, {
        status: response.status,
        headers: returned,
      });
    } catch {
      return c.json({ error: "replica_unavailable" }, 503);
    }
  });
  app.get("/composition/state", (c) =>
    c.json({
      phase,
      head,
      runtime_source_hashes: runtimeSourceHashes,
      owner: options.owner,
      issuer: options.origin,
      personal_server_origin: options.origin,
      account_origin: options.accountOrigin,
      client_id: options.clientId,
      redirect_uri: options.redirectUri,
      source_id: sourceId,
      mode: source ? "connector" : "fixture",
      instances: source
        ? (collector?.store
            .listConnections(sourceId)
            .filter((connection) => connection.deletedAt === null)
            .map((connection) => connection.instance) ?? [])
        : ["conn", "conn-other"],
      streams: declaration.streams,
      ...(source
        ? {
            declaration_sha256: declaration.digest,
            declaration_version: declaration.version,
            canonical_records: collector
              ? (
                  collector.db
                    .prepare(
                      "SELECT COUNT(*) AS n FROM pdpp_records WHERE deleted=0",
                    )
                    .get() as { n: number }
                ).n
              : 0,
            connection_id: collector ? source.connectionId : null,
            binding_generation:
              collector?.store.getInstanceBinding(source.connectionId)
                .generation ?? null,
            ingestion: {
              ready: Boolean(collectorRoutes),
              method: source.methodId,
              binding_generation:
                collector?.store.getInstanceBinding(source.connectionId)
                  .generation ?? null,
              connection_id: collector ? source.connectionId : null,
              envelope: {
                instance: "registered connection_id",
                key: "connector key unchanged",
                data: "connector data unchanged",
                emitted_at: "connector timestamp unchanged",
                op: "optional connector operation unchanged",
              },
              streams: declaration.streams.map((stream) => ({
                name: stream.name,
                fields: stream.fields,
                schema: stream.schema,
                url: collector
                  ? `${options.origin}/pdpp/v1/streams/${encodeURIComponent(stream.name)}/records/ingest?${new URLSearchParams({ method: source.methodId, binding_generation: String(collector.store.getInstanceBinding(source.connectionId).generation) })}`
                  : null,
              })),
            },
            referenced_blobs: connectorConfirmed?.referenced_blobs ?? 0,
            legacy: {
              ready: Boolean(legacyRoutes),
              grant_endpoint: `${options.origin}/v1/grants`,
              data_endpoint: `${options.origin}/v1/data`,
              ...(options.granteeAddress && {
                grantee_address: options.granteeAddress,
              }),
            },
          }
        : {
            window: {
              since: "2026-10-01T00:00:00Z",
              until: "2026-11-01T00:00:00Z",
            },
          }),
      owner_proof_received: credential !== undefined,
      signing_requests: requests.filter(
        (r) => statuses.get(r.request_id) === "pending",
      ),
      servers: typedRequests.map((r, index) => ({
        device: index === 0 ? "A" : "B",
        address: r.message.serverAddress,
      })),
      ...(failure && { failure }),
      cycle_retries: cycleRetries,
      ...(connectorConfirmed
        ? { confirmed: connectorConfirmed }
        : confirmed
          ? { confirmed }
          : {}),
    }),
  );
  async function run() {
    if (started) throw new Error("Composition already started");
    started = true;
    while (!closed && (!credential || signatures.size !== 3)) await pause(250);
    if (closed || !credential) return;
    try {
      phase = "registering";
      const rpc = createPublicClient({
        transport: http(rpcUrl, { timeout: 25000, retryCount: 0 }),
      });
      assert.equal(await rpc.getChainId(), 14800);
      for (const origin of [gatewayUrl, storageUrl]) {
        const response = await fetch(`${origin}/health`);
        await response.body?.cancel();
        assert(response.ok, "Dev health preflight failed");
      }
      const master = [
        ...deriveMasterKey(signatures.get(requests[0].request_id)!),
      ];
      for (let index = 0; index < typedRequests.length; index++) {
        if (closed) return;
        const response = await fetch(`${gatewayUrl}/v1/servers`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            authorization: `Web3Signed ${signatures.get(requests[index + 1].request_id)!}`,
          },
          body: JSON.stringify(typedRequests[index].message),
        });
        await response.body?.cancel();
        assert(
          response.ok,
          `Dev server registration refused: HTTP ${response.status}`,
        );
      }
      signatures.clear();
      phase = "starting_replicas";
      const scriptSha256 = digest(
        readFileSync(
          fileURLToPath(
            new URL("./pdpp-replica-live-journey.ts", import.meta.url),
          ),
        ),
      );
      if (source && options.source) {
        const dataRoot = mkdtempSync(join(options.root, "connector-run-"));
        const a = await openReplicaRuntime({
          root: join(dataRoot, "A"),
          owner: options.owner,
          master,
          serverKey: serverKeys[0],
          scriptSha256,
          source: options.source,
        });
        await attachCollector(a, serverAccount(serverKeys[0]));
        const b = new Device({
          root: join(dataRoot, "B"),
          owner: options.owner,
          master,
          serverKey: serverKeys[1],
          scriptSha256,
          source: options.source,
          consent: { issuerOrigin: options.origin, credential },
        });
        devices.push(b);
        await b.start();
        let internalOrigin = await b.call<string>("resourceOrigin");
        disallowResource = allowHarnessLoopback(internalOrigin);
        resourceOrigin = internalOrigin;
        phase = "awaiting_records";
        while (!closed) {
          if (credential && b.init.consent?.credential !== credential) {
            resourceOrigin = undefined;
            disallowResource?.();
            await b.kill();
            b.init.consent = { issuerOrigin: options.origin, credential };
            await b.start();
            internalOrigin = await b.call<string>("resourceOrigin");
            disallowResource = allowHarnessLoopback(internalOrigin);
            resourceOrigin = internalOrigin;
          }
          const results = await Promise.allSettled([
            a.call("cycle"),
            b.call("cycle"),
          ]);
          for (const result of results)
            if (result.status === "rejected") cycleRetries++;
          const left = a.snapshot();
          const right = await b.call("snapshot");
          const readiness = evaluateConnectorReadiness({
            a: left,
            b: right,
            aCanonical: canonicalRows(join(dataRoot, "A/records.sqlite")),
            sourceId,
            oracle: () =>
              assertCanonicalEquality(
                join(dataRoot, "A/records.sqlite"),
                join(dataRoot, "B/records.sqlite"),
              ),
          });
          if (readiness.ready) {
            connectorConfirmed = readiness.receipt;
            phase = "ready";
          } else {
            connectorConfirmed = undefined;
            phase =
              readiness.reason === "no_rows"
                ? "awaiting_records"
                : "replicating";
          }
          await pause(2000);
        }
        return;
      }
      for (let index = 0; index < 2; index++) {
        const device = new Device({
          root: join(options.root, index === 0 ? "A" : "B"),
          owner: options.owner,
          master,
          serverKey: serverKeys[index],
          scriptSha256,
          consent: { issuerOrigin: options.origin, credential },
        });
        devices.push(device);
        await device.start();
        if (closed) return;
      }
      const [a, b] = devices;
      const internalOrigin = await b.call<string>("resourceOrigin");
      disallowResource = allowHarnessLoopback(internalOrigin);
      resourceOrigin = internalOrigin;
      const data = {
        text: "before replicated edit",
        collected_at: "2026-10-15T12:00:00Z",
        private_note: "must stay hidden",
      };
      const blob = await a.call<{
        blobId: string;
        sha256: string;
        bytes: number;
      }>("blob", { id: "visible", size: 32768, data });
      await a.call("put", {
        id: "outside",
        data: { ...data, collected_at: "2026-09-30T23:59:59Z" },
      });
      await a.call("put", {
        id: "until-boundary",
        data: { ...data, collected_at: "2026-11-01T00:00:00Z" },
      });
      await a.call("put", { id: "other-only", instance: "conn-other", data });
      phase = "replicating";
      const startedAt = Date.now();
      while (!closed) {
        // The production owner proof lasts 15 minutes. A later genuine proof
        // refreshes B's host credential by restarting the same durable worker;
        // it creates no grant, token, or alternate introspection authority.
        if (credential && b.init.consent?.credential !== credential) {
          resourceOrigin = undefined;
          disallowResource?.();
          await b.kill();
          b.init.consent = { issuerOrigin: options.origin, credential };
          await b.start();
          const nextOrigin = await b.call<string>("resourceOrigin");
          disallowResource = allowHarnessLoopback(nextOrigin);
          resourceOrigin = nextOrigin;
        }
        const cycles = await Promise.allSettled(
          devices.map((device) => device.call("cycle")),
        );
        for (const result of cycles)
          if (result.status === "rejected") cycleRetries++;
        if (!confirmed) {
          const [left, right] = await Promise.all(
            devices.map((device) => device.call("snapshot")),
          );
          const visible = right.appRows.find(
            (row) => row.recordKey === "visible",
          );
          if (
            left.pending === 0 &&
            visible &&
            visible.confirmation === undefined &&
            right.blobs[blob.blobId]?.sha256 === blob.sha256 &&
            ["visible", "outside", "until-boundary", "other-only"].every(
              (id) => id in right.records,
            )
          ) {
            const oracle = assertCanonicalEquality(
              join(options.root, "A/records.sqlite"),
              join(options.root, "B/records.sqlite"),
            );
            assert.deepEqual(left.records, right.records);
            assert.deepEqual(left.blobs, right.blobs);
            assert(
              right.evidence.some((entry) => entry.chain?.status === "Active"),
              "No confirmed chain evidence",
            );
            confirmed = {
              record_id: "visible",
              record_sha256: digest(JSON.stringify(right.records.visible)),
              canonical_sha256: oracle.B,
              blob_id: blob.blobId,
              blob_sha256: blob.sha256,
              blob_bytes: blob.bytes,
            };
            phase = "ready";
            failure = undefined;
          } else if (Date.now() - startedAt > 12 * 60000) {
            failure = "confirmation_deadline_exceeded";
            phase = "replicating";
          }
        }
        await pause(2000);
      }
    } catch {
      // Errors from SDK/network/worker code may contain authorization material.
      // Publish only the known stage; never stringify the underlying exception.
      failure = `${phase}_failed`;
      phase = "failed";
    }
  }
  return {
    app,
    run,
    attachCollector,
    close: async () => {
      closed = true;
      resourceOrigin = undefined;
      for (const device of devices) await device.kill();
      await closeLegacy?.();
      await collector?.close();
      disallowResource?.();
      signatures.clear();
      credential = undefined;
      store.close();
    },
  };
}

async function main() {
  const { values } = parseArgs({
    options: {
      owner: { type: "string" },
      port: { type: "string" },
      "account-origin": { type: "string" },
      "client-id": { type: "string" },
      "redirect-uri": { type: "string" },
      root: { type: "string" },
      "declaration-path": { type: "string" },
      "declaration-sha256": { type: "string" },
      "method-id": { type: "string" },
      "connection-id": { type: "string" },
      "grantee-address": { type: "string" },
    },
    strict: true,
  });
  assert(
    values.owner &&
      values.port &&
      values["account-origin"] &&
      values["client-id"] &&
      values["redirect-uri"],
    "Required: --owner --port --account-origin --client-id --redirect-uri",
  );
  const port = Number(values.port);
  assert(
    Number.isInteger(port) && port > 1024 && port <= 65535,
    "Explicit unprivileged port required",
  );
  const origin = `http://127.0.0.1:${port}`;
  installHarnessSafety();
  const disallowIssuer = allowHarnessLoopback(origin);
  const parent = join(homedir(), ".tmp");
  mkdirSync(parent, { recursive: true });
  const realFlags = [
    values["declaration-path"],
    values["declaration-sha256"],
    values["method-id"],
    values["connection-id"],
  ];
  if (realFlags.some(Boolean))
    assert(
      values.root && realFlags.every(Boolean),
      "Real-source mode requires --root --declaration-path --declaration-sha256 --method-id --connection-id",
    );
  const source = realFlags.some(Boolean)
    ? loadCompositionSource({
        declarationPath: values["declaration-path"]!,
        declarationSha256: values["declaration-sha256"]!,
        methodId: values["method-id"]!,
        connectionId: values["connection-id"]!,
      })
    : undefined;
  const root =
    values.root ?? mkdtempSync(join(parent, "replica-owner-composition-"));
  if (values.root)
    assert(
      existsSync(join(root, "auth.sqlite")) &&
        statSync(join(root, "auth.sqlite")).isFile(),
      "--root requires an existing auth.sqlite",
    );
  const host = await createOwnerComposition({
    root,
    owner: getAddress(values.owner),
    origin,
    accountOrigin: values["account-origin"],
    clientId: values["client-id"],
    redirectUri: values["redirect-uri"],
    source,
    ...(values["grantee-address"] && {
      granteeAddress: getAddress(values["grantee-address"]),
      legacyRoutesFactory: (ports: CompositionLegacyPorts) => {
        const storage = openReplicaOwnerLegacyStorage({ root: ports.root });
        try {
          const routes = createReplicaOwnerLegacyRoutes({
            ...storage,
            logger: pino({ level: "silent" }),
            serverOrigin: ports.serverOrigin,
            serverOwner: ports.serverOwner,
            serverSigner: ports.serverSigner,
            gatewayConfig: ports.gatewayConfig,
            gateway: createGatewayClient(gatewayUrl),
            gatewayUrl,
            accessLogWriter: createAccessLogWriter(join(ports.root, "logs")),
            granteeAddress: getAddress(values["grantee-address"]!),
          });
          return { routes, close: () => storage.close() };
        } catch (error) {
          storage.close();
          throw error;
        }
      },
    }),
  });
  const listener = serve({
    hostname: "127.0.0.1",
    port,
    fetch: (request) => {
      if (new URL(request.url).origin !== origin)
        return new Response(null, { status: 421 });
      return host.app.fetch(request);
    },
  });
  await new Promise<void>((resolve, reject) => {
    listener.once("listening", resolve);
    listener.once("error", reject);
  });
  console.log(
    JSON.stringify({
      origin,
      owner: getAddress(values.owner),
      client_id: values["client-id"],
      redirect_uri: values["redirect-uri"],
      state: `${origin}/composition/state`,
    }),
  );
  const running = host.run();
  let stopping = false;
  const stop = async () => {
    if (stopping) return;
    stopping = true;
    listener.close();
    if ("closeAllConnections" in listener) listener.closeAllConnections();
    await host.close();
    await running;
    disallowIssuer();
  };
  process.once("SIGINT", () => void stop());
  process.once("SIGTERM", () => void stop());
}
if (
  process.argv[1] &&
  pathToFileURL(process.argv[1]).href === import.meta.url
) {
  void main().catch(() => {
    console.error(
      "Composition startup failed; check explicit local configuration and port",
    );
    process.exitCode = 1;
  });
}
