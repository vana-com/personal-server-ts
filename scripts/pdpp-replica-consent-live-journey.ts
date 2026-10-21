/** Dev-only single-issuer consent over the real 8a replica workers. No env/config files. */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import Database from "better-sqlite3";
import { serve } from "@hono/node-server";
import { Hono } from "hono";
import pino from "pino";
import { createPublicClient, http } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import {
  deriveMasterKey,
  MASTER_KEY_MESSAGE,
  serverRegistrationDomain,
  SERVER_REGISTRATION_TYPES,
} from "@opendatalabs/vana-sdk/node";
import {
  AuthorizationSessionStore,
  computeS256Challenge,
  openPdppAuthStore,
  PDPP_DATA_ACCESS_TYPE_V02,
  PdppTokenService,
  type DeclarationSnapshot,
  type Grant,
} from "@opendatalabs/personal-server-ts-core/pdpp";
import {
  createStreamDeclarationRegistry,
  type PdppReplicaReads,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { pdppAuthRoutes } from "../packages/server/src/routes/pdpp-auth.js";
import { pdppRecordsRoutes } from "../packages/server/src/routes/pdpp-records.js";
import { pdppWellKnownRoutes } from "../packages/server/src/routes/pdpp-well-known.js";
import { pdppBlobsRoutes } from "../packages/server/src/routes/pdpp-blobs.js";
import { createReplicaAuthorizationService } from "../packages/server/src/pdpp/replica-authorization.js";
import type { createSqliteRecordStore } from "../packages/server/src/storage/pdpp-records-sqlite-store.js";
import {
  buildReplicaRuntimeSource,
  type ReplicaRuntimeSource,
} from "./pdpp-replica-runtime-source.js";
import {
  allowHarnessLoopback,
  config,
  Device,
  digest,
  gatewayUrl,
  installHarnessSafety,
  pause,
  rpcUrl,
  serverAccount,
  sourceId,
  storageUrl,
  type Snapshot,
} from "./pdpp-replica-live-journey.js";

const logger = pino({ level: "silent" });
const clientId = "replica-consent-acceptance";
const expiryClientId = `${clientId}-expiry`;
const redirect = "https://replica-app.invalid/callback";
const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
export const window = {
  since: "2026-10-01T00:00:00Z",
  until: "2026-11-01T00:00:00Z",
};
const fields = ["text", "collected_at", "blob_ref"];
const snapshot: DeclarationSnapshot = {
  source_id: sourceId,
  source_kind: "connector",
  version: "1",
  digest: "a".repeat(64),
  streams: [
    {
      name: "messages",
      fields: ["id", ...fields, "private_note"],
      required_fields: ["id", "private_note"],
      primary_key: ["id"],
      consent_time_field: "collected_at",
    },
  ],
};

/** Binds only a fresh OS-assigned loopback port; closes its network permission with the listener. */
async function listen(app: Hono) {
  const server = serve({ fetch: app.fetch, hostname: "127.0.0.1", port: 0 });
  await new Promise<void>((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  });
  const address = server.address();
  assert(address && typeof address === "object");
  const origin = `http://127.0.0.1:${address.port}`;
  const disallow = allowHarnessLoopback(origin);
  return {
    origin,
    close: async () => {
      if ("closeIdleConnections" in server) server.closeIdleConnections();
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
      disallow();
    },
  };
}

/** One durable AS on A. Owner tokens are provisioned only for this random fixture owner. */
export async function openConsentIssuer(
  root: string,
  owner: string,
  ttlSeconds = 12,
) {
  const store = openPdppAuthStore(join(root, "auth.sqlite"));
  const tokens = new PdppTokenService(store, {
    accessTokenTtlSeconds: 600,
  });
  const ownerToken = (subjectId = owner) =>
    tokens.issueOwnerToken({ subjectId, sourceId, ttlSeconds: 3600 })
      .access_token;
  const credential = ownerToken();
  const foreignCredential = ownerToken(`foreign-${owner}`);
  const app = new Hono();
  app.route(
    "/pdpp/v1",
    pdppAuthRoutes({
      logger,
      store,
      tokens,
      sessions: new AuthorizationSessionStore(),
      resolveDeclaration: (id) => (id === sourceId ? snapshot : null),
      inventoryFor: () => ({ eligibleFor: () => ["conn", "conn-other"] }),
      currentSubjectId: (c) => {
        const context = tokens.resolveToken(
          c.req.header("authorization")?.replace(/^Bearer /, "") ?? "",
        );
        return context.active && context.tokenKind === "owner"
          ? (context.subjectId ?? null)
          : null;
      },
      registeredClient: (id) =>
        [clientId, expiryClientId].includes(id)
          ? { client_id: id, redirect_uris: [redirect] }
          : null,
      // Harness-only AS policy: one client exercises real short expiry in the same issuer/store.
      grantExpiryFor: (_request, id) =>
        id === expiryClientId
          ? new Date(Date.now() + ttlSeconds * 1000).toISOString()
          : undefined,
    }),
  );
  const httpServer = await listen(app);
  return {
    ...httpServer,
    credential,
    foreignCredential,
    close: async () => {
      await httpServer.close();
      store.close();
    },
  };
}
export type ConsentIssuer = Awaited<ReturnType<typeof openConsentIssuer>>;

/** Real RS routes over B's canonical SQLite store; no local grant/token database. */
export async function openReplicaResourceServer(
  store: ReturnType<typeof createSqliteRecordStore>,
  options: {
    owner: string;
    issuerOrigin: string;
    credential: string;
    source?: ReplicaRuntimeSource;
    fetch?: typeof fetch;
    /**
     * The host reader capability (`AppDeps.pdpp.reads`). A host with a
     * receiver passes `receiver.readStore`; one without passes the store.
     */
    reads: PdppReplicaReads;
  },
) {
  const runtimeSource = options.source
    ? buildReplicaRuntimeSource(options.source)
    : undefined;
  const resourceSourceId = runtimeSource?.sourceId ?? sourceId;
  const auth = createReplicaAuthorizationService({
    ...options,
    credential: async () => options.credential,
    connections: () =>
      store
        .listConnections(resourceSourceId)
        .filter(
          (c) =>
            c.deletedAt === null &&
            (!runtimeSource || c.instance === runtimeSource.connectionId),
        )
        .map((c) => ({
          owner: options.owner,
          sourceId: resourceSourceId,
          connectionId: c.instance,
          issuerInstanceId: c.instance,
          localInstanceId: c.instance,
        })),
  });
  const declarations =
    runtimeSource?.declarations ??
    createStreamDeclarationRegistry([
      {
        name: "messages",
        semantics: "mutable_state",
        primaryKey: ["id"],
        cursorField: "collected_at",
        consentTimeField: "collected_at",
        requiredFields: ["id", "private_note"],
        declaredFields: snapshot.streams[0].fields,
      },
    ]);
  const app = new Hono();
  app.route(
    "/pdpp/v1",
    pdppRecordsRoutes({
      logger,
      store,
      bindingStore: store,
      auth,
      declarations,
      ownerSubjectId: options.owner,
      reads: options.reads,
    }),
  );
  app.route(
    "/pdpp/v1/blobs",
    pdppBlobsRoutes({
      store,
      auth,
      declarations,
      reads: options.reads,
      readBlobBytes: async (id) => {
        const bytes = store.getBlobBytes(id);
        return bytes ? new Uint8Array(bytes) : undefined;
      },
    }),
  );
  const server = await listen(app);
  app.route(
    "/.well-known",
    pdppWellKnownRoutes({
      resource: server.origin,
      coreQueryBase: "/pdpp/v1",
      authorizationServers: [options.issuerOrigin],
      selfExportSupported: false,
    }),
  );
  return server;
}

async function json(response: Response, status: number, label: string) {
  // Never include raw HTTP bodies in errors: a token response can contain credentials.
  const value = (await response.json()) as Record<string, unknown>;
  assert.equal(
    response.status,
    status,
    `${label}: HTTP ${response.status}, error=${typeof value.error === "string" ? value.error : "none"}`,
  );
  return value;
}
function api(origin: string, path: string, token?: string, body?: unknown) {
  return globalThis.fetch(origin + "/pdpp/v1" + path, {
    method: body === undefined ? "GET" : "POST",
    headers: {
      ...(token && { authorization: `Bearer ${token}` }),
      ...(body !== undefined && { "content-type": "application/json" }),
    },
    ...(body !== undefined && { body: JSON.stringify(body) }),
  });
}
function form(
  origin: string,
  path: string,
  body: Record<string, string>,
  token?: string,
) {
  return globalThis.fetch(origin + "/pdpp/v1" + path, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      ...(token && { authorization: `Bearer ${token}` }),
    },
    body: new URLSearchParams(body),
  });
}

/** Same authorize/review/approve wire contract used by Account, with no UI claim. */
export async function approveNarrowConsent(
  issuer: ConsentIssuer,
  ownerCredential = issuer.credential,
  options: { expiring?: boolean } = {},
) {
  const selectedClient = options.expiring ? expiryClientId : clientId;
  const created = await json(
    await api(issuer.origin, "/authorize", ownerCredential, {
      client_id: selectedClient,
      redirect_uri: redirect,
      state: "replica-8b",
      code_challenge: computeS256Challenge(verifier),
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
              fields: snapshot.streams[0].fields,
              time_range: {
                since: "2026-01-01T00:00:00Z",
                until: "2027-01-01T00:00:00Z",
              },
              minimum: { fields: ["text"], time_range: window },
            },
          ],
        },
      ],
    }),
    201,
    "authorize",
  );
  const base = `/authorize/${created.session_id}`;
  const picks = new URLSearchParams({ "instance[messages]": "conn" });
  const original = await json(
    await api(issuer.origin, `${base}/review?${picks}`, ownerCredential),
    200,
    "initial review",
  );
  const choices = {
    fields: { messages: fields },
    time_ranges: { messages: window },
  };
  const instanceChoices = { messages: ["conn"] };
  const stale = await json(
    await api(issuer.origin, `${base}/approve`, ownerCredential, {
      review_digest: (original.review as { review_digest: string })
        .review_digest,
      instance_choices: instanceChoices,
      owner_choices: choices,
    }),
    409,
    "stale digest",
  );
  assert.equal(stale.error, "stale_review");
  for (const field of fields) picks.append("field[messages]", field);
  picks.append("since[messages]", window.since);
  picks.append("until[messages]", window.until);
  const narrowed = await json(
    await api(issuer.origin, `${base}/review?${picks}`, ownerCredential),
    200,
    "narrowed review",
  );
  const reviewDigest = (narrowed.review as { review_digest: string })
    .review_digest;
  const approvalBody = {
    review_digest: reviewDigest,
    instance_choices: instanceChoices,
    owner_choices: choices,
  };
  const approved = await json(
    await api(issuer.origin, `${base}/approve`, ownerCredential, approvalBody),
    200,
    "approve exact digest",
  );
  const returned = new URL(String(approved.redirect_uri));
  assert.equal(returned.origin + returned.pathname, redirect);
  assert.equal(returned.searchParams.get("state"), "replica-8b");
  const code = returned.searchParams.get("code");
  assert(code);
  const redeem = () =>
    form(issuer.origin, "/token", {
      grant_type: "authorization_code",
      code,
      client_id: selectedClient,
      redirect_uri: redirect,
      code_verifier: verifier,
    });
  const issued = await json(await redeem(), 200, "redeem");
  const entry = (
    issued.authorization_details as { type: string; grant: Grant }[]
  )[0];
  assert.equal(entry.type, PDPP_DATA_ACCESS_TYPE_V02);
  assert.equal(entry.grant.version, "0.2.0");
  assert.deepEqual(entry.grant.streams, [
    {
      name: "messages",
      instance_ids: ["conn"],
      fields,
      time_constraint: { field: "collected_at", ...window },
    },
  ]);
  assert.deepEqual(entry.grant.retention, {
    max_duration: "P1D",
    on_expiry: "delete",
  });
  const replayCode = async () => {
    const denied = await json(await redeem(), 400, "code replay");
    assert.equal(denied.error, "invalid_grant");
  };
  const replayApproval = async () => {
    const response = await api(
      issuer.origin,
      `${base}/approve`,
      ownerCredential,
      approvalBody,
    );
    assert.equal(response.status, 400, "old approval replay denied");
    await response.body?.cancel();
  };
  await replayCode();
  await replayApproval();
  return {
    token: String(issued.access_token),
    grantId: String(issued.grant_id),
    ttlSeconds: Number(issued.expires_in),
    reviewDigest,
    replayCode,
    replayApproval,
  };
}
export type ApprovedConsent = Awaited<ReturnType<typeof approveNarrowConsent>>;

export async function assertAppRead(
  origin: string,
  token: string,
  expected: { text: string; collected_at: string; blob_ref: unknown },
  blob: { blobId: string; sha256: string; bytes: number },
) {
  const record = await json(
    await api(origin, "/streams/messages/records/visible", token),
    200,
    "app record",
  );
  assert.equal(record.object, "record");
  assert.equal(record.id, "visible");
  assert.equal(record.stream, "messages");
  assert.deepEqual(
    record.data,
    expected,
    "exact authorized projection; schema-required hidden fields must stay absent",
  );
  const list = await json(
    await api(origin, "/streams/messages/records", token),
    200,
    "app record list",
  );
  const records = list.data as { id: string; data: unknown }[];
  assert.deepEqual(
    records.map((r) => r.id),
    ["visible"],
    "time window and connection scope",
  );
  assert.deepEqual(records[0].data, expected);
  for (const id of ["other-only", "outside", "until-boundary"])
    await json(
      await api(origin, `/streams/messages/records/${id}`, token),
      404,
      `excluded record ${id}`,
    );
  await json(
    await api(
      origin,
      "/streams/messages/records/visible?fields=private_note",
      token,
    ),
    400,
    "hidden field request",
  );
  const response = await api(
    origin,
    `/blobs/${encodeURIComponent(blob.blobId)}`,
    token,
  );
  assert.equal(response.status, 200, "authorized blob");
  const bytes = new Uint8Array(await response.arrayBuffer());
  assert.equal(bytes.length, blob.bytes);
  assert.equal(digest(bytes), blob.sha256);
}
export async function assertIssuerInactive(
  issuer: ConsentIssuer,
  token: string,
) {
  const health = await json(
    await form(
      issuer.origin,
      "/introspect",
      { token: issuer.credential },
      issuer.credential,
    ),
    200,
    "issuer credential health",
  );
  assert.equal(
    health.active,
    true,
    "issuer authenticated credential remains active",
  );
  assert.equal(health.pdpp_token_kind, "owner");
  const inactive = await json(
    await form(issuer.origin, "/introspect", { token }, issuer.credential),
    200,
    "issuer inactive decision",
  );
  assert.equal(
    inactive.active,
    false,
    "issuer explicitly rejects this app token",
  );
  return {
    checkedAt: new Date().toISOString(),
    issuerCredentialActive: true,
    introspectionActive: false,
  };
}
export async function assertTokenDenied(
  origin: string,
  token: string,
  blobId: string,
  issuer: ConsentIssuer,
) {
  const authority = await assertIssuerInactive(issuer, token);
  for (const path of [
    "/streams/messages/records",
    "/streams/messages/records/visible",
    `/blobs/${encodeURIComponent(blobId)}`,
  ])
    await json(
      await api(origin, path, token),
      401,
      "issuer-inactive token read",
    );
  return authority;
}
export async function revokeConsent(
  issuer: ConsentIssuer,
  consent: ApprovedConsent,
) {
  const response = await form(
    issuer.origin,
    "/revoke",
    { grant_id: consent.grantId },
    issuer.credential,
  );
  assert.equal(response.status, 200, "revoke at issuer");
  await response.body?.cancel();
}

/** Independent read-only SQL oracle: local write/history counters are intentionally absent. */
function stableJson(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stableJson);
  if (value !== null && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value)
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([key, member]) => [key, stableJson(member)]),
    );
  return value;
}
export function canonicalRows(path: string) {
  const db = new Database(path, { readonly: true, fileMustExist: true });
  try {
    return (
      db
        .prepare(
          "SELECT instance,stream,record_key,data,emitted_at,deleted,blob_id FROM pdpp_records ORDER BY instance,stream,record_key",
        )
        .all() as { data: string }[]
    ).map((r) => ({ ...r, data: stableJson(JSON.parse(r.data)) }));
  } finally {
    db.close();
  }
}
export function assertCanonicalEquality(aPath: string, bPath: string) {
  const a = canonicalRows(aPath),
    b = canonicalRows(bPath);
  assert.deepEqual(b, a, "independent canonical SQL equality");
  assert(a.length > 0, "nonempty canonical oracle");
  const aSha256 = digest(JSON.stringify(a)),
    bSha256 = digest(JSON.stringify(b));
  assert.equal(aSha256, bSha256);
  return {
    fields: [
      "instance",
      "stream",
      "record_key",
      "data",
      "emitted_at",
      "deleted",
      "blob_id",
    ],
    rows: a,
    A: aSha256,
    B: bSha256,
  };
}

async function main() {
  installHarnessSafety();
  const parent = join(homedir(), ".tmp");
  mkdirSync(parent, { recursive: true });
  const root = mkdtempSync(join(parent, "replica-consent-"));
  const reportPath =
    process.argv[2] ?? join(parent, `replica-consent-${Date.now()}.json`);
  const ownerAccount = privateKeyToAccount(generatePrivateKey());
  const owner = ownerAccount.address;
  const master = [
    ...deriveMasterKey(
      await ownerAccount.signMessage({ message: MASTER_KEY_MESSAGE }),
    ),
  ];
  const issuerRoot = join(root, "A");
  mkdirSync(issuerRoot, { recursive: true, mode: 0o700 });
  const issuer = await openConsentIssuer(issuerRoot, owner);
  const run = randomUUID();
  const devices = ["A", "B"].map(
    (name) =>
      new Device({
        root: join(root, name),
        owner,
        master,
        serverKey: generatePrivateKey(),
        scriptSha256: digest(
          readFileSync(
            fileURLToPath(
              new URL("./pdpp-replica-live-journey.ts", import.meta.url),
            ),
          ),
        ),
        ...(name === "B" && {
          consent: {
            issuerOrigin: issuer.origin,
            credential: issuer.credential,
          },
        }),
      }),
  );
  const [a, b] = devices;
  const sourcePaths = [
    "scripts/pdpp-replica-live-journey.ts",
    "scripts/pdpp-replica-consent-live-journey.ts",
    "packages/core/src/ports/pdpp-auth.ts",
    "packages/core/dist/ports/pdpp-auth.js",
    "packages/server/src/pdpp/replica-authorization.ts",
    "packages/server/src/routes/pdpp-auth.ts",
    "packages/server/src/routes/pdpp-records.ts",
    "packages/server/src/routes/pdpp-blobs.ts",
    "packages/server/src/storage/pdpp-records-sqlite-store.ts",
    "packages/server/src/storage/pdpp-replication-receiver.ts",
    "packages/server/src/storage/pdpp-replication-transport.ts",
  ];
  const sourceHashes = () =>
    Object.fromEntries(
      sourcePaths.map((path) => [path, digest(readFileSync(path))]),
    );
  const initialSourceHashes = sourceHashes();
  const report: Record<string, unknown> = {
    run,
    owner,
    status: "running",
    node: process.version,
    head: execFileSync("git", ["rev-parse", "HEAD"], {
      encoding: "utf8",
    }).trim(),
    harnessSha256: digest(readFileSync(fileURLToPath(import.meta.url))),
    hostSha256: a.init.scriptSha256,
    adapterSha256: digest(
      readFileSync("packages/server/src/pdpp/replica-authorization.ts"),
    ),
    dirtyTree: execFileSync(
      "git",
      ["status", "--porcelain", "--", "packages", "scripts"],
      { encoding: "utf8" },
    ).trim(),
    sourceHashes: initialSourceHashes,
    startedAt: new Date().toISOString(),
    gatewayUrl,
    storageUrl,
    rpcUrl,
    chainId: 14800,
    authority: "single issuer A; no authorization state replicated",
    ui: "unverified; Account dev route unavailable, API fallback authorized",
    retryableCycleErrors: {} as Record<string, number>,
    cases: [],
  };
  const cases = report.cases as unknown[];
  const save = () =>
    writeFileSync(reportPath, JSON.stringify(report, null, 2) + "\n", {
      mode: 0o600,
    });
  async function settle(
    label: string,
    predicate: (s: Snapshot) => boolean,
    inspect?: (s: Snapshot) => Promise<void>,
  ) {
    const start = Date.now();
    while (Date.now() - start < 12 * 60_000) {
      for (const [index, device] of devices.entries()) {
        try {
          await device.call("cycle");
        } catch (error) {
          if (!device.child.connected) throw error;
          // Match 8a: a cycle aggregates transient phase failures while durable retry work remains.
          const kind =
            error instanceof Error &&
            error.message === "Replica transport cycle incomplete"
              ? error.message
              : "cycle failure";
          const causes =
            error instanceof Error && Array.isArray(error.cause)
              ? error.cause
              : [];
          const key = JSON.stringify({
            stage: label,
            device: index === 0 ? "A" : "B",
            kind,
            causes,
          });
          const counts = report.retryableCycleErrors as Record<string, number>;
          counts[key] = (counts[key] ?? 0) + 1;
          console.log(
            JSON.stringify({
              retryableCycleError: JSON.parse(key),
              count: counts[key],
            }),
          );
          save();
        }
      }
      const receiving = await b.call("snapshot");
      console.log(
        JSON.stringify({
          stage: label,
          elapsedMs: Date.now() - start,
          imported: receiving.importedFragments,
          errors: receiving.inboxErrors,
        }),
      );
      await inspect?.(receiving);
      if (predicate(receiving))
        return { elapsedMs: Date.now() - start, snapshot: receiving };
      await pause(5000);
    }
    throw new Error(`Timed out: ${label}`);
  }
  async function resourceOrigin() {
    return b.call<string>("resourceOrigin");
  }
  async function restartB() {
    const previousPid = b.child.pid;
    await b.kill();
    await b.start();
    const origin = await resourceOrigin();
    allowHarnessLoopback(origin);
    assert.notEqual(b.child.pid, previousPid);
    return { previousPid, pid: b.child.pid, origin };
  }
  try {
    const rpc = createPublicClient({
      transport: http(rpcUrl, { timeout: 25_000, retryCount: 0 }),
    });
    assert.equal(await rpc.getChainId(), 14800);
    for (const url of [gatewayUrl, storageUrl]) {
      const response = await globalThis.fetch(`${url}/health`);
      assert(response.ok);
      await response.body?.cancel();
    }
    for (const [i, device] of devices.entries()) {
      const account = serverAccount(device.init.serverKey);
      const message = {
        ownerAddress: owner,
        serverAddress: account.address,
        publicKey: account.publicKey,
        serverUrl: `https://replica-consent-${i}-${run}.invalid`,
      };
      const signature = await ownerAccount.signTypedData({
        domain: serverRegistrationDomain(config.gateway),
        types: SERVER_REGISTRATION_TYPES,
        primaryType: "ServerRegistration",
        message,
      });
      const response = await globalThis.fetch(`${gatewayUrl}/v1/servers`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Web3Signed ${signature}`,
        },
        body: JSON.stringify(message),
      });
      assert(response.ok, `dev registration ${response.status}`);
      await response.body?.cancel();
    }
    // Provision both handles on A too, without starting another AS or copying auth state.
    a.init.consent = {
      issuerOrigin: issuer.origin,
      credential: issuer.credential,
    };
    await a.start();
    await b.start();
    let origin = await resourceOrigin();
    allowHarnessLoopback(origin);
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
    const blobRef = {
      blob_id: blob.blobId,
      mime_type: "application/octet-stream",
      size_bytes: blob.bytes,
    };
    const expected = {
      text: data.text,
      collected_at: data.collected_at,
      blob_ref: blobRef,
    };
    await a.call("put", {
      id: "outside",
      data: { ...data, collected_at: "2026-09-30T23:59:59Z" },
    });
    await a.call("put", {
      id: "until-boundary",
      data: { ...data, collected_at: window.until },
    });
    await a.call("put", { id: "other-only", instance: "conn-other", data });
    const pendingLabels = new Set<string>();
    async function inspectPending(
      label: string,
      snapshot: Snapshot,
      consent: ApprovedConsent,
      pendingText: string,
      current: typeof expected | undefined,
    ) {
      const row = snapshot.ownerRows.find(
        (candidate) => candidate.recordKey === "visible",
      );
      if (
        row?.confirmation !== "not yet confirmed" ||
        row.data.text !== pendingText ||
        pendingLabels.has(label)
      )
        return;
      const appRow = snapshot.appRows.find(
        (candidate) => candidate.recordKey === "visible",
      );
      assert.equal(
        appRow?.data.text,
        current?.text,
        "shared grant read port excludes the pending edit",
      );
      const active = await json(
        await form(
          issuer.origin,
          "/introspect",
          { token: consent.token },
          issuer.credential,
        ),
        200,
        "pending-phase issuer decision",
      );
      assert.equal(active.active, true);
      assert.equal(active.grant_id, consent.grantId);
      const appControl = async () => {
        if (current) await assertAppRead(origin, consent.token, current, blob);
        else {
          await json(
            await api(
              origin,
              "/streams/messages/records/visible",
              consent.token,
            ),
            404,
            "pending record withheld",
          );
          const list = await json(
            await api(origin, "/streams/messages/records", consent.token),
            200,
            "pending list",
          );
          assert.deepEqual(list.data, []);
          await json(
            await api(
              origin,
              `/blobs/${encodeURIComponent(blob.blobId)}`,
              consent.token,
            ),
            404,
            "pending blob withheld",
          );
        }
        const changes = await json(
          await api(
            origin,
            "/streams/messages/records?changes_since=",
            consent.token,
          ),
          200,
          "pending changes feed",
        );
        assert(
          !(changes.data as { data?: { text?: string } }[]).some(
            (record) => record.data?.text === pendingText,
          ),
          "pending text absent from actual app history",
        );
      };
      await appControl();
      const restarted = await restartB();
      origin = restarted.origin;
      const retained = await b.call("snapshot");
      const retainedOwner = retained.ownerRows.find(
        (candidate) => candidate.recordKey === "visible",
      );
      assert.equal(retainedOwner?.confirmation, "not yet confirmed");
      assert.equal(retainedOwner?.data.text, pendingText);
      await appControl();
      pendingLabels.add(label);
      cases.push({
        case: label,
        grantId: consent.grantId,
        issuerActive: true,
        ownerRow: row,
        appCurrent: current ?? null,
        afterRestartOwnerRow: retainedOwner,
        restarted,
        appPendingPayloadDenied: true,
        appCurrentControlPassed: true,
      });
      save();
    }
    const initialGrant = await approveNarrowConsent(issuer);
    const replicated = await settle(
      "initial replication",
      (s) =>
        s.blobs[blob.blobId]?.sha256 === blob.sha256 &&
        !!s.records["other-only"],
      (snapshot) =>
        inspectPending(
          "initial pending",
          snapshot,
          initialGrant,
          data.text,
          undefined,
        ),
    );
    assert(
      pendingLabels.has("initial pending"),
      "live run must observe owner pending before app confirmation",
    );
    await assertAppRead(origin, initialGrant.token, expected, blob);
    await revokeConsent(issuer, initialGrant);
    cases.push({
      case: "initial replication",
      ...replicated,
      canonical: assertCanonicalEquality(
        join(a.init.root, "records.sqlite"),
        join(b.init.root, "records.sqlite"),
      ),
    });
    save();
    const forbidden = await approveNarrowConsent(
      issuer,
      issuer.foreignCredential,
    );
    await assertTokenDenied(origin, forbidden.token, blob.blobId, issuer);
    for (const phase of ["initial", "after replicated edit"]) {
      const consent = await approveNarrowConsent(issuer);
      if (phase !== "initial") {
        const previousExpected = { ...expected };
        data.text = "after replicated edit";
        expected.text = data.text;
        await a.call("put", {
          id: "visible",
          data: { ...data, blob_ref: blobRef },
        });
        const edited = await settle(
          "replicated edit",
          (s) => (s.records.visible as { text?: string })?.text === data.text,
          (snapshot) =>
            inspectPending(
              "edit pending under active grant",
              snapshot,
              consent,
              data.text,
              previousExpected,
            ),
        );
        assert(
          pendingLabels.has("edit pending under active grant"),
          "live edit must be observed pending under the existing grant",
        );
        cases.push({
          case: "replicated edit",
          ...edited,
          canonical: assertCanonicalEquality(
            join(a.init.root, "records.sqlite"),
            join(b.init.root, "records.sqlite"),
          ),
        });
        save();
      }
      await assertAppRead(origin, consent.token, expected, blob);
      const restarted = await restartB();
      origin = restarted.origin;
      await assertAppRead(origin, consent.token, expected, blob);
      await consent.replayCode();
      await consent.replayApproval();
      await revokeConsent(issuer, consent);
      const revokeDecision = await assertTokenDenied(
        origin,
        consent.token,
        blob.blobId,
        issuer,
      );
      const afterRevoke = await restartB();
      origin = afterRevoke.origin;
      await assertTokenDenied(origin, consent.token, blob.blobId, issuer);
      await consent.replayCode();
      await consent.replayApproval();
      const expiring = await approveNarrowConsent(issuer, issuer.credential, {
        expiring: true,
      });
      await assertAppRead(origin, expiring.token, expected, blob);
      const waitStarted = Date.now();
      await pause((expiring.ttlSeconds + 1) * 1000);
      const expiryDecision = await assertTokenDenied(
        origin,
        expiring.token,
        blob.blobId,
        issuer,
      );
      const afterExpiry = await restartB();
      origin = afterExpiry.origin;
      await assertTokenDenied(origin, expiring.token, blob.blobId, issuer);
      await expiring.replayCode();
      await expiring.replayApproval();
      const fresh = await approveNarrowConsent(issuer);
      await assertAppRead(origin, fresh.token, expected, blob);
      await revokeConsent(issuer, fresh);
      await assertTokenDenied(origin, forbidden.token, blob.blobId, issuer);
      cases.push({
        case: phase,
        restart: restarted,
        revokedRestart: afterRevoke,
        expiredRestart: afterExpiry,
        exactDigest: consent.reviewDigest,
        grantId: consent.grantId,
        activeGrantAcrossEdit: phase === "after replicated edit",
        revokeDecision,
        expiryDecision,
        staleDigestDenied: true,
        oldApprovalDenied: true,
        codeReplayDenied: true,
        hiddenFieldDenied: true,
        otherConnectionDenied: true,
        otherOwnerDenied: true,
        revokedSameTokenDenied: true,
        realExpiryElapsedMs: Date.now() - waitStarted,
        ttlSeconds: expiring.ttlSeconds,
        freshConsentAfterRestart: true,
      });
      save();
    }
    for (const device of devices) {
      const final = await device.call("snapshot");
      assert.equal(final.quarantines, 0);
      assert.deepEqual(final.inboxErrors, []);
    }
    assert.deepEqual(
      sourceHashes(),
      initialSourceHashes,
      "source and built auth seam stayed frozen during the live run",
    );
    report.status = "passed";
  } catch (error) {
    report.status = "failed";
    report.error =
      error instanceof Error ? error.message : "Consent journey failed";
    process.exitCode = 1;
  } finally {
    for (const device of devices) await device.kill();
    await issuer.close();
    report.finishedAt = new Date().toISOString();
    report.peakRssKiB = {
      A: a.peakRssKiB,
      B: b.peakRssKiB,
      parent: process.resourceUsage().maxRSS,
    };
    save();
    rmSync(root, { recursive: true, force: true });
    console.log(
      JSON.stringify({
        status: report.status,
        error: report.error,
        reportPath,
      }),
    );
  }
}
if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url)
  await main();
