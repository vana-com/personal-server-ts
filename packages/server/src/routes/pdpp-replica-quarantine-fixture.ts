/** Test-only real issuer/replica HTTP fixture; never imports the live harness. */
import assert from "node:assert/strict";
import { join } from "node:path";
import { serve } from "@hono/node-server";
import { Hono } from "hono";
import pino from "pino";
import {
  AuthorizationSessionStore,
  computeS256Challenge,
  openPdppAuthStore,
  PDPP_DATA_ACCESS_TYPE_V02,
  PdppTokenService,
  type DeclarationSnapshot,
  type Grant,
} from "@opendatalabs/personal-server-ts-core/pdpp";
import type {
  Grant as PdppPortGrant,
  PdppAuthorizationService,
} from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import { createStreamDeclarationRegistry } from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { pdppAuthRoutes } from "./pdpp-auth.js";
import {
  pdppRecordsRoutes,
  type PdppRecordsRouteDeps,
} from "./pdpp-records.js";
import { pdppBlobsRoutes, type PdppBlobsRouteDeps } from "./pdpp-blobs.js";
import {
  replicaChainCommitment,
  type ReplicaRegistrationEvidence,
  type ReplicaTransportPort,
} from "@opendatalabs/personal-server-ts-core/replication/dpv2";
import {
  fragmentReplicaPayload,
  prepareReplicaManifest,
  replicaDigest,
  replicaFragmentKey,
  replicaManifestKey,
  replicaScope,
  type PreparedFragment,
  type PreparedManifest,
  type Predecessor,
} from "@opendatalabs/personal-server-ts-core/replication/transport";
import type { ReplicaBatchFacts } from "@opendatalabs/personal-server-ts-core/replication/writer-identity";
import type { createReplicaRecordStore } from "../storage/pdpp-replica-canonical-port.js";

const sourceId = "https://replica-journey.invalid/declaration";
const logger = pino({ level: "silent" });
const clientId = "replica-consent-acceptance";
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

async function listen(app: Hono) {
  const server = serve({ fetch: app.fetch, hostname: "127.0.0.1", port: 0 });
  await new Promise<void>((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  });
  const address = server.address();
  assert(address && typeof address === "object");
  const origin = `http://127.0.0.1:${address.port}`;
  return {
    origin,
    close: async () => {
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
    },
  };
}

export async function openConsentIssuer(
  root: string,
  owner: string,
  ttlSeconds = 12,
) {
  const store = openPdppAuthStore(join(root, "auth.sqlite"));
  const tokens = new PdppTokenService(store, {
    accessTokenTtlSeconds: ttlSeconds,
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
        id === clientId ? { client_id: id, redirect_uris: [redirect] } : null,
    }),
  );
  const httpServer = await listen(app);
  return {
    ...httpServer,
    credential,
    foreignCredential,
    tokens,
    close: async () => {
      await httpServer.close();
      store.close();
    },
  };
}
export type ConsentIssuer = Awaited<ReturnType<typeof openConsentIssuer>>;

export async function openReplicaResourceServer(
  store: ReturnType<typeof createReplicaRecordStore>,
  options: {
    owner: string;
    tokens: PdppTokenService;
    /** The host reader capability (`AppDeps.pdpp.reads`). */
    reads: NonNullable<PdppRecordsRouteDeps["reads"]> &
      NonNullable<PdppBlobsRouteDeps["reads"]>;
  },
) {
  // Co-located AS/RS seam: consult the one live issuer token service per read.
  // Replica SQLite contains only data; no auth state is copied or synthesized.
  const auth: PdppAuthorizationService = {
    async resolveToken(accessToken: string) {
      const context = options.tokens.resolveToken(accessToken);
      // Same retained AS-grant -> RS-port mirror used by the supported
      // coLocatedAuthorizationService; no fixture grant is manufactured.
      return { ...context, grant: context.grant as PdppPortGrant | undefined };
    },
  };
  const declarations = createStreamDeclarationRegistry([
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
      instancesForSource: (subject, source) =>
        subject === options.owner && source === sourceId
          ? ["conn", "conn-other"]
          : [],
    }),
  );
  app.route(
    "/pdpp/v1/blobs",
    pdppBlobsRoutes({
      store,
      auth,
      declarations,
      reads: options.reads,
      instancesForSource: (subject, source) =>
        subject === options.owner && source === sourceId
          ? ["conn", "conn-other"]
          : [],
      readBlobBytes: async (id) => {
        const bytes = store.getBlobBytes(id);
        return bytes ? new Uint8Array(bytes) : undefined;
      },
    }),
  );
  return listen(app);
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
) {
  const created = await json(
    await api(issuer.origin, "/authorize", ownerCredential, {
      client_id: clientId,
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
      client_id: clientId,
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

/** Finalized DPv2 evidence of one registered manifest slot. */
export function finalizedEvidence(
  owner: string,
  manifest: Pick<
    PreparedManifest,
    "scope" | "version" | "dataHash" | "metadataHash"
  >,
  currentVersion = String(manifest.version),
): ReplicaRegistrationEvidence {
  return {
    head: {
      owner,
      scope: manifest.scope,
      version: String(manifest.version),
      dataHash: manifest.dataHash,
      metadataHash: manifest.metadataHash,
      deleted: false,
    },
    chain: {
      owner,
      scope: manifest.scope,
      version: String(manifest.version),
      currentVersion,
      status: "Active",
      commitment: replicaChainCommitment(
        manifest.dataHash,
        manifest.metadataHash,
      ),
      chainId: 14800,
      registry: `0x${"2".repeat(40)}`,
      blockNumber: 123n,
      blockHash: `0x${"3".repeat(64)}`,
      blockTimestamp: 1000n,
    },
    pending: false,
  };
}

/**
 * An in-memory storage and registry with finalized evidence. Codec identity
 * is deliberate: crypto is covered by transport tests; here the finalized
 * hash bindings and the authorization/read boundary are the oracle.
 */
export function finalizedReplicaNetwork(owner: string) {
  const objects = new Map<string, Uint8Array>();
  const evidence = new Map<string, ReplicaRegistrationEvidence>();
  const latest = new Map<string, number>();
  const observed: string[] = [];
  const register = (manifest: PreparedManifest) => {
    const slot = replicaManifestKey(manifest.scope, manifest.version);
    objects.set(slot, manifest.encrypted);
    evidence.set(slot, finalizedEvidence(owner, manifest));
    latest.set(
      manifest.scope,
      Math.max(latest.get(manifest.scope) ?? 0, manifest.version),
    );
    return slot;
  };
  const read = (key: string) => {
    const bytes = objects.get(key);
    if (!bytes) throw new Error("not found");
    return bytes;
  };
  const port: ReplicaTransportPort = {
    encryptedByteLength: (bytes) => bytes,
    encrypt: async (_scope, bytes) => bytes,
    decrypt: async (_scope, bytes) => bytes,
    putFragment: async (f) => {
      objects.set(replicaFragmentKey(f.scope, f.digest), f.encrypted);
    },
    getFragment: async (scope, digest) =>
      read(replicaFragmentKey(scope, digest)),
    hasFragment: async (scope, digest) =>
      objects.has(replicaFragmentKey(scope, digest)),
    put: async (manifest) => {
      objects.set(
        replicaManifestKey(manifest.scope, manifest.version),
        manifest.encrypted,
      );
    },
    register: async (manifest) => {
      register(manifest);
    },
    get: async (scope, version) => read(replicaManifestKey(scope, version)),
    list: async () => ({
      points: [...latest].map(([scope, version]) => ({
        scope,
        version: String(version),
      })),
      cursor: null,
    }),
    evidence: async (scope, version) => {
      const slot = replicaManifestKey(scope, version);
      observed.push(slot);
      return evidence.get(slot) ?? { head: null, chain: null, pending: false };
    },
  };
  /**
   * Store a batch's fragments and register its manifest at the next version.
   * `sign` is the writer's server key, as `remoteReplicaTestWriter().sign`.
   */
  async function publish(input: {
    writer: string;
    batch: string;
    sequence?: number;
    previous?: Predecessor | null;
    collectedAt: string;
    bytes: Uint8Array;
    sign: (facts: ReplicaBatchFacts) => Promise<unknown>;
  }): Promise<{
    slot: string;
    manifest: PreparedManifest;
    fragments: PreparedFragment[];
  }> {
    const statement = {
      owner,
      writer: input.writer,
      batch: input.batch,
      sequence: input.sequence ?? 1,
      previous: input.previous ?? null,
      collectedAt: input.collectedAt,
    };
    const fragments = await fragmentReplicaPayload({
      ...statement,
      bytes: input.bytes,
      encrypt: port.encrypt,
    });
    for (const fragment of fragments) await port.putFragment(fragment);
    const manifest = await prepareReplicaManifest({
      ...statement,
      version: (latest.get(replicaScope(input.writer)) ?? 0) + 1,
      digest: replicaDigest(input.bytes),
      totalBytes: input.bytes.length,
      fragments: fragments.map((f) => ({
        digest: f.digest,
        bytes: f.encrypted.length,
      })),
      sign: input.sign,
      encrypt: port.encrypt,
    });
    return { slot: register(manifest), manifest, fragments };
  }
  return { port, objects, evidence, observed, publish };
}
