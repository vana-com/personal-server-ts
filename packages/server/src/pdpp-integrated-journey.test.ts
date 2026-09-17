/**
 * PDPP integrated journey: seeded data -> real AS review/approval -> real
 * grant-bound token -> real RS constrained read -> revoke -> denial.
 *
 * This is the integration lane's acceptance test. Its whole point is that
 * NOTHING in the authorization path is a fixture:
 *
 * - The AS is the real `pdppAuthRoutes` surface backed by the real
 *   `PdppAuthStore` (SQLite), `PdppTokenService`, and `AuthorizationSessionStore`
 *   from the AS lane (`feat/pdpp-as-grants`, packages/core/src/pdpp/**).
 * - The RS is the real `pdppRecordsRoutes` surface backed by the real record
 *   store and enforcement from the RS lane (`feat/pdpp-record-storage-rs`,
 *   packages/core/src/storage/pdpp-records/**).
 * - Both are mounted into ONE real `createApp(...)` Hono instance, so the
 *   token the AS mints is the same token the RS resolves, through the same
 *   process and the same store.
 *
 * The RS lane's own `app.pdpp.test.ts` uses `createFixtureAuthorizationService`
 * (a hand-written token->context map). That proves the RS routes are mounted,
 * but it cannot prove the AS and RS agree, because the fixture is written to
 * match whatever the RS expects. Here the context comes from the AS's real
 * `resolveToken`, so a disagreement between the two lanes fails this test.
 *
 * Attribution: all `packages/core/src/pdpp/**` code is the AS lane's; all
 * `packages/core/src/storage/pdpp-records/**` and `routes/pdpp-{records,blobs,
 * well-known}.ts` code is the RS lane's. This file is the only integration
 * code, and it is additive.
 */

import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import pino from "pino";
import { createApp } from "./app.js";
import { initializeDatabase } from "./storage/index-schema.js";
import {
  createIndexManager,
  type IndexManager,
} from "./storage/index-manager.js";
import {
  createMemoryRecordStore,
  createStreamDeclarationRegistry,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import {
  AuthorizationSessionStore,
  openPdppAuthStore,
  PdppTokenService,
  PDPP_DATA_ACCESS_TYPE,
  computeS256Challenge,
  type DeclarationSnapshot,
  type PdppAuthStore,
} from "@opendatalabs/personal-server-ts-core/pdpp";
import type {
  PdppAuthorizationService,
  Grant as PdppAuthorizationContextGrant,
} from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import { createTestWallet } from "@opendatalabs/personal-server-ts-core/test-utils";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import type { AccessLogWriter } from "@opendatalabs/personal-server-ts-core/logging/access-log";
import type { AccessLogReader } from "@opendatalabs/personal-server-ts-core/logging/access-reader";

const SERVER_ORIGIN = "http://localhost:8080";
const SUBJECT = "sub_owner_1";
const CLIENT_ID = "https://client.example/app";
const REDIRECT_URI = "https://client.example/callback";
const SOURCE_ID = "spotify";
const INSTANCE = "inst_spotify_1";
const ownerWallet = createTestWallet(0);

/**
 * Seeded playlists. `created_at` decides grant visibility (the grant's window
 * is `since 2026-01-01`); `emitted_at` decides list ordering. In-window and
 * out-of-window records alternate so that any page of stored rows contains a
 * mix — the condition under which filter-after-pagination produces short
 * pages and wrong cursors.
 */
const SEEDED_PLAYLISTS = [
  {
    id: "pl_1",
    name: "road trip",
    created_at: "2026-04-01T00:00:00.000Z",
    emitted_at: "2026-05-01T00:00:00.000Z",
  },
  {
    id: "pl_2",
    name: "old favourites",
    created_at: "2020-01-01T00:00:00.000Z",
    emitted_at: "2026-05-02T00:00:00.000Z",
  },
  {
    id: "pl_3",
    name: "focus",
    created_at: "2026-04-03T00:00:00.000Z",
    emitted_at: "2026-05-03T00:00:00.000Z",
  },
  {
    id: "pl_4",
    name: "archive 2019",
    created_at: "2019-06-01T00:00:00.000Z",
    emitted_at: "2026-05-04T00:00:00.000Z",
  },
  {
    id: "pl_5",
    name: "summer",
    created_at: "2026-04-05T00:00:00.000Z",
    emitted_at: "2026-05-05T00:00:00.000Z",
  },
  {
    id: "pl_6",
    name: "throwback",
    created_at: "2018-01-01T00:00:00.000Z",
    emitted_at: "2026-05-06T00:00:00.000Z",
  },
];

/** The three records inside the grant window, newest-first (default order). */
const IN_WINDOW_DESC = ["pl_5", "pl_3", "pl_1"];

/**
 * PKCE (RFC 7636) is mandatory on this AS: PDPP clients are public clients,
 * so an intercepted authorization code must be useless without the verifier.
 * The journey uses a real verifier and a real S256 challenge rather than a
 * stub, so it exercises the AS's actual binding check at redemption.
 */
const CODE_VERIFIER =
  "journey-verifier-0123456789abcdefghijklmnopqrstuvwxyz-ABCDEFG";
const CODE_CHALLENGE = computeS256Challenge(CODE_VERIFIER);

function createMockGateway(): GatewayClient {
  return {
    isRegisteredBuilder: async () => true,
    getBuilder: async () => null,
    getGrant: async () => null,
    listGrantsByUser: async () => [],
    getSchemaForScope: async () => null,
    getServer: async () => null,
    getFile: async () => null,
    listFilesSince: async () => ({ files: [], cursor: null }),
    getSchema: async () => null,
    registerServer: async () => ({ alreadyRegistered: false }),
    registerFile: async () => ({}),
    createGrant: async () => ({}),
    revokeGrant: async () => undefined,
  } as unknown as GatewayClient;
}

/**
 * The retained declaration snapshot the AS resolves against. `playlists`
 * carries a `consent_time_field`, which is what makes the time_range in the
 * selection request below legal (§6 "Note on `time_range`"). `follows` exists
 * so the journey can prove a NON-granted stream is refused by the RS.
 */
const SNAPSHOT: DeclarationSnapshot = {
  source_id: SOURCE_ID,
  source_kind: "connector",
  version: "2026-09-01",
  digest: "sha256:integration-fixture-declaration",
  streams: [
    {
      name: "playlists",
      fields: ["id", "name", "owner_email", "created_at"],
      required_fields: ["id"],
      consent_time_field: "created_at",
      primary_key: ["id"],
    },
    {
      name: "follows",
      fields: ["id", "artist"],
      required_fields: ["id"],
      primary_key: ["id"],
    },
  ],
};

/**
 * Bridge the AS's token service to the RS's authorization port.
 *
 * This adapter is the AS<->RS seam, and writing it is what surfaced the two
 * real mismatches reported to the owning lanes:
 *
 *  1. `PdppTokenService.resolveToken` is SYNCHRONOUS, but the RS port declares
 *     `resolveToken(...): Promise<PdppTokenContext>`. Awaiting a non-promise
 *     works, so this is benign today — but the RS port is a mirror of the AS
 *     contract and says it should be "identical, not a superset". It is not.
 *  2. The AS's `PdppTokenContext` marks `tokenKind` and `subjectId` OPTIONAL
 *     (an inactive token carries neither); the RS's mirror marks them
 *     REQUIRED. So the real AS type is NOT assignable to the RS port type,
 *     and this adapter has to narrow. A direct `auth: tokenService` wiring
 *     does not typecheck.
 *
 * Neither is papered over here: the adapter narrows explicitly and the
 * assertions below pin the real behavior.
 */
function bridgeAsToRs(tokens: PdppTokenService): PdppAuthorizationService {
  return {
    async resolveToken(accessToken: string) {
      const context = tokens.resolveToken(accessToken);
      if (!context.active) {
        // The RS port requires tokenKind/subjectId even on the inactive
        // branch; the AS (correctly, per RFC 7662 §2.2) omits them. Fill the
        // required shape without inventing a subject.
        return {
          active: false as const,
          tokenKind: "client" as const,
          subjectId: "",
          inactiveReason: context.inactiveReason,
        };
      }
      return {
        active: true as const,
        tokenKind: context.tokenKind ?? "client",
        subjectId: context.subjectId ?? "",
        // MISMATCH 3: the AS's `ClientDisplay` has a closed shape
        // (`name: string` + known optional URIs); the RS mirror declares an
        // open `[key: string]: unknown` index signature. A closed type is not
        // assignable to an indexed one, so the AS `Grant` is NOT assignable to
        // the RS `Grant` and this cast is load-bearing, not cosmetic. The cast
        // is safe at runtime (the AS shape is a strict subset of what the RS
        // reads) but it is exactly the silent drift the mirror was supposed to
        // prevent. Reported to both lanes; the fix is for the RS to import the
        // AS types now that both branches are composable.
        grant: context.grant as PdppAuthorizationContextGrant | undefined,
        clientId: context.clientId,
        expiresAt: context.expiresAt,
      };
    },
  };
}

interface Harness {
  app: ReturnType<typeof createApp>;
  tokens: PdppTokenService;
  authStore: PdppAuthStore;
  ownerToken: string;
}

describe("PDPP integrated journey (real AS + real RS in one app)", () => {
  let tempDir: string;
  let indexManager: IndexManager;
  let harness: Harness;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "pdpp-journey-"));
    const db = initializeDatabase(":memory:");
    indexManager = createIndexManager(db);
    harness = makeHarness(tempDir, indexManager);
  });

  afterEach(async () => {
    harness.authStore.close();
    indexManager.close();
    await rm(tempDir, { recursive: true, force: true });
  });

  function makeHarness(dir: string, index: IndexManager): Harness {
    // --- Seed actual data into the real RS record store -------------------
    //
    // Six records, alternating in/out of the grant's time window. The
    // interleaving matters: it is what makes filter-before-pagination
    // observable. A grant window that happens to select a contiguous prefix
    // would pass even with the pagination defect.
    const store = createMemoryRecordStore();
    const ingest = store.ingestBatch(
      SEEDED_PLAYLISTS.map((row) => ({
        instance: INSTANCE,
        stream: "playlists",
        key: row.id,
        data: {
          id: row.id,
          name: row.name,
          owner_email: "owner@example.com",
          created_at: row.created_at,
        },
        emitted_at: row.emitted_at,
      })),
      () => "mutable_state",
      () => ["id"],
    );
    expect(ingest.rejected).toEqual([]);

    const declarations = createStreamDeclarationRegistry([
      {
        name: "playlists",
        semantics: "mutable_state",
        primaryKey: ["id"],
        cursorField: "emitted_at",
        consentTimeField: "created_at",
        requiredFields: ["id"],
      },
      {
        name: "follows",
        semantics: "mutable_state",
        primaryKey: ["id"],
        cursorField: "emitted_at",
        requiredFields: ["id"],
      },
    ]);

    // --- Real AS: SQLite-backed store, real token service ------------------
    const authStore = openPdppAuthStore(join(dir, "pdpp-auth.db"));
    const tokens = new PdppTokenService(authStore);
    const sessions = new AuthorizationSessionStore();
    const ownerToken = tokens.issueOwnerToken({
      subjectId: SUBJECT,
    }).access_token;

    const logger = pino({ level: "silent" });
    const app = createApp({
      logger,
      version: "0.0.1",
      startedAt: new Date(),
      indexManager: index,
      hierarchyOptions: { dataDir: join(dir, "data") },
      serverOrigin: SERVER_ORIGIN,
      serverOwner: ownerWallet.address,
      gateway: createMockGateway(),
      accessLogWriter: {
        append: async () => undefined,
      } as unknown as AccessLogWriter,
      accessLogReader: {
        list: async () => ({ entries: [], cursor: null }),
      } as unknown as AccessLogReader,
      // Real AS mounted at /pdpp/v1
      pdppAuth: {
        logger,
        store: authStore,
        tokens,
        sessions,
        resolveDeclaration: (sourceId) =>
          sourceId === SOURCE_ID ? SNAPSHOT : null,
        inventoryFor: () => ({ eligibleFor: () => [INSTANCE] }),
        // The owner is already authenticated by the PS session layer; this
        // journey drives that seam with the real owner token.
        currentSubjectId: (c) => {
          const header = c.req.header("authorization") ?? "";
          if (!header.toLowerCase().startsWith("bearer ")) return null;
          const context = tokens.resolveToken(header.slice(7).trim());
          return context.active && context.tokenKind === "owner"
            ? (context.subjectId ?? null)
            : null;
        },
      },
      // Real RS mounted at /v1, resolving tokens through the real AS
      pdpp: {
        store,
        auth: bridgeAsToRs(tokens),
        declarations,
        instancesForSubject: () => [INSTANCE],
        resource: SERVER_ORIGIN,
      },
    });

    return { app, tokens, authStore, ownerToken };
  }

  /** Drive the real AS: authorize -> review -> approve -> code -> token. */
  async function runAuthorizationJourney(): Promise<{
    grantId: string;
    accessToken: string;
  }> {
    const { app, ownerToken } = harness;
    const ownerAuth = { Authorization: `Bearer ${ownerToken}` };

    // 1. Selection request (RFC 9396). Narrower than the declaration on
    //    purpose: two of four fields, and a time_range that excludes pl_2.
    const authorizeRes = await app.request("/pdpp/v1/authorize", {
      method: "POST",
      headers: { ...ownerAuth, "content-type": "application/json" },
      body: JSON.stringify({
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        client_display: { name: "Example App" },
        code_challenge: CODE_CHALLENGE,
        code_challenge_method: "S256",
        authorization_details: [
          {
            type: PDPP_DATA_ACCESS_TYPE,
            source: { id: SOURCE_ID },
            purpose_code: "https://pdpp.dev/purpose/personalization",
            access_mode: "continuous",
            streams: [
              {
                name: "playlists",
                fields: ["name"],
                time_range: { since: "2026-01-01T00:00:00.000Z" },
              },
            ],
          },
        ],
      }),
    });
    expect(authorizeRes.status).toBe(201);
    const { session_id: sessionId } = await authorizeRes.json();

    // 2. Real consent review model, with the digest the approval must echo.
    const reviewRes = await app.request(
      `/pdpp/v1/authorize/${sessionId}/review`,
      { headers: ownerAuth },
    );
    expect(reviewRes.status).toBe(200);
    const reviewBody = await reviewRes.json();
    // Both instances resolve to a single handle, so this is the review branch,
    // not the `instance_choice_required` branch.
    expect(reviewBody.instance_choice_required).toBeUndefined();
    const review = reviewBody.review;
    expect(review?.review_digest).toBeTruthy();

    // 3. Owner approval, authenticated by the real owner token.
    const approveRes = await app.request(
      `/pdpp/v1/authorize/${sessionId}/approve`,
      {
        method: "POST",
        headers: { ...ownerAuth, "content-type": "application/json" },
        body: JSON.stringify({ review_digest: review.review_digest }),
      },
    );
    expect(approveRes.status).toBe(200);
    const approval = await approveRes.json();
    expect(approval.grant_id).toBeTruthy();

    // 4. Redeem the authorization code for a real grant-bound token.
    const code = new URL(approval.redirect_uri).searchParams.get("code");
    expect(code).toBeTruthy();
    const tokenRes = await app.request("/pdpp/v1/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: code!,
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        code_verifier: CODE_VERIFIER,
      }).toString(),
    });
    expect(tokenRes.status).toBe(200);
    expect(tokenRes.headers.get("cache-control")).toBe("no-store");
    const token = await tokenRes.json();
    expect(token.access_token).toBeTruthy();

    return { grantId: approval.grant_id, accessToken: token.access_token };
  }

  it("issues a grant-bound token whose grant the RS resolves from the real AS", async () => {
    const { grantId, accessToken } = await runAuthorizationJourney();

    // The token the AS minted resolves, through the real AS, to a client
    // context carrying the resolved grant the RS will enforce.
    const context = harness.tokens.resolveToken(accessToken);
    expect(context.active).toBe(true);
    expect(context.tokenKind).toBe("client");
    expect(context.subjectId).toBe(SUBJECT);
    expect(context.grant?.grant_id).toBe(grantId);

    // Axis resolution really happened: the wildcard-free grant carries the
    // narrowed field set (plus the schema-required `id` floor) and the
    // instance handle resolved from inventory, not from the request.
    const stream = context.grant!.streams.find((s) => s.name === "playlists");
    expect(stream).toBeDefined();
    expect(stream!.instance_ids).toEqual([INSTANCE]);
    expect(new Set(stream!.fields)).toEqual(new Set(["id", "name"]));
    expect(stream!.time_constraint).toMatchObject({
      field: "created_at",
      since: "2026-01-01T00:00:00.000Z",
    });
    expect(context.grant!.source).toEqual({
      kind: "connector",
      id: SOURCE_ID,
    });
  });

  /**
   * REGRESSION for a defect this integration found and fixed.
   *
   * `pdpp-records.ts` used to ask the store for records with the granted
   * field set and only THEN filter through
   * `recordWithinGrantTimeConstraint(row.data, ...)`. That predicate reads
   * `row.data[time_constraint.field]`, but projection had already deleted
   * that field whenever the constraint field was not itself granted, and
   * `withinTimeConstraint` treats an absent value as "outside the
   * constraint". Every record was filtered out and the read returned an empty
   * list — a silent wrong answer, not an error.
   *
   * Isolated proof of the original defect (same store, same predicate):
   *   projectedKeys:     ["id","name"]
   *   withinProjected:   false   <- constraint field was projected away
   *   withinUnprojected: true    <- same record, same grant, correct answer
   *
   * This is the case the RS lane's own tests could not see, because they
   * either grant the constraint field or use no time_constraint. The grant
   * here deliberately does NOT include `created_at`.
   */
  it("enforces the time constraint when the constraint field is NOT granted", async () => {
    const { accessToken } = await runAuthorizationJourney();

    const res = await harness.app.request("/v1/streams/playlists/records", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    expect(res.status).toBe(200);
    const body = await res.json();

    // Exactly the in-window records, newest-first; the 2018/2019/2020 ones
    // are outside the grant's `since`.
    expect(body.data.map((d: { data: { id: string } }) => d.data.id)).toEqual(
      IN_WINDOW_DESC,
    );

    // The constraint field was needed to evaluate the window, but it was
    // never granted — so it must not leak into the response.
    expect(body.data[0].data).toEqual({ id: "pl_5", name: "summer" });
    expect(body.data[0].data.created_at).toBeUndefined();
    expect(body.data[0].data.owner_email).toBeUndefined();
  });

  /**
   * REGRESSION: grant filtering must happen BEFORE pagination.
   *
   * The store pages first and the route filtered afterwards, so a page of
   * `limit` STORED rows could yield fewer than `limit` VISIBLE rows. With the
   * interleaved seed above, `limit=2` returned only 1 record, and
   * `has_more`/`next_cursor` described a position in the UNFILTERED sequence.
   * `limit` must mean "at most N records you may see".
   */
  it("applies the grant filter before pagination, so limit and cursors count visible records", async () => {
    const { accessToken } = await runAuthorizationJourney();
    const auth = { Authorization: `Bearer ${accessToken}` };

    const first = await harness.app.request(
      "/v1/streams/playlists/records?limit=2",
      { headers: auth },
    );
    expect(first.status).toBe(200);
    const firstBody = await first.json();

    // A full page of VISIBLE records, not a short page of stored rows.
    expect(
      firstBody.data.map((d: { data: { id: string } }) => d.data.id),
    ).toEqual(IN_WINDOW_DESC.slice(0, 2));
    expect(firstBody.has_more).toBe(true);
    expect(firstBody.next_cursor).toBeTruthy();

    // The cursor resumes in the filtered sequence, with no gap or repeat.
    const second = await harness.app.request(
      `/v1/streams/playlists/records?limit=2&cursor=${encodeURIComponent(firstBody.next_cursor)}`,
      { headers: auth },
    );
    expect(second.status).toBe(200);
    const secondBody = await second.json();
    expect(
      secondBody.data.map((d: { data: { id: string } }) => d.data.id),
    ).toEqual(IN_WINDOW_DESC.slice(2));
    // Terminal page: nothing further the client may see.
    expect(secondBody.has_more).toBe(false);
  });

  /**
   * REGRESSION: a client token must not learn about records outside its grant
   * through stream-listing metadata. `record_count` / `last_updated` came
   * straight from the store's instance-wide listing, which counted all six
   * seeded records and reported the newest one's timestamp — leaking the
   * existence and recency of data the grant does not expose.
   */
  it("does not leak non-granted records through client stream-listing metadata", async () => {
    const { accessToken } = await runAuthorizationJourney();

    const res = await harness.app.request("/v1/streams", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    expect(res.status).toBe(200);
    const body = await res.json();

    // Only the granted stream, counted over only the granted projection.
    expect(body.data).toHaveLength(1);
    expect(body.data[0].name).toBe("playlists");
    expect(body.data[0].record_count).toBe(IN_WINDOW_DESC.length);
    // Newest VISIBLE record (pl_5), not the newest stored record (pl_6).
    expect(body.data[0].last_updated).toBe("2026-05-05T00:00:00.000Z");
  });

  /**
   * changes_since must apply the same grant filter and the same projection as
   * the list path, and must not expose the constraint field it needs
   * internally to evaluate the time window.
   */
  it("applies grant filtering and projection consistently on the changes_since feed", async () => {
    const { accessToken } = await runAuthorizationJourney();

    const res = await harness.app.request(
      "/v1/streams/playlists/records?changes_since=",
      { headers: { Authorization: `Bearer ${accessToken}` } },
    );
    expect(res.status).toBe(200);
    const body = await res.json();

    expect(body.data).toHaveLength(IN_WINDOW_DESC.length);
    for (const row of body.data) {
      expect(Object.keys(row.data).sort()).toEqual(["id", "name"]);
      expect(row.data.created_at).toBeUndefined();
      expect(row.data.owner_email).toBeUndefined();
    }
  });

  /**
   * Owner tokens carry no grant: the owner reads their own store without a
   * second grant authority, unprojected and unfiltered. This is the control
   * that proves the fixes above narrowed the CLIENT path only and did not
   * quietly constrain owner access.
   */
  it("leaves owner-token reads unfiltered and unprojected", async () => {
    const res = await harness.app.request(
      "/v1/streams/playlists/records?limit=100",
      { headers: { Authorization: `Bearer ${harness.ownerToken}` } },
    );
    expect(res.status).toBe(200);
    const body = await res.json();

    // Every seeded record, including those outside any grant window.
    expect(body.data).toHaveLength(SEEDED_PLAYLISTS.length);
    // Full record, including fields no client grant exposes.
    expect(body.data[0].data.owner_email).toBe("owner@example.com");
    expect(body.data[0].data.created_at).toBeTruthy();

    // Owner stream listing sees the true instance-wide counts.
    const streams = await harness.app.request("/v1/streams", {
      headers: { Authorization: `Bearer ${harness.ownerToken}` },
    });
    const streamsBody = await streams.json();
    expect(streamsBody.data[0].record_count).toBe(SEEDED_PLAYLISTS.length);
  });

  /**
   * The same read with the constraint field inside the granted field set.
   * This isolates the defect above: nothing changes except that `created_at`
   * is granted, and now the time constraint filters correctly instead of
   * eliminating everything. This is the positive proof that real per-stream
   * field projection AND real time-constraint enforcement both work.
   */
  it("enforces field projection and the time constraint when the constraint field is granted", async () => {
    const { app, ownerToken } = harness;
    const ownerAuth = { Authorization: `Bearer ${ownerToken}` };

    const authorizeRes = await app.request("/pdpp/v1/authorize", {
      method: "POST",
      headers: { ...ownerAuth, "content-type": "application/json" },
      body: JSON.stringify({
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        client_display: { name: "Example App" },
        code_challenge: CODE_CHALLENGE,
        code_challenge_method: "S256",
        authorization_details: [
          {
            type: PDPP_DATA_ACCESS_TYPE,
            source: { id: SOURCE_ID },
            purpose_code: "https://pdpp.dev/purpose/personalization",
            access_mode: "continuous",
            streams: [
              {
                name: "playlists",
                fields: ["name", "created_at"],
                time_range: { since: "2026-01-01T00:00:00.000Z" },
              },
            ],
          },
        ],
      }),
    });
    expect(authorizeRes.status).toBe(201);
    const { session_id: sessionId } = await authorizeRes.json();

    const reviewRes = await app.request(
      `/pdpp/v1/authorize/${sessionId}/review`,
      { headers: ownerAuth },
    );
    const review = (await reviewRes.json()).review;

    const approveRes = await app.request(
      `/pdpp/v1/authorize/${sessionId}/approve`,
      {
        method: "POST",
        headers: { ...ownerAuth, "content-type": "application/json" },
        body: JSON.stringify({ review_digest: review.review_digest }),
      },
    );
    expect(approveRes.status).toBe(200);
    const approval = await approveRes.json();

    const code = new URL(approval.redirect_uri).searchParams.get("code");
    const tokenRes = await app.request("/pdpp/v1/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: code!,
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        code_verifier: CODE_VERIFIER,
      }).toString(),
    });
    const { access_token: accessToken } = await tokenRes.json();

    const res = await app.request("/v1/streams/playlists/records", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    expect(res.status).toBe(200);
    const body = await res.json();

    // Time constraint enforced: the pre-2026 records are excluded.
    expect(body.data.map((d: { data: { id: string } }) => d.data.id)).toEqual(
      IN_WINDOW_DESC,
    );
    // Field projection enforced: `owner_email` was never granted, so it must
    // not appear even though it exists in the seeded record. `created_at` IS
    // granted here, so it must appear.
    expect(body.data[0].data).toEqual({
      id: "pl_5",
      name: "summer",
      created_at: "2026-04-05T00:00:00.000Z",
    });
    expect(body.data[0].data.owner_email).toBeUndefined();
  });

  /**
   * PKCE must actually bind the code to the requesting client, not merely be
   * accepted as a parameter. This drives the real flow up to a valid
   * authorization code, then redeems it with the WRONG verifier: the AS must
   * refuse, and no token may be issued. Without this, the happy-path PKCE
   * assertions above would pass even if the AS ignored the verifier entirely.
   */
  it("refuses to redeem an authorization code with the wrong PKCE verifier", async () => {
    const { app, ownerToken } = harness;
    const ownerAuth = { Authorization: `Bearer ${ownerToken}` };

    const authorizeRes = await app.request("/pdpp/v1/authorize", {
      method: "POST",
      headers: { ...ownerAuth, "content-type": "application/json" },
      body: JSON.stringify({
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        client_display: { name: "Example App" },
        code_challenge: CODE_CHALLENGE,
        code_challenge_method: "S256",
        authorization_details: [
          {
            type: PDPP_DATA_ACCESS_TYPE,
            source: { id: SOURCE_ID },
            purpose_code: "https://pdpp.dev/purpose/personalization",
            access_mode: "continuous",
            streams: [{ name: "playlists", fields: ["name"] }],
          },
        ],
      }),
    });
    expect(authorizeRes.status).toBe(201);
    const { session_id: sessionId } = await authorizeRes.json();

    const reviewRes = await app.request(
      `/pdpp/v1/authorize/${sessionId}/review`,
      { headers: ownerAuth },
    );
    const review = (await reviewRes.json()).review;

    const approveRes = await app.request(
      `/pdpp/v1/authorize/${sessionId}/approve`,
      {
        method: "POST",
        headers: { ...ownerAuth, "content-type": "application/json" },
        body: JSON.stringify({ review_digest: review.review_digest }),
      },
    );
    expect(approveRes.status).toBe(200);
    const code = new URL(
      (await approveRes.json()).redirect_uri,
    ).searchParams.get("code");
    expect(code).toBeTruthy();

    // A real, unexpired, unredeemed code — but the wrong verifier. This is
    // the intercepted-code case PKCE exists to stop.
    const tokenRes = await app.request("/pdpp/v1/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: code!,
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        code_verifier: `${CODE_VERIFIER}-tampered`,
      }).toString(),
    });
    expect(tokenRes.status).toBe(400);
    const body = await tokenRes.json();
    expect(body.access_token).toBeUndefined();
  });

  it("refuses a stream the grant does not cover", async () => {
    const { accessToken } = await runAuthorizationJourney();

    const res = await harness.app.request("/v1/streams/follows/records", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    expect(res.status).toBe(403);
  });

  it("denies the RS read within the introspection bound after revocation", async () => {
    const { grantId, accessToken } = await runAuthorizationJourney();

    // The read is authorized before revocation (200, not 403). Row count is
    // not asserted here — see the known-defect test above.
    const before = await harness.app.request("/v1/streams/playlists/records", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    expect(before.status).toBe(200);

    // Revoke through the real AS revocation endpoint, not the store directly.
    const revokeRes = await harness.app.request("/pdpp/v1/revoke", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${harness.ownerToken}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ grant_id: grantId }).toString(),
    });
    expect(revokeRes.status).toBe(200);

    // The AS reports the grant inactive immediately (§2, §9 AS item 8).
    const context = harness.tokens.resolveToken(accessToken);
    expect(context.active).toBe(false);
    expect(context.inactiveReason).toBe("grant_revoked");

    // And the RS denies the read with 403 grant_revoked. There is no cache to
    // wait out here: the RS resolves through the AS on every request, so the
    // 60-second positive-cache bound is satisfied trivially.
    const after = await harness.app.request("/v1/streams/playlists/records", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    expect(after.status).toBe(403);
    const error = await after.json();
    expect(JSON.stringify(error)).toContain("grant_revoked");
  });
});
