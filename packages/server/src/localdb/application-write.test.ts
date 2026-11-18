import { afterEach, expect, it, vi } from "vitest";
import {
  connectionQueue,
  openLocalDb,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
import {
  createWriteSessionAuthorization,
  createInMemoryWriteSessionStore,
  createInMemoryWriteProofReplayStore,
  hashWriteSessionToken,
} from "@opendatalabs/personal-server-ts-core/write";
import type { GatewayGrantResponse } from "@opendatalabs/vana-sdk/browser";
import * as grantStore from "../../../core/src/localdb/application-grants.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const owner = `0x${"12".repeat(20)}` as const;
const builder = `0x${"34".repeat(20)}` as const;
const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});

function grant(
  overrides: Partial<GatewayGrantResponse> = {},
): GatewayGrantResponse {
  return {
    id: "application-grant",
    grantVersion: "1",
    grantorAddress: owner,
    granteeId: "registered-app",
    scopes: ["write:notes.items"],
    expiresAt: null,
    revokedAt: null,
    expired: false,
    ...overrides,
  } as GatewayGrantResponse;
}
async function fixture() {
  const db = await openLocalDb(openBetterSqlite3(":memory:"), {
    owner,
    network: "test",
    deviceId: "application-test",
  });
  drivers.push(db);
  const sessions = createInMemoryWriteSessionStore();
  await sessions.create({
    tokenHash: await hashWriteSessionToken("test-token"),
    builderAddress: builder,
    grantId: "application-grant",
    writeScopes: ["notes.items"],
    createdAt: new Date().toISOString(),
    expiresAtMs: Date.now() + 60_000,
  });
  return { db, sessions, queue: connectionQueue() };
}

it("records an observed revocation through authorization before refusing the write", async () => {
  const f = await fixture();
  const observations = grantStore.createApplicationGrantStore(f.db);
  const auth = createWriteSessionAuthorization({
    serverOrigin: "https://server.example",
    serverOwner: owner,
    sessionStore: f.sessions,
    replayStore: createInMemoryWriteProofReplayStore(),
    policyPorts: {
      authSessionVerifier: {
        getBuilder: vi.fn().mockResolvedValue({ id: "registered-app" }),
      },
      grantVerifier: {
        getGrant: vi
          .fn()
          .mockResolvedValue(grant({ revokedAt: "2026-01-01T00:00:00Z" })),
      },
      grantObservations: observations,
    },
  });
  await expect(
    auth.authorizeSessionWrite({
      request: new Request("https://server.example/notes.items", {
        method: "POST",
        headers: { authorization: "Bearer test-token" },
        body: "{}",
      }),
      scope: "notes.items",
    }),
  ).rejects.toMatchObject({ errorCode: "GRANT_REVOKED" });
  const tables = await f.db.query(
    "SELECT name FROM sqlite_master WHERE name='application_grants'",
  );
  expect(tables).toHaveLength(1);
  expect(
    await f.db.query(
      "SELECT grant_id, revision, status FROM application_grants",
    ),
  ).toEqual([
    { grant_id: "application-grant", revision: "1", status: "revoked" },
  ]);
});
