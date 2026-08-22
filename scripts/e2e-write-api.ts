/**
 * Self-contained end-to-end demo of the Write API slice.
 *
 * Boots a real personal server in-process (no external gateway, no network:
 * an injected mock GatewayClient supplies the builder + grants), then runs
 * the full builder flow:
 *
 *   1. open a write-session: Web3Signed handshake with a WRITE-grant
 *      (`write:`-prefixed scope entries) -> short-lived bearer token
 *   2. write a JSON record through the EXISTING ingest endpoint
 *      (POST /v1/data/:scope) with the session token + a builder-signed
 *      payload proof (X-Vana-Write-Signature) -> stored with $writtenBy
 *      attribution, PS-side owner signing untouched
 *   3. read back WITHOUT a read-grant -> 403 (write never confers read)
 *   4. read back with a SEPARATE read-grant -> 200, attribution verifiable
 *
 * Run:
 *   npm run e2e:write-api
 *   (or npx tsx scripts/e2e-write-api.ts)
 *
 * Exits non-zero if any check fails.
 */

import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  MASTER_KEY_MESSAGE,
  verifyWeb3Signed,
} from "@opendatalabs/vana-sdk/node";
import type {
  Builder,
  GatewayClient,
  GatewayGrantResponse,
} from "@opendatalabs/vana-sdk/node";
import {
  createTestWallet,
  buildWeb3SignedHeader,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import {
  ServerConfigSchema,
  type ServerConfig,
} from "../packages/core/src/schemas/server-config.js";
import { createServer } from "../packages/server/src/bootstrap.js";

const PORT = 8798;
const ORIGIN = `http://localhost:${PORT}`;
const SCOPE = "notes.entries";
const WRITE_GRANT_ID = "0xwritegrant1";
const READ_GRANT_ID = "0xreadgrant1";

const owner = createTestWallet(0);
const builder = createTestWallet(3);

const failures: string[] = [];
function check(condition: boolean, label: string, detail: unknown = "") {
  const note = detail ? ` — ${String(detail)}` : "";
  console.log(`${condition ? "PASS" : "FAIL"} ${label}${note}`);
  if (!condition) failures.push(label);
}

function makeMockGateway(): GatewayClient {
  const grantFor = (grantId: string, scopes: string[]): GatewayGrantResponse =>
    ({
      id: grantId,
      grantorAddress: owner.address,
      granteeId: builder.address,
      scopes,
      status: "confirmed",
      addedAt: "2026-01-21T10:00:00.000Z",
      expiresAt: null,
      expired: false,
      revokedAt: null,
      revocationSignature: null,
      paymentStatus: "paid",
      paidAt: null,
      paidBy: null,
      grantVersion: "1",
      settleTxHash: null,
      settleSubmittedAt: null,
      revocationTxHash: null,
      revocationSubmittedAt: null,
      fee: {
        asset: "0x0000000000000000000000000000000000000000",
        registrationFee: "0",
        dataAccessFee: "0",
        totalDue: "0",
      },
    }) as GatewayGrantResponse;
  const builderFor = (address: string): Builder => ({
    id: address,
    ownerAddress: owner.address,
    granteeAddress: address as `0x${string}`,
    publicKey: "0x04",
    appUrl: "https://e2e.test",
    addedAt: "2026-01-21T10:00:00.000Z",
  });
  return {
    isRegisteredBuilder: async () => true,
    getBuilder: async (address: string) => builderFor(address),
    getGrant: async (grantId: string) => {
      if (grantId === WRITE_GRANT_ID) {
        return grantFor(WRITE_GRANT_ID, [`write:${SCOPE}`]);
      }
      if (grantId === READ_GRANT_ID) {
        return grantFor(READ_GRANT_ID, [SCOPE]);
      }
      return null;
    },
    listGrantsByUser: async () => [],
    getSchemaForScope: async () => null,
    getSchema: async () => null,
    getServer: async () => null,
    getFile: async () => null,
    listFilesSince: async () => ({ files: [], cursor: null }),
    registerServer: async () => ({ alreadyRegistered: true }),
    registerFile: async () => ({}),
    createGrant: async () => ({ grantId: WRITE_GRANT_ID }),
    revokeGrant: async () => undefined,
  } as unknown as GatewayClient;
}

function makeConfig(): ServerConfig {
  return ServerConfigSchema.parse({
    server: { port: PORT, origin: ORIGIN },
    gateway: { url: "http://localhost:9999" },
    sync: { enabled: false },
    tunnel: { enabled: false },
    devUi: { enabled: true },
    logging: { level: "error" },
  });
}

type App = { request: (path: string, init?: RequestInit) => Promise<Response> };

async function main() {
  const rootPath = await mkdtemp(join(tmpdir(), "vana-write-api-e2e-"));
  const ownerSignature = await owner.signMessage(MASTER_KEY_MESSAGE);

  const ctx = await createServer(makeConfig(), {
    rootPath,
    ownerSignature,
    gatewayClient: makeMockGateway(),
  });
  const app = ctx.app as unknown as App;

  try {
    // 1. Open a write-session (builder proves control of its key + grant).
    const handshake = await buildWeb3SignedHeader({
      wallet: builder,
      aud: ORIGIN,
      method: "POST",
      uri: "/v1/write/session",
      grantId: WRITE_GRANT_ID,
    });
    const sessionRes = await app.request(`${ORIGIN}/v1/write/session`, {
      method: "POST",
      headers: { Authorization: handshake },
    });
    check(
      sessionRes.status === 200,
      "open write-session",
      `status=${sessionRes.status}`,
    );
    const session = (await sessionRes.json()) as {
      access_token?: string;
      scope?: string;
    };
    check(Boolean(session.access_token), "session token minted");
    check(session.scope === SCOPE, "session scope", session.scope);
    const token = session.access_token ?? "";

    // 2. Write a JSON record with the session token + signed payload.
    const rawBody = JSON.stringify({
      note: "hello from the builder",
      source: "e2e-write-api",
    });
    const payloadProof = await buildWeb3SignedHeader({
      wallet: builder,
      aud: ORIGIN,
      method: "POST",
      uri: `/v1/data/${SCOPE}`,
      body: new TextEncoder().encode(rawBody),
    });
    const writeRes = await app.request(`${ORIGIN}/v1/data/${SCOPE}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
        "X-Vana-Write-Signature": payloadProof,
      },
      body: rawBody,
    });
    check(
      writeRes.status === 201,
      "builder write ingested",
      `status=${writeRes.status}`,
    );

    // 3. Read back WITHOUT a read-grant (using the WRITE grant) -> 403.
    const writeGrantRead = await buildWeb3SignedHeader({
      wallet: builder,
      aud: ORIGIN,
      method: "GET",
      uri: `/v1/data/${SCOPE}`,
      grantId: WRITE_GRANT_ID,
    });
    const deniedRes = await app.request(`${ORIGIN}/v1/data/${SCOPE}`, {
      headers: { Authorization: writeGrantRead },
    });
    check(
      deniedRes.status === 403,
      "read with write-grant denied",
      `status=${deniedRes.status}`,
    );

    // 4. Read back with a SEPARATE read-grant -> 200 + verifiable attribution.
    const readGrantRead = await buildWeb3SignedHeader({
      wallet: builder,
      aud: ORIGIN,
      method: "GET",
      uri: `/v1/data/${SCOPE}`,
      grantId: READ_GRANT_ID,
    });
    const readRes = await app.request(`${ORIGIN}/v1/data/${SCOPE}`, {
      headers: { Authorization: readGrantRead },
    });
    check(
      readRes.status === 200,
      "read with read-grant served",
      `status=${readRes.status}`,
    );
    const envelope = (await readRes.json()) as {
      data?: Record<string, unknown>;
    };
    const data = envelope.data ?? {};
    check(data.note === "hello from the builder", "payload intact");
    const attribution = data.$writtenBy as
      | {
          builder?: string;
          grantId?: string;
          signature?: string;
          bodyHash?: string;
        }
      | undefined;
    check(
      attribution?.builder?.toLowerCase() === builder.address.toLowerCase(),
      "attribution builder identity",
      attribution?.builder,
    );
    check(
      attribution?.grantId === WRITE_GRANT_ID,
      "attribution grant id",
      attribution?.grantId,
    );

    // Cryptographic attribution: the stored compact proof recovers to the
    // builder over the original body bytes.
    let recovered: string | null = null;
    try {
      const verified = await verifyWeb3Signed({
        headerValue: `Web3Signed ${attribution?.signature ?? ""}`,
        expectedOrigin: ORIGIN,
        expectedMethod: "POST",
        expectedPath: `/v1/data/${SCOPE}`,
        bodyBytes: new TextEncoder().encode(rawBody),
      });
      recovered = verified.signer;
    } catch (err) {
      check(false, "attribution signature verifies", (err as Error).message);
    }
    if (recovered) {
      check(
        recovered.toLowerCase() === builder.address.toLowerCase(),
        "attribution signature recovers to builder",
        recovered,
      );
    }
  } finally {
    await ctx.cleanup();
  }

  if (failures.length > 0) {
    console.error(`\n${failures.length} check(s) failed`);
    process.exit(1);
  }
  console.log("\nAll checks passed");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
