import { Hono } from "hono";
import {
  handlePersonalServerDataRequest,
  type PersonalServerApiDispatchOptions,
  type PersonalServerReadFulfillmentReporter,
} from "@opendatalabs/personal-server-ts-core/api";
import type { HierarchyManagerOptions } from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import type { IndexManager } from "@opendatalabs/personal-server-ts-core/storage/index";
import type {
  DataPortabilityGatewayConfig,
  GatewayClient,
} from "@opendatalabs/vana-sdk/node";
import type { AccessLogWriter } from "@opendatalabs/personal-server-ts-core/logging/access-log";
import type {
  ScopeDeletionTracker,
  SyncManager,
} from "@opendatalabs/personal-server-ts-core/sync";
import type {
  DataStoragePort,
  RuntimeAvailabilityPort,
} from "@opendatalabs/personal-server-ts-core/ports";
import type { ServerSigner } from "@opendatalabs/personal-server-ts-core/signing";
import type { TokenStore } from "../token-store.js";
import type {
  WriteProofReplayStore,
  WriteSessionStore,
} from "@opendatalabs/personal-server-ts-core/write";
import type { LineageGatewayPort } from "@opendatalabs/personal-server-ts-core/lineage";
import type { Logger } from "pino";
import {
  createBodyLimit,
  DATA_INGEST_MAX_SIZE,
} from "../middleware/body-limit.js";
import { createNodeDataStorage } from "../storage/node-data-storage.js";
import { createServerApiAuth } from "../api-auth.js";

export interface DataRouteDeps {
  indexManager: IndexManager;
  hierarchyOptions: HierarchyManagerOptions;
  logger: Logger;
  serverOrigin: string | (() => string);
  serverOwner?: `0x${string}`;
  gateway: GatewayClient;
  /**
   * Required for the X402 flow on GET /v1/data/:scope. Provides the EIP-712
   * domain (escrowPaymentDomain + dataRegistryDomain) the server uses to
   * recover X-PAYMENT signatures and the embedded accessRecord signatures.
   */
  gatewayConfig?: DataPortabilityGatewayConfig;
  /**
   * Gateway base URL. Used by the X402 forward path — the handler `fetch`es
   * POST /v1/escrow/pay directly so it can inspect the gateway's structured
   * error body (the SDK's gateway.payForOperation discards it).
   */
  gatewayUrl?: string;
  /**
   * When true, GET /v1/data/:scope enforces the X402 challenge / X-PAYMENT
   * cycle on every read. Off-by-default so dev / test setups don't require
   * builder-side payment signing.
   */
  paymentEnabled?: boolean;
  accessLogWriter: AccessLogWriter;
  readFulfillmentReporter?: PersonalServerReadFulfillmentReporter;
  syncManager?: SyncManager | null;
  /** Read-side tombstone memory; reads of a deleted scope answer 410. */
  scopeDeletions?: ScopeDeletionTracker;
  devToken?: string;
  accessToken?: string;
  tokenStore?: TokenStore;
  dataStorage?: DataStoragePort;
  runtimeAvailability?: RuntimeAvailabilityPort;
  /**
   * Write API sessions (POST /v1/write/session). When present, the ingest
   * endpoint accepts write-session bearer tokens for delegated builder
   * writes; absent = owner-only ingest, unchanged.
   */
  writeSessionStore?: WriteSessionStore;
  /** Replay guard for per-write proofs; defaults to in-memory (api-auth). */
  writeProofReplayStore?: WriteProofReplayStore;
  /**
   * Powers the RECORD_DATA_ACCESS attestation embedded in 402 challenges.
   * When supplied alongside serverOwner + paymentEnabled, every challenge
   * carries a server-signed accessRecord. Required for the on-chain
   * recordDataAccess to be scheduled by gateway.settle later.
   */
  serverSigner?: ServerSigner;
  /**
   * Personal server's own EOA address. Needed by the X402 verifier so it
   * can confirm that the accessRecord echoed back in X-PAYMENT was signed
   * by this server (not forged by a malicious builder).
   */
  serverAddress?: `0x${string}`;
  /**
   * Gateway access for derivative data: lineage source lookups on write, the
   * signed lineage read and the cascade delete walk. Absent = lineage writes
   * can only cite local scopes; lineage read / cascade answer 503 / 501.
   */
  lineageGateway?: LineageGatewayPort;
  mountPath?: PersonalServerApiDispatchOptions["basePath"];
}

export function dataRoutes(deps: DataRouteDeps): Hono {
  const app = new Hono();

  const dataStorage =
    deps.dataStorage ??
    createNodeDataStorage({
      indexManager: deps.indexManager,
      hierarchyOptions: deps.hierarchyOptions,
    });
  const auth = createServerApiAuth({
    serverOrigin: deps.serverOrigin,
    serverOwner: deps.serverOwner,
    gateway: deps.gateway,
    devToken: deps.devToken,
    accessToken: deps.accessToken,
    tokenStore: deps.tokenStore,
    dataStorage,
    runtimeAvailability: deps.runtimeAvailability,
    writeSessionStore: deps.writeSessionStore,
    writeProofReplayStore: deps.writeProofReplayStore,
  });

  app.use("/:scope", createBodyLimit(DATA_INGEST_MAX_SIZE));
  app.all("*", (c) =>
    handlePersonalServerDataRequest(
      c.req.raw,
      {
        storage: dataStorage,
        auth,
        accessLogWriter: deps.accessLogWriter,
        readFulfillmentReporter: deps.readFulfillmentReporter,
        syncManager: deps.syncManager ?? null,
        scopeDeletions: deps.scopeDeletions,
        runtimeAvailability: deps.runtimeAvailability,
        serverSigner: deps.serverSigner,
        serverOwner: deps.serverOwner,
        serverAddress: deps.serverAddress,
        gateway: deps.gateway,
        gatewayConfig: deps.gatewayConfig,
        gatewayUrl: deps.gatewayUrl,
        paymentEnabled: deps.paymentEnabled,
        lineageGateway: deps.lineageGateway,
        // Network identifier for the 402 challenge body. We use the chain
        // id as the convention since the gateway is chain-scoped; clients
        // dispatch on the (scheme, chainId) pair, not the human name.
        network: deps.gatewayConfig
          ? `vana:${deps.gatewayConfig.chainId}`
          : undefined,
        logger: deps.logger,
      },
      { basePath: deps.mountPath },
    ),
  );

  return app;
}
