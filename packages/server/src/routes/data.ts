import { Hono } from "hono";
import {
  handlePersonalServerDataRequest,
  type PersonalServerApiDispatchOptions,
} from "@opendatalabs/personal-server-ts-core/api";
import type { HierarchyManagerOptions } from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import type { IndexManager } from "@opendatalabs/personal-server-ts-core/storage/index";
import type {
  DataPortabilityGatewayConfig,
  GatewayClient,
} from "@opendatalabs/vana-sdk/node";
import type { AccessLogWriter } from "@opendatalabs/personal-server-ts-core/logging/access-log";
import type { SyncManager } from "@opendatalabs/personal-server-ts-core/sync";
import type {
  DataStoragePort,
  RuntimeAvailabilityPort,
} from "@opendatalabs/personal-server-ts-core/ports";
import type { ServerSigner } from "@opendatalabs/personal-server-ts-core/signing";
import type { TokenStore } from "../token-store.js";
import type { Logger } from "pino";
import {
  createBodyLimit,
  DATA_INGEST_MAX_SIZE,
} from "../middleware/body-limit.js";
import { createNodeDataStorage } from "../storage/node-data-storage.js";
import { createServerApiAuth } from "../api-auth.js";
import { createSchemaRegistrar } from "../schema-registrar.js";

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
  syncManager?: SyncManager | null;
  devToken?: string;
  accessToken?: string;
  tokenStore?: TokenStore;
  dataStorage?: DataStoragePort;
  runtimeAvailability?: RuntimeAvailabilityPort;
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
  });

  const schemaRegistrar =
    deps.serverSigner && deps.gatewayUrl
      ? createSchemaRegistrar({
          gatewayUrl: deps.gatewayUrl,
          signer: deps.serverSigner,
          logger: deps.logger,
        })
      : undefined;

  app.use("/:scope", createBodyLimit(DATA_INGEST_MAX_SIZE));
  app.all("*", (c) =>
    handlePersonalServerDataRequest(
      c.req.raw,
      {
        storage: dataStorage,
        auth,
        schemaResolver: deps.gateway,
        schemaRegistrar,
        accessLogWriter: deps.accessLogWriter,
        syncManager: deps.syncManager ?? null,
        runtimeAvailability: deps.runtimeAvailability,
        serverSigner: deps.serverSigner,
        serverOwner: deps.serverOwner,
        serverAddress: deps.serverAddress,
        gateway: deps.gateway,
        gatewayConfig: deps.gatewayConfig,
        gatewayUrl: deps.gatewayUrl,
        paymentEnabled: deps.paymentEnabled,
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
