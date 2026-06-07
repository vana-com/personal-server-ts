import { Hono } from "hono";
import {
  handlePersonalServerDataRequest,
  type PersonalServerApiDispatchOptions,
} from "@opendatalabs/personal-server-ts-core/api";
import type { HierarchyManagerOptions } from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import type { IndexManager } from "@opendatalabs/personal-server-ts-core/storage/index";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import type { AccessLogWriter } from "@opendatalabs/personal-server-ts-core/logging/access-log";
import type { SyncManager } from "@opendatalabs/personal-server-ts-core/sync";
import type {
  FeeVerifierPort,
  DataStoragePort,
  RuntimeAvailabilityPort,
} from "@opendatalabs/personal-server-ts-core/ports";
import type { TokenStore } from "../token-store.js";
import type { Logger } from "pino";
import {
  createBodyLimit,
  DATA_INGEST_MAX_SIZE,
} from "../middleware/body-limit.js";
import { createNodeDataStorage } from "../storage/node-data-storage.js";
import { createServerApiAuth } from "../api-auth.js";
import { createSchemaRegistrar } from "../schema-registrar.js";
import type { ServerSigner } from "@opendatalabs/personal-server-ts-core/signing";

export interface DataRouteDeps {
  indexManager: IndexManager;
  hierarchyOptions: HierarchyManagerOptions;
  logger: Logger;
  serverOrigin: string | (() => string);
  serverOwner?: `0x${string}`;
  gateway: GatewayClient;
  accessLogWriter: AccessLogWriter;
  syncManager?: SyncManager | null;
  devToken?: string;
  accessToken?: string;
  tokenStore?: TokenStore;
  feeVerifier?: FeeVerifierPort;
  dataStorage?: DataStoragePort;
  runtimeAvailability?: RuntimeAvailabilityPort;
  mountPath?: PersonalServerApiDispatchOptions["basePath"];
  /** Server signing account — enables binary schema auto-registration. */
  serverSigner?: ServerSigner;
  /** Gateway base URL, required (with serverSigner) for schema registration. */
  gatewayUrl?: string;
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
    feeVerifier: deps.feeVerifier,
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
        feeVerifier: deps.feeVerifier,
        logger: deps.logger,
      },
      { basePath: deps.mountPath },
    ),
  );

  return app;
}
