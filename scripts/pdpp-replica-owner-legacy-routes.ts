/** Production legacy API mounted beside the existing replica authority. */
import { Hono } from "hono";
import { getAddress } from "viem";
import { statSync } from "node:fs";
import { join } from "node:path";
import assert from "node:assert/strict";
import type { DataPortabilityGatewayConfig } from "@opendatalabs/vana-sdk/node";
import type { DataStoragePort } from "@opendatalabs/personal-server-ts-core/ports";
import type { ServerSigner } from "@opendatalabs/personal-server-ts-core/signing";
import { withLegacyProjection } from "@opendatalabs/personal-server-ts-core/storage/legacy-projection";
import {
  dataRoutes,
  type DataRouteDeps,
} from "../packages/server/src/routes/data.js";
import { grantsRoutes } from "../packages/server/src/routes/grants.js";
import {
  createBodyLimit,
  DEFAULT_MAX_SIZE,
} from "../packages/server/src/middleware/body-limit.js";
import { initializeDatabase } from "../packages/server/src/storage/index-schema.js";
import { createIndexManager } from "../packages/server/src/storage/index-manager.js";
import { createNodeDataStorage } from "../packages/server/src/storage/node-data-storage.js";

/**
 * Normal file storage at A's existing root. A separate normal index avoids
 * migrating the receiver's runtime.db; no authority database is opened.
 * Empty storage stays empty until a normal ingest writes actual envelopes.
 * The caller owns close(), including when route composition fails.
 */
export function openReplicaOwnerLegacyStorage({ root }: { root: string }) {
  assert(statSync(root).isDirectory(), "Existing A root directory required");
  const db = initializeDatabase(join(root, "legacy-index.db"));
  try {
    const indexManager = createIndexManager(db);
    const hierarchyOptions = { dataDir: join(root, "data") };
    const rawDataStorage = createNodeDataStorage({
      indexManager,
      hierarchyOptions,
    });
    let closed = false;
    return {
      indexManager,
      hierarchyOptions,
      rawDataStorage,
      close() {
        if (closed) return;
        closed = true;
        indexManager.close();
      },
    };
  } catch (error) {
    db.close();
    throw error;
  }
}

export type ReplicaOwnerLegacyRouteDeps = Pick<
  DataRouteDeps,
  | "indexManager"
  | "hierarchyOptions"
  | "logger"
  | "serverOrigin"
  | "gateway"
  | "accessLogWriter"
  | "runtimeAvailability"
  | "syncManager"
  | "scopeDeletions"
  | "paymentEnabled"
  | "gatewayUrl"
  | "pdppImporter"
> & {
  serverOwner: `0x${string}`;
  serverSigner: ServerSigner;
  gatewayConfig: DataPortabilityGatewayConfig;
  /** A's real retained envelopes and index, never a canonical-row substitute. */
  rawDataStorage: DataStoragePort;
  /** Explicit public DCR builder address supplied by the parent. */
  granteeAddress: `0x${string}`;
};

/** Mount at `/`; all owner proof, grant policy and reads remain production-owned. */
export function createReplicaOwnerLegacyRoutes(
  deps: ReplicaOwnerLegacyRouteDeps,
): Hono {
  const granteeAddress = getAddress(deps.granteeAddress);
  const app = new Hono();
  app.use("*", async (c, next) => {
    if (
      c.req.method !== "POST" ||
      c.req.path.replace(/\/+$/, "") !== "/v1/grants"
    )
      return next();
    return createBodyLimit(DEFAULT_MAX_SIZE)(c, next);
  });
  app.use("*", async (c, next) => {
    if (
      c.req.method !== "POST" ||
      c.req.path.replace(/\/+$/, "") !== "/v1/grants"
    )
      return next();
    // Read a clone: production auth must verify the original signed bytes.
    const body = (await c.req.raw
      .clone()
      .json()
      .catch(() => null)) as { granteeAddress?: unknown } | null;
    if (
      typeof body?.granteeAddress === "string" &&
      body.granteeAddress.toLowerCase() !== granteeAddress.toLowerCase()
    ) {
      return c.json({ error: "DCR_GRANTEE_MISMATCH" }, 403);
    }
    await next();
  });
  app.route(
    "/v1/grants",
    grantsRoutes({
      logger: deps.logger,
      gateway: deps.gateway,
      gatewayConfig: deps.gatewayConfig,
      serverOwner: deps.serverOwner,
      serverOrigin: deps.serverOrigin,
      serverSigner: deps.serverSigner,
      mountPath: "/v1/grants",
    }),
  );
  app.route(
    "/v1/data",
    dataRoutes({
      ...deps,
      dataStorage: withLegacyProjection(deps.rawDataStorage),
      serverAddress: deps.serverSigner.address,
      mountPath: "/v1/data",
    }),
  );
  return app;
}
