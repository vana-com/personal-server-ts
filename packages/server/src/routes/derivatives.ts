/**
 * Derivative compute routes: /v1/derivatives/questions. Thin Hono wrapper
 * over the runtime-agnostic core handler; builder auth is the Write API's
 * (write-session token + signed proof), owner auth is the usual owner gate.
 */

import { Hono } from "hono";
import type { Logger } from "pino";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import {
  handlePersonalServerDerivativesRequest,
  MAX_QUESTION_BODY_BYTES,
  type PersonalServerDerivativesApiDeps,
} from "@opendatalabs/personal-server-ts-core/derivatives";
import type { PersonalServerApiDispatchOptions } from "@opendatalabs/personal-server-ts-core/api";
import type {
  DataStoragePort,
  RuntimeAvailabilityPort,
} from "@opendatalabs/personal-server-ts-core/ports";
import type {
  WriteProofReplayStore,
  WriteSessionStore,
} from "@opendatalabs/personal-server-ts-core/write";
import type { TokenStore } from "../token-store.js";
import { createBodyLimit } from "../middleware/body-limit.js";
import { createServerApiAuth } from "../api-auth.js";

export interface DerivativesRouteDeps {
  logger: Logger;
  serverOrigin: string | (() => string);
  serverOwner?: `0x${string}`;
  gateway: GatewayClient;
  devToken?: string;
  accessToken?: string;
  tokenStore?: TokenStore;
  dataStorage?: DataStoragePort;
  runtimeAvailability?: RuntimeAvailabilityPort;
  /** Shared with the data routes so builder tokens work on both. */
  writeSessionStore?: WriteSessionStore;
  writeProofReplayStore?: WriteProofReplayStore;
  /** The compute layer (store + scheduler). Absent = every route answers 503. */
  compute?: PersonalServerDerivativesApiDeps["compute"];
  now?: () => Date;
  mountPath?: PersonalServerApiDispatchOptions["basePath"];
}

export function derivativesRoutes(deps: DerivativesRouteDeps): Hono {
  const app = new Hono();
  const auth = createServerApiAuth({
    serverOrigin: deps.serverOrigin,
    serverOwner: deps.serverOwner,
    gateway: deps.gateway,
    devToken: deps.devToken,
    accessToken: deps.accessToken,
    tokenStore: deps.tokenStore,
    dataStorage: deps.dataStorage,
    runtimeAvailability: deps.runtimeAvailability,
    writeSessionStore: deps.writeSessionStore,
    writeProofReplayStore: deps.writeProofReplayStore,
  });

  app.use("*", createBodyLimit(MAX_QUESTION_BODY_BYTES));
  app.all("*", (c) =>
    handlePersonalServerDerivativesRequest(
      c.req.raw,
      {
        auth,
        compute: deps.compute ?? null,
        now: deps.now,
        logger: deps.logger,
      },
      { basePath: deps.mountPath },
    ),
  );
  return app;
}
