/**
 * Owner connector routes (stream sync):
 *
 *   DELETE /v1/owner/connectors/:connectorId   delete one source's data
 *
 * Only the owner may call it. The behaviour is `handleOwnerConnectorDelete`
 * in core, which the Lite runtime also answers, so both hosts share one rule.
 */

import { Hono } from "hono";
import {
  handleOwnerConnectorDelete,
  type ConnectionDeletePort,
  type LegacyWriteSwitch,
} from "@opendatalabs/personal-server-ts-core/api";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import type { TokenStore } from "../token-store.js";
import { createServerApiAuth } from "../api-auth.js";

export interface OwnerConnectorsRouteDeps {
  serverOrigin: string | (() => string);
  serverOwner?: `0x${string}`;
  gateway: GatewayClient;
  devToken?: string;
  accessToken?: string;
  tokenStore?: TokenStore;
  /** The stream-sync writer. Absent = the route answers 503. */
  connectionDelete?: ConnectionDeletePort | null;
  /** The account's stream-sync switch, the one the legacy write gate reads. */
  switched: LegacyWriteSwitch;
}

export function ownerConnectorsRoutes(deps: OwnerConnectorsRouteDeps): Hono {
  const app = new Hono();
  const auth = createServerApiAuth({
    serverOrigin: deps.serverOrigin,
    serverOwner: deps.serverOwner,
    gateway: deps.gateway,
    devToken: deps.devToken,
    accessToken: deps.accessToken,
    tokenStore: deps.tokenStore,
  });

  app.delete("/:connectorId", (c) =>
    handleOwnerConnectorDelete(c.req.raw, c.req.param("connectorId"), {
      authorizeOwner: (request) => auth.authorizeOwner(request),
      switched: deps.switched,
      connectionDelete: deps.connectionDelete,
    }),
  );
  return app;
}
