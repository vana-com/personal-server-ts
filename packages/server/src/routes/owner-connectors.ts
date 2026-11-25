/**
 * Owner connector routes (stream sync):
 *
 *   DELETE /v1/owner/connectors/:connectorId   delete one source's data
 *   GET    /v1/owner/connectors/:connectorId   the lifetime a delete of it would end
 *   DELETE /v1/owner/connectors/:connectorId/legacy   retire its legacy copy only
 *   GET    /v1/owner/connectors/:connectorId/legacy   what is left of that
 *
 * Only the owner may call it. The behaviour is `handleOwnerConnectorDelete`
 * in core, which the Lite runtime also answers, so both hosts share one rule.
 */

import { Hono } from "hono";
import {
  handleOwnerConnectorDelete,
  handleOwnerConnectorLifetime,
  handleOwnerLegacyRetire,
  handleOwnerLegacyRetireStatus,
  ownerConnectorRefusal,
  type ConnectionDeletePort,
  type StorageModeRead,
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
  /** The account's storage mode: one port for every route that depends on it. */
  mode: StorageModeRead;
  /**
   * Throws when the stream-sync services are shutting down. Called after owner
   * authorization, so a caller who is not the owner learns nothing of it.
   */
  assertAdmitting?: () => void;
}

/**
 * The connector segment decoded strictly; `null` for a malformed
 * percent-escape. `fromEnd` counts back from the last path segment (the
 * `/legacy` routes name the connector one before it).
 */
function decodeSegment(request: Request, fromEnd = 1): string | null {
  const segments = new URL(request.url).pathname.split("/");
  const segment = segments[segments.length - fromEnd] ?? "";
  try {
    return decodeURIComponent(segment);
  } catch {
    return null;
  }
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

  const handlerDeps = {
    authorizeOwner: async (request: Request) => {
      await auth.authorizeOwner(request);
      deps.assertAdmitting?.();
    },
    mode: deps.mode,
    owner: deps.serverOwner,
    connectionDelete: deps.connectionDelete,
  };
  app.delete("/:connectorId", (c) =>
    handleOwnerConnectorDelete(
      c.req.raw,
      decodeSegment(c.req.raw),
      handlerDeps,
    ),
  );
  app.get("/:connectorId", (c) =>
    handleOwnerConnectorLifetime(
      c.req.raw,
      decodeSegment(c.req.raw),
      handlerDeps,
    ),
  );
  app.delete("/:connectorId/legacy", (c) =>
    handleOwnerLegacyRetire(
      c.req.raw,
      decodeSegment(c.req.raw, 2),
      handlerDeps,
    ),
  );
  app.get("/:connectorId/legacy", (c) =>
    handleOwnerLegacyRetireStatus(
      c.req.raw,
      decodeSegment(c.req.raw, 2),
      handlerDeps,
    ),
  );
  app.all("/:connectorId/legacy", async (c) => {
    await auth.authorizeOwner(c.req.raw);
    return ownerConnectorRefusal(
      405,
      "METHOD_NOT_ALLOWED",
      "Method not allowed",
    );
  });
  // Any other method: the owner learns it is not allowed; a stranger learns
  // nothing (the same order as the Lite runtime).
  app.all("/:connectorId", async (c) => {
    await auth.authorizeOwner(c.req.raw);
    return ownerConnectorRefusal(
      405,
      "METHOD_NOT_ALLOWED",
      "Method not allowed",
    );
  });
  return app;
}
