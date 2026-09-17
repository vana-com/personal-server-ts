import { Hono } from "hono";
import { PDPP_API_VERSION } from "@opendatalabs/personal-server-ts-core/pdpp";

/**
 * The negotiated PDPP API version, shared with the Authorization Server.
 *
 * Both halves mount into one app and both hard-reject an unrecognized value,
 * so a client that pins one version must be able to reach both. Importing the
 * AS's constant rather than restating a literal is what keeps that true: the
 * two surfaces previously diverged ("0.1.0" vs "2026-04-06"), and a client
 * pinning either could reach only half the server.
 */
const PDPP_VERSION = PDPP_API_VERSION;

export interface PdppWellKnownRouteDeps {
  /** This resource server's own identifier (RFC 9728 §2 `resource`). */
  resource: string;
  /** Base path §8 record endpoints extend from, e.g. "/v1". */
  coreQueryBase: string;
  /** Omit when the authorization-server set is not enumerable (RFC 9728 §2). */
  authorizationServers?: string[];
  resourceName?: string;
  selfExportSupported?: boolean;
}

export function pdppWellKnownRoutes(deps: PdppWellKnownRouteDeps): Hono {
  const app = new Hono();

  app.get("/oauth-protected-resource", (c) => {
    return c.json({
      resource: deps.resource,
      ...(deps.authorizationServers && {
        authorization_servers: deps.authorizationServers,
      }),
      ...(deps.resourceName && { resource_name: deps.resourceName }),
      pdpp_core_query_base: deps.coreQueryBase,
      pdpp_token_kinds_supported: ["owner", "client"],
      pdpp_self_export_supported: deps.selfExportSupported ?? true,
      pdpp_provider_connect_version: PDPP_VERSION,
    });
  });

  return app;
}
