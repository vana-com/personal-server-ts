/**
 * In-process MCP read client.
 *
 * The MCP route accepts a tool call from Claude, then needs to read scoped data
 * from the user's Personal Server *as the per-connection grantee*. We do NOT
 * round-trip through the public HTTP origin for this — the relay/tunnel is
 * only for inbound Claude traffic. Instead we:
 *
 *  1. Build a Web Request signed by the connection's grantee, with the
 *     existing grantId in the Web3Signed payload.
 *  2. Hand it to `handlePersonalServerDataRequest` directly.
 *
 * This guarantees parity: the MCP read goes through the same policy check
 * (`verifyDataReadPolicy`) and access-log path as an external builder read.
 * No special owner-mode code path; no shared global grantee; logs record the
 * per-connection grantee address.
 */

import type { ServerAccount } from "../keys/server-account.js";
import { signMcpGranteeRequest } from "./grantee.js";
import {
  handlePersonalServerDataRequest,
  type PersonalServerDataApiDeps,
} from "../api/index.js";

export interface McpDataReadClient {
  /**
   * Perform `GET /v1/data/:scope?grantId=…` as the connection grantee and
   * return the parsed response body. Throws `McpDataReadError` if the read
   * fails for any reason (no matching grant, scope not covered, runtime
   * unavailable, …) — the caller turns this into an MCP `isError` result.
   */
  readScope(params: {
    scope: string;
    grantId: string;
    limit?: number;
  }): Promise<McpDataReadResult>;
}

export interface McpDataReadResult {
  status: number;
  body: unknown;
}

export class McpDataReadError extends Error {
  constructor(
    public status: number,
    public body: unknown,
  ) {
    super(
      typeof body === "object" && body !== null && "error" in body
        ? String(
            (body as { error?: { message?: string } }).error?.message ??
              `mcp data read failed (status ${status})`,
          )
        : `mcp data read failed (status ${status})`,
    );
  }
}

export interface CreateMcpDataReadClientOptions {
  /**
   * Origin the Web3Signed payload's `aud` claim is bound to. This MUST match
   * the `serverOrigin` configured on the data API auth port — otherwise the
   * signature audience check will fail.
   */
  serverOrigin: string;
  granteeAccount: ServerAccount;
  /**
   * The data API deps used to mount `/v1/data` for external traffic. We reuse
   * the exact same handler + ports so policy and access-logging are identical.
   */
  dataApiDeps: PersonalServerDataApiDeps;
  /**
   * Base path the data API was mounted under externally — required so the
   * Web3Signed signature URI matches what `handlePersonalServerDataRequest`
   * expects after strip-base-path. Defaults to `/v1/data`.
   */
  basePath?: string;
}

export function createMcpDataReadClient(
  options: CreateMcpDataReadClientOptions,
): McpDataReadClient {
  const basePath = options.basePath ?? "/v1/data";

  return {
    async readScope({ scope, grantId, limit }) {
      const safeScope = encodeURIComponent(scope);
      const query = limit !== undefined ? `?limit=${limit}` : "";
      const pathWithQuery = `${basePath}/${safeScope}${query}`;
      // The data-API auth verifier checks `payload.uri === url.pathname` on the
      // incoming Request — pathname has no query string, so sign the path only.
      const signingUri = `${basePath}/${safeScope}`;

      const authorization = await signMcpGranteeRequest({
        account: options.granteeAccount,
        aud: options.serverOrigin,
        method: "GET",
        uri: signingUri,
        grantId,
      });

      const url = new URL(pathWithQuery, options.serverOrigin).toString();
      const request = new Request(url, {
        method: "GET",
        headers: { Authorization: authorization },
      });

      const response = await handlePersonalServerDataRequest(
        request,
        options.dataApiDeps,
        { basePath },
      );

      const text = await response.text();
      let body: unknown;
      try {
        body = text ? JSON.parse(text) : null;
      } catch {
        body = text;
      }

      if (!response.ok) {
        throw new McpDataReadError(response.status, body);
      }

      return { status: response.status, body };
    },
  };
}
