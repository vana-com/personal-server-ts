import type { DataStoragePort } from "@opendatalabs/personal-server-ts-core/ports";
import type { ServerConfig } from "@opendatalabs/personal-server-ts-core/schemas";
import type { AccessLogReader } from "@opendatalabs/personal-server-ts-core/logging/access-reader";
import type { AccessLogWriter } from "@opendatalabs/personal-server-ts-core/logging/access-log";
import type {
  McpConnectionStore,
  McpOAuthAuthorizationStore,
} from "@opendatalabs/personal-server-ts-core/mcp";
import type { PsLiteRuntimeOptions, PsLiteTokenStore } from "./runtime.js";
import {
  loadOrCreatePsLiteConfig,
  savePsLiteConfig,
  type PsLiteStateStore,
} from "./state.js";
import type { PsLiteRelayTlsIdentityStore } from "./relay-tls.js";

/**
 * The complete set of PS Lite persistence ports, named as one composition
 * contract for a host (Mobile) that backs them all with a single durable store.
 *
 * This is a struct of the EXISTING narrow contracts — it deliberately does not
 * collapse them into one catch-all domain API. A host may implement each port
 * over one SQLite database, but PS Lite keeps addressing them by their narrow
 * responsibilities (data storage, key/value state, tokens, access logs, MCP
 * connection/authorization records, relay TLS identity).
 *
 * `relayTlsIdentity` is consumed by the relay TLS factory
 * (`createRustlsPsLiteRelayTlsFactory`), not the HTTP runtime. The start
 * factory forwards it to the relay automatically. A supplied bundle is all or
 * nothing: hosts must not accidentally combine native and browser persistence.
 */
export interface PsLitePersistenceBundle {
  /** Data envelopes + index metadata. */
  storage: DataStoragePort;
  /** Key/value runtime state: config, encrypted server identity, relay, cursor. */
  state: PsLiteStateStore;
  /** Session/device access tokens. */
  tokens: PsLiteTokenStore;
  /** Access-log read + write. */
  accessLog: AccessLogReader & AccessLogWriter;
  /** Per-connection MCP records (grantee key, token hash, grants). */
  mcpConnections: McpConnectionStore;
  /** In-flight MCP OAuth authorization records. */
  mcpOAuthAuthorizations: McpOAuthAuthorizationStore;
  /** Issued relay TLS identity cache. Consumed by the relay TLS factory. */
  relayTlsIdentity: PsLiteRelayTlsIdentityStore;
}

/**
 * The subset of {@link PsLiteRuntimeOptions} that a persistence bundle supplies.
 * Everything a caller still owns (auth, identity, gateway, signer, config
 * values, sync manager) stays out of the bundle.
 */
export type PsLitePersistenceRuntimeOptions = Pick<
  PsLiteRuntimeOptions,
  | "storage"
  | "tokenStore"
  | "accessLogReader"
  | "accessLogWriter"
  | "saveConfig"
  | "mcpConnectionStore"
  | "mcpOAuthAuthorizationStore"
> &
  Required<Pick<PsLiteRuntimeOptions, "config">>;

/**
 * Map a {@link PsLitePersistenceBundle} onto the runtime option subset it backs,
 * so a host can construct PS Lite with no direct browser storage dependency:
 *
 * ```ts
 * const runtime = createPsLiteRuntime({
 *   ...(await psLitePersistenceRuntimeOptions(bundle, configDefaults)),
 *   auth,
 *   identity,
 *   serverOwner,
 *   active: true,
 * });
 * ```
 *
 * `saveConfig` is derived from the injected state store via the existing
 * `savePsLiteConfig` contract, so config writes land in the host's store.
 */
export async function psLitePersistenceRuntimeOptions(
  bundle: PsLitePersistenceBundle,
  configDefaults?: Partial<ServerConfig>,
): Promise<PsLitePersistenceRuntimeOptions> {
  assertCompletePsLitePersistenceBundle(bundle);
  const config = await loadOrCreatePsLiteConfig(bundle.state, configDefaults);
  return {
    storage: bundle.storage,
    config,
    tokenStore: bundle.tokens,
    accessLogReader: bundle.accessLog,
    accessLogWriter: bundle.accessLog,
    saveConfig: async (nextConfig: unknown) => {
      const saved = await savePsLiteConfig(bundle.state, nextConfig);
      Object.assign(config, saved);
    },
    mcpConnectionStore: bundle.mcpConnections,
    mcpOAuthAuthorizationStore: bundle.mcpOAuthAuthorizations,
  };
}

/**
 * Defends the all-or-nothing bundle contract at the JavaScript boundary, where
 * TypeScript's required properties are not enforced.
 */
export function assertCompletePsLitePersistenceBundle(
  bundle: PsLitePersistenceBundle | null | undefined,
): void {
  if (!bundle || typeof bundle !== "object") {
    throw new Error("PS Lite persistence bundle must be a complete object");
  }
  const required: (keyof PsLitePersistenceBundle)[] = [
    "storage",
    "state",
    "tokens",
    "accessLog",
    "mcpConnections",
    "mcpOAuthAuthorizations",
    "relayTlsIdentity",
  ];
  const missing = required.filter((key) => bundle[key] == null);
  if (missing.length > 0) {
    throw new Error(
      `PS Lite persistence bundle must be complete; missing ${missing.join(", ")}`,
    );
  }
}
