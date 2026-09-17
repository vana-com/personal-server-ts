/**
 * Boot the PDPP Authorization Server for a real Personal Server.
 *
 * This is the seam between "the AS exists as a library" and "this running
 * server is a PDPP authorization server". It opens the persistent store,
 * derives the declaration trust policy from what the deployment actually
 * serves, and hands the route module the owner-proof wiring so consent
 * decisions authenticate against the same wallet signature every other owner
 * route uses.
 *
 * Returns undefined when PDPP is disabled or has nothing to serve, which
 * leaves `/pdpp/v1` unmounted. An authorization server with no retained
 * declarations can issue nothing useful, so mounting it would add surface
 * without adding capability.
 */

import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { Logger } from "pino";
import type { ServerConfig } from "@opendatalabs/personal-server-ts-core/schemas";
import type { IndexManager } from "@opendatalabs/personal-server-ts-core/storage/index";
import {
  AuthorizationSessionStore,
  openPdppAuthStore,
  PdppTokenService,
  UnsupportedAuthStateError,
} from "@opendatalabs/personal-server-ts-core/pdpp";
import type { PdppAuthRouteDeps } from "../routes/pdpp-auth.js";
import type { TokenStore } from "../token-store.js";
import {
  buildDeclarationRegistry,
  deriveSupportedConnectors,
  singleInstanceInventory,
  type ConfiguredDeclaration,
} from "./deployment.js";

export interface CreatePdppAuthDepsOptions {
  config: ServerConfig;
  storageRoot: string;
  logger: Logger;
  indexManager: IndexManager;
  serverOrigin: string | (() => string);
  serverOwner?: `0x${string}`;
  devToken?: string;
  accessToken?: string;
  tokenStore?: TokenStore;
}

export async function createPdppAuthDeps(
  options: CreatePdppAuthDepsOptions,
): Promise<PdppAuthRouteDeps | undefined> {
  const { config, logger } = options;
  if (!config.pdpp.enabled) return undefined;

  // The AS binds grants to a subject and authenticates decisions against the
  // server owner. Without a known owner there is no subject to bind to and no
  // signature to check, so refuse to mount rather than invent either.
  if (!options.serverOwner) {
    logger.warn(
      "PDPP enabled but no server owner is configured — authorization server not mounted",
    );
    return undefined;
  }

  // The connector inventory is what this PS actually holds, not a config
  // assertion. A declaration for a source with no data here is refused.
  const { scopes } = options.indexManager.listDistinctScopes();
  const supportedConnectors = deriveSupportedConnectors(
    scopes.map((s) => s.scope),
  );

  const declarations = await readDeclarations(
    config.pdpp.declarationPaths,
    logger,
  );
  const registry = buildDeclarationRegistry({
    declarations,
    supportedConnectors,
    logger,
  });

  if (registry.retained.length === 0) {
    logger.warn(
      { supportedConnectors, configured: config.pdpp.declarationPaths.length },
      "PDPP enabled but no declarations were retained — authorization server not mounted",
    );
    return undefined;
  }

  let store;
  try {
    store = openPdppAuthStore(join(options.storageRoot, "pdpp-auth.db"));
  } catch (err) {
    if (err instanceof UnsupportedAuthStateError) {
      // §9 AS item 21: persisted authorization state whose contract this build
      // cannot validate must not be reinterpreted. Refusing to mount is the
      // conservative half of "migrate or require fresh consent" — the server
      // keeps running, but it issues nothing against state it cannot read.
      logger.error(
        { err: err.message },
        "PDPP authorization state is unsupported — authorization server not mounted",
      );
      return undefined;
    }
    throw err;
  }

  const tokens = new PdppTokenService(store);
  const sessions = new AuthorizationSessionStore();
  const subjectId = options.serverOwner.toLowerCase();

  logger.info(
    {
      declarations: registry.retained.map((d) => d.source_id),
      supportedConnectors,
      requirePkce: config.pdpp.requirePkce,
    },
    "PDPP Authorization Server mounted at /pdpp/v1",
  );

  return {
    logger,
    store,
    tokens,
    sessions,
    resolveDeclaration: registry.resolve,
    inventoryFor: (subject, sourceId) =>
      singleInstanceInventory(subject || subjectId, sourceId),
    // This PS is single-owner: the authenticated owner is the only subject.
    // The owner-proof middleware below is what establishes that a caller is
    // that owner; this just names the subject grants bind to.
    currentSubjectId: () => subjectId,
    requirePkce: config.pdpp.requirePkce,
    ownerAuth: {
      serverOrigin: options.serverOrigin,
      serverOwner: options.serverOwner,
      devToken: options.devToken,
      accessToken: options.accessToken,
      tokenStore: options.tokenStore,
    },
    // The verified signer is the owner; normalize to the same subject the
    // grants use so a token minted here resolves sessions created above.
    ownerSubjectId: () => subjectId,
  };
}

/**
 * Read each configured declaration document.
 *
 * A path that cannot be read is logged and skipped rather than fatal: one
 * bad declaration should not stop a server booting, and the registry will
 * refuse to mount if nothing survives.
 */
async function readDeclarations(
  paths: string[],
  logger: Logger,
): Promise<ConfiguredDeclaration[]> {
  const out: ConfiguredDeclaration[] = [];
  for (const path of paths) {
    try {
      const document = await readFile(path, "utf-8");
      // The source_id is the declaration's own claim; `parseDeclaration`
      // cross-checks it, so read it here only to key the retention.
      const sourceId = (JSON.parse(document) as { source_id?: string })
        .source_id;
      if (typeof sourceId !== "string" || sourceId.length === 0) {
        logger.warn({ path }, "PDPP declaration has no source_id — skipped");
        continue;
      }
      out.push({ sourceId, document });
    } catch (err) {
      logger.warn(
        { path, err: (err as Error).message },
        "PDPP declaration could not be read — skipped",
      );
    }
  }
  return out;
}
