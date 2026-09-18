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
import type { DeclarationSnapshot } from "@opendatalabs/personal-server-ts-core/pdpp";
import {
  AuthorizationSessionStore,
  declaredSourceId,
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

/**
 * The mounted AS plus the snapshots it retained.
 *
 * The Resource Server derives its per-stream shapes from these exact
 * snapshots rather than re-reading config, so both halves enforce against the
 * same retained document a grant was frozen against.
 */
export type PdppAuthBootResult = PdppAuthRouteDeps & {
  retainedDeclarations: DeclarationSnapshot[];
  /**
   * The exact documents behind `retainedDeclarations`, keyed by source id.
   *
   * The sync importer verifies a producer's claimed declaration digest, and
   * the only honest thing to digest is the bytes that were actually
   * retrieved. The auth store persists a parsed snapshot rather than the
   * document, so re-digesting from storage would compare a re-serialization
   * against a digest taken over the original — a check that can fail for
   * formatting alone and proves nothing about what the producer read. These
   * are those original bytes, carried forward from boot.
   */
  retainedDocuments: Map<string, string>;
};

export async function createPdppAuthDeps(
  options: CreatePdppAuthDepsOptions,
): Promise<PdppAuthBootResult | undefined> {
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
    retainedDeclarations: registry.retained,
    retainedDocuments: registry.retainedDocuments,
    resolveDeclaration: registry.resolve,
    inventoryFor: (subject, sourceId) =>
      singleInstanceInventory(subject || subjectId, sourceId),
    /**
     * Bind the session's subject to an *authenticated* owner.
     *
     * This PS is single-owner, so there is only ever one subject — but "there
     * is one subject" and "any caller may open a session bound to it" are
     * different claims, and the second is the one that was wrong. Previously
     * this ignored the request entirely and returned the configured owner, so
     * an unauthenticated caller could create sessions against the owner's
     * subject: consent-screen spam and unbounded session allocation, even
     * though approval still required a real owner token.
     *
     * Now the caller must present an active PDPP owner token, and the subject
     * it resolves to must be the configured owner. Single-owner stays a
     * deployment property; it stops being an authentication bypass.
     */
    currentSubjectId: (c) => {
      const header = c.req.header("authorization");
      if (!header?.toLowerCase().startsWith("bearer ")) return null;
      const presented = header.slice(7).trim();
      if (presented.length === 0) return null;

      const context = tokens.resolveToken(presented);
      if (!context.active || context.tokenKind !== "owner") return null;
      // A token for some other subject is not authority here, even though a
      // single-owner deployment should never mint one.
      if (context.subjectId !== subjectId) return null;
      return subjectId;
    },
    // Redirect targets are validated by exact match against this. A client
    // absent from the config gets null, which fails the request closed — an
    // unregistered client cannot receive an authorization code.
    registeredClient: (clientId) => {
      const registered = config.pdpp.clients.find(
        (candidate) => candidate.clientId === clientId,
      );
      return registered
        ? {
            client_id: registered.clientId,
            redirect_uris: registered.redirectUris,
          }
        : null;
    },
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
      // The source id is the declaration's own claim; `parseDeclaration`
      // cross-checks it, so read it here only to key the retention.
      //
      // Asking Core for the id rather than picking a field keeps the boot path
      // shape-agnostic. Reading `source_id` directly meant a normative §5
      // document -- which nests it under `source.id` -- was skipped here before
      // the parser (which handles both) ever saw it, so the AS never mounted
      // and the only evidence was a warning about a missing field the document
      // was never supposed to have.
      const sourceId = declaredSourceId(document);
      if (sourceId === null) {
        logger.warn(
          { path },
          "PDPP declaration declares no source id — skipped",
        );
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
