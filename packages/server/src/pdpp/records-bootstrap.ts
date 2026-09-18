/**
 * Boot the PDPP Resource Server for a real Personal Server.
 *
 * `createPdppAuthDeps` makes a running server a PDPP *authorization* server.
 * This is its counterpart: without it a real deployment can issue a perfectly
 * valid grant-bound token that has nothing to read, and cannot even publish
 * the RFC 9728 metadata a client needs to discover where to authorize.
 *
 * Two deliberate choices about where things come from:
 *
 *   1. Stream declarations are derived from the SAME retained declaration
 *      snapshots the AS resolved grants against — not a second config list.
 *      A grant freezes a declaration version at consent time; if the RS read
 *      its stream shapes from somewhere else, the two could disagree about
 *      what a stream's primary key or required fields are, and enforcement
 *      would be measured against a different document than the one the owner
 *      consented to. One retained snapshot, one authority.
 *
 *   2. Token resolution is the co-located path: the RS resolves through the
 *      AS's own `PdppTokenService` in-process. Core §8 permits this for a
 *      co-located AS+RS, and it is the only correct option here because there
 *      is exactly one authority — introspecting over HTTP against ourselves
 *      would add a network hop and a second code path without adding a second
 *      opinion. A separated deployment is a different wiring, not this one.
 *
 * Returns undefined when the AS did not mount, which leaves the resource
 * surface unmounted too. An RS with no authorization server cannot enforce a
 * grant, and a resource server that cannot enforce is worse than absent.
 */

import type { Database } from "better-sqlite3";
import type { Logger } from "pino";
import type { DeclarationSnapshot } from "@opendatalabs/personal-server-ts-core/pdpp";
import {
  createStreamDeclarationRegistry,
  type PdppRecordStore,
  type StreamDeclaration,
  type StreamDeclarationRegistry,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import type {
  PdppAuthorizationService,
  Grant as PdppPortGrant,
} from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import type { PdppAuthRouteDeps } from "../routes/pdpp-auth.js";
import { createSqliteRecordStore } from "../storage/pdpp-records-sqlite-store.js";
import { singleInstanceInventory } from "./deployment.js";

export interface PdppRecordsDeps {
  store: PdppRecordStore;
  auth: PdppAuthorizationService;
  declarations: StreamDeclarationRegistry;
  instancesForSubject?: (subjectId: string) => string[];
  resource: string;
  authorizationServers?: string[];
}

export interface CreatePdppRecordsDepsOptions {
  /** The mounted AS, or undefined when it did not mount. */
  pdppAuth: PdppAuthRouteDeps | undefined;
  /** The retained snapshots the AS resolves grants against. */
  declarations: DeclarationSnapshot[];
  /** The server's own database; records live alongside the rest of its state. */
  db: Database;
  serverOwner: `0x${string}` | undefined;
  resource: string;
  logger: Logger;
}

export function createPdppRecordsDeps(
  options: CreatePdppRecordsDepsOptions,
): PdppRecordsDeps | undefined {
  const { pdppAuth, logger } = options;

  // No authorization server means no authority to enforce against.
  if (!pdppAuth || !options.serverOwner) return undefined;

  const streams = options.declarations.flatMap(toStreamDeclarations);
  if (streams.length === 0) {
    logger.warn(
      "PDPP retained declarations define no streams — resource server not mounted",
    );
    return undefined;
  }

  const subjectId = options.serverOwner.toLowerCase();

  // Every instance handle this deployment can produce, derived the same way
  // the AS derives them at issuance, so an owner read and a grant-bound read
  // agree about which instances exist.
  const instances = Array.from(
    new Set(
      options.declarations.map(
        (snapshot) =>
          singleInstanceInventory(subjectId, snapshot.source_id).eligibleFor(
            "",
          )[0],
      ),
    ),
  );

  logger.info(
    { streams: streams.map((s) => s.name), resource: options.resource },
    "PDPP Resource Server mounted at /v1",
  );

  return {
    store: createSqliteRecordStore(options.db),
    auth: coLocatedAuthorizationService(pdppAuth),
    declarations: createStreamDeclarationRegistry(streams),
    instancesForSubject: () => instances,
    resource: options.resource,
    // Co-located: this server is its own authorization server.
    authorizationServers: [options.resource],
  };
}

/**
 * Resolve tokens through the AS in-process.
 *
 * The AS's `resolveToken` is synchronous and marks `tokenKind`/`subjectId`
 * optional, because an inactive token carries neither (RFC 7662 §2.2). The
 * RS port is async and requires them, so this narrows explicitly rather than
 * casting: an inactive result must never yield an undefined subject that
 * flows onward into an authorization decision.
 */
function coLocatedAuthorizationService(
  pdppAuth: PdppAuthRouteDeps,
): PdppAuthorizationService {
  return {
    async resolveToken(accessToken: string) {
      const context = pdppAuth.tokens.resolveToken(accessToken);
      if (!context.active) {
        return {
          active: false as const,
          tokenKind: "client" as const,
          subjectId: "",
          inactiveReason: context.inactiveReason,
        };
      }
      return {
        active: true as const,
        tokenKind: context.tokenKind ?? "client",
        subjectId: context.subjectId ?? "",
        grant: context.grant as PdppPortGrant | undefined,
        clientId: context.clientId,
        expiresAt: context.expiresAt,
      };
    },
  };
}

/**
 * Project a retained declaration onto the per-stream shapes the RS enforces.
 *
 * `cursorField` falls back to `emitted_at` because that is what both record
 * store backends actually sort by; naming a declared field the store does not
 * order by would produce cursors that resume at the wrong place.
 */
function toStreamDeclarations(
  snapshot: DeclarationSnapshot,
): StreamDeclaration[] {
  return snapshot.streams.map((stream) => ({
    name: stream.name,
    semantics: "mutable_state" as const,
    primaryKey: stream.primary_key,
    cursorField: "emitted_at",
    consentTimeField: stream.consent_time_field,
    requiredFields: stream.required_fields,
    // §8 stream metadata reports both; carried from the retained declaration
    // rather than reconstructed, so what a client is told matches what the
    // owner consented against.
    ...(stream.schema && { schema: stream.schema }),
    ...(stream.selection && { selection: stream.selection }),
  }));
}
