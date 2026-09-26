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

import { createHash } from "node:crypto";
import type { Database } from "better-sqlite3";
import type { Logger } from "pino";
import type { DeclarationSnapshot } from "@opendatalabs/personal-server-ts-core/pdpp";
import {
  createSourceStreamDeclarationRegistry,
  type PdppRecordStore,
  type SourceStreamDeclarations,
  type StreamDeclaration,
  type StreamDeclarationRegistry,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import type {
  PdppAuthorizationService,
  Grant as PdppPortGrant,
} from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import {
  createPdppImporter,
  type PdppImporter,
  type RetainedDeclaration,
} from "@opendatalabs/personal-server-ts-core/sync";
import type { PdppAuthRouteDeps } from "../routes/pdpp-auth.js";
import { createSqliteRecordStore } from "../storage/pdpp-records-sqlite-store.js";
import { singleInstanceInventory } from "./deployment.js";

export interface PdppRecordsDeps {
  store: PdppRecordStore;
  bindingStore: ReturnType<typeof createSqliteRecordStore>;
  configuredMethods: Map<string, string[]>;
  auth: PdppAuthorizationService;
  declarations: StreamDeclarationRegistry;
  instancesForSubject?: (subjectId: string) => string[];
  readBlobBytes?: (
    blobId: string,
  ) => Promise<Uint8Array<ArrayBuffer> | undefined>;
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
  configuredMethods?: { sourceId: string; methodId: string }[];
}

export function createPdppRecordsDeps(
  options: CreatePdppRecordsDepsOptions,
): PdppRecordsDeps | undefined {
  const { pdppAuth, logger } = options;

  // No authorization server means no authority to enforce against.
  if (!pdppAuth || !options.serverOwner) return undefined;

  const subjectId = options.serverOwner.toLowerCase();

  // Every instance handle this deployment can produce, derived the same way
  // the AS derives them at issuance, so an owner read and a grant-bound read
  // agree about which instances exist. Each instance holds exactly one
  // source's records, so its streams are validated against that source's
  // declaration and no other.
  const sources: SourceStreamDeclarations[] = [];
  for (const snapshot of options.declarations) {
    const instance = singleInstanceInventory(
      subjectId,
      snapshot.source_id,
    ).eligibleFor("")[0];
    const claimant = sources.find((s) => s.instance === instance);
    if (claimant) {
      // Two source ids that derive one instance would write one set of
      // rows under two authorities. Keep the first and refuse the rest.
      logger.warn(
        {
          sourceId: snapshot.source_id,
          instance,
          claimedBy: claimant.sourceId,
        },
        "PDPP declaration shares an instance with another source — its streams are not mounted",
      );
      continue;
    }
    sources.push({
      sourceId: snapshot.source_id,
      instance,
      streams: toStreamDeclarations(snapshot),
    });
  }

  const streams = sources.flatMap((source) => source.streams);
  if (streams.length === 0) {
    logger.warn(
      "PDPP retained declarations define no streams — resource server not mounted",
    );
    return undefined;
  }
  const instances = sources.map((source) => source.instance);
  const configuredMethods = new Map<string, string[]>();
  for (const configured of options.configuredMethods ?? []) {
    const source = sources.find(
      (candidate) => candidate.sourceId === configured.sourceId,
    );
    if (!source) continue;
    const methodIds = configuredMethods.get(source.instance) ?? [];
    methodIds.push(configured.methodId);
    configuredMethods.set(source.instance, methodIds);
  }

  logger.info(
    { streams: streams.map((s) => s.name), resource: options.resource },
    "PDPP Resource Server mounted at /v1",
  );

  const store = createSqliteRecordStore(options.db);

  return {
    store,
    bindingStore: store,
    configuredMethods,
    auth: coLocatedAuthorizationService(pdppAuth),
    declarations: createSourceStreamDeclarationRegistry(sources),
    // This deployment has exactly one owner. A subject other than that
    // owner (however it got an "owner"-kind token) owns none of these
    // instances — comparison normalized the same way subjectId is derived
    // above (lowercased address), so casing never causes a false mismatch.
    instancesForSubject: (subject) =>
      subject.toLowerCase() === subjectId ? instances : [],
    // Real boot wiring for GET /v1/blobs/:blobId: reads the same store the
    // blob was ingested into, so this deployment can only ever serve bytes
    // it verifiably stored -- store.getBlobBytes re-verifies size/sha256
    // against the recorded metadata on every read (fails closed on
    // corruption or metadata-only rows) rather than trusting the disk blindly.
    readBlobBytes: async (blobId) => store.getBlobBytes(blobId),
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
        instanceIds: context.instanceIds,
        grant: context.grant as PdppPortGrant | undefined,
        clientId: context.clientId,
        expiresAt: context.expiresAt,
      };
    },
  };
}

/**
 * Build the sync importer that maps qualifying DataPipe envelopes into the
 * record store the RS reads from.
 *
 * Built from the SAME retained snapshots and the SAME instance derivation as
 * the RS above, for the same reason given at the top of this file: a record
 * imported under a different stream shape or a different instance handle than
 * the RS enforces against is a record no grant can correctly reach. One
 * retained declaration, one authority — on the write path too.
 *
 * The SQLite store refuses every write from this importer with
 * `method_required`: `$pdpp` metadata names no acquisition method or binding
 * generation, so P8a and P8c cannot be applied to it. The importer reports
 * that as a terminal `method_authority` rejection and does not retry it.
 *
 * Returns undefined when the RS did not mount. Importing into a store nothing
 * can read would be write-only work, and it would do it against declarations
 * this deployment has not accepted.
 */
export function createPdppSyncImporter(options: {
  records: PdppRecordsDeps | undefined;
  declarations: DeclarationSnapshot[];
  /** Exact retained bytes per source id, from the AS boot. */
  documents: Map<string, string>;
  serverOwner: `0x${string}` | undefined;
  logger: Logger;
}): PdppImporter | undefined {
  const { records, serverOwner, logger } = options;
  if (!records || !serverOwner) return undefined;

  const subjectId = serverOwner.toLowerCase();
  const retained: RetainedDeclaration[] = [];
  for (const snapshot of options.declarations) {
    const document = options.documents.get(snapshot.source_id);
    if (document === undefined) {
      // A snapshot with no retained document cannot have its digest
      // verified, and an unverifiable declaration must not be used as the
      // authority for accepting writes. Skipping it is fail-closed: its
      // envelopes are rejected as `unknown_source` rather than imported on
      // the strength of a check that never ran.
      logger.warn(
        { sourceId: snapshot.source_id },
        "PDPP declaration has no retained document — sync import disabled for this source",
      );
      continue;
    }
    retained.push({
      sourceId: snapshot.source_id,
      version: snapshot.version,
      // Digest the exact retained bytes once, here, because this is the only
      // place they exist and because the importer is bundled for the browser
      // lite runtime where `node:crypto` is unavailable.
      documentDigest: createHash("sha256")
        .update(document, "utf8")
        .digest("hex"),
      streams: toStreamDeclarations(snapshot).map((stream) => ({
        name: stream.name,
        primaryKey: stream.primaryKey,
        semantics: stream.semantics,
      })),
    });
  }

  if (retained.length === 0) return undefined;

  logger.info(
    { sources: retained.map((d) => d.sourceId) },
    "PDPP sync importer enabled for synced DataPipe envelopes",
  );

  return createPdppImporter({
    store: records.store,
    declarations: retained,
    instanceFor: (sourceId) =>
      singleInstanceInventory(subjectId, sourceId).eligibleFor("")[0],
    logger,
  });
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
    // From the declaration, defaulting to `mutable_state` when a declaration
    // omits it so documents written before the field existed keep their exact
    // meaning. Previously hardcoded, which silently coerced an `append_only`
    // stream into upsert behavior and left a producer's claim unfalsifiable.
    semantics: stream.semantics ?? ("mutable_state" as const),
    primaryKey: stream.primary_key,
    cursorField: "emitted_at",
    consentTimeField: stream.consent_time_field,
    requiredFields: stream.required_fields,
    // The declared member list, carried rather than dropped: it is what makes
    // a v0.2 grant's approved projection checkable against the snapshot the
    // grant was resolved from. Without it the RS would have to treat any
    // granted field as servable and answer from whatever a record happened to
    // carry.
    declaredFields: stream.fields,
    // §8 stream metadata reports both; carried from the retained declaration
    // rather than reconstructed, so what a client is told matches what the
    // owner consented against.
    ...(stream.schema && { schema: stream.schema }),
    ...(stream.selection && { selection: stream.selection }),
  }));
}
