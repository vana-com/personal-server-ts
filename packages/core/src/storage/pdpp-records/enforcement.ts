import { grantIsCandidate } from "../../pdpp/types.js";
import { PdppError } from "../../errors/pdpp-catalog.js";
import {
  type PdppAuthorizationService,
  findStreamGrant,
  grantIsV02,
  withinTimeConstraint,
  type PdppTokenContext,
  type StreamGrant,
} from "../../ports/pdpp-auth.js";
import type { StreamDeclaration } from "./stream-declaration.js";
import {
  evidenceTime,
  remoteEvidence,
  type DeliveryLease,
  type EvidenceTime,
} from "../../policy/delivery-lease.js";

/**
 * Resolves a request-time authorization context to the effective read
 * parameters this lane's PdppRecordStore calls need — `instanceIds`,
 * `fields` — and validates the request against the grant/subject scope. This
 * is the single narrow chokepoint every §8 read endpoint calls through, so
 * enforcement logic (and any future grant-shape change) lives in one place.
 *
 * Throws PdppError for every documented spec §8 failure mode. Never returns
 * a widened scope: on ambiguity, the narrower (deny) reading wins.
 */
export interface ResolvedReadScope {
  instanceIds: string[];
  fields?: string[];
  streamGrant?: StreamGrant; // undefined for owner tokens (no grant)
  /** Core v0.1 sparse-read floor, capped by the frozen grant fields. */
  schemaRequiredFloor: boolean;
}

export function resolveReadScope(
  context: PdppTokenContext,
  stream: string,
  declaration: StreamDeclaration | undefined,
  requestedFields?: string[],
): ResolvedReadScope {
  if (!context.active) {
    throw mapInactiveToError(context);
  }

  if (!declaration) {
    throw new PdppError("not_found", `Stream '${stream}' not found`);
  }

  if (context.tokenKind === "owner") {
    // Owner tokens carry no grant: full current-capability read, but still
    // scoped to the owner's own subject — enforced by the caller passing
    // only that subject's instance_ids into the store query, which for the
    // owner-token case is "every instance belonging to subjectId". This
    // module doesn't own instance-to-subject resolution (that's the RS
    // route layer's data-store lookup); it returns `undefined` fields (no
    // projection restriction) since an owner token has no grant field list.
    // An owner token has no grant and so no projection to floor: the owner
    // reads their own records whole.
    return {
      instanceIds: [],
      fields: requestedFields,
      schemaRequiredFloor: false,
    };
  }

  // Client token: requires an active resolved grant.
  if (!context.grant) {
    throw new PdppError("grant_invalid", "Client token has no resolved grant");
  }

  const streamGrant = findStreamGrant(context.grant, stream);
  if (!streamGrant) {
    throw new PdppError(
      "grant_stream_not_allowed",
      `Grant does not include stream '${stream}'`,
    );
  }

  if (
    streamGrant.fields.length === 0 ||
    streamGrant.instance_ids.length === 0
  ) {
    // Per the AS contract: "If the RS finds ... an empty `fields`, or an
    // empty `instance_ids`, that is an AS bug — fail closed."
    throw new PdppError(
      "grant_invalid",
      "Resolved grant is malformed (empty fields or instance_ids)",
    );
  }

  if (
    grantIsCandidate(context.grant) &&
    streamGrant.time_constraint &&
    !["date", "date-time"].includes(streamGrant.time_constraint.type ?? "")
  ) {
    throw new PdppError(
      "grant_invalid",
      "Candidate time constraint has no valid frozen type",
    );
  }

  // Issuance resolves required fields into grant.fields. A later declaration
  // never adds authority. The current v0.1 sparse-read floor is restricted to
  // fields the grant already carries; private v0.2 selects exactly. The
  // candidate freezes its floor in the grant itself.
  const schemaRequiredFloor = !grantIsV02(context.grant);
  let requiredFloor = declaration.requiredFields ?? [];
  if (grantIsCandidate(context.grant)) {
    const frozen = streamGrant.required_fields;
    if (
      !Array.isArray(frozen) ||
      frozen.some((f) => !streamGrant.fields.includes(f))
    ) {
      throw new PdppError(
        "grant_invalid",
        "Candidate grant has no frozen required-field floor within its fields",
      );
    }
    requiredFloor = frozen;
  }

  // v0.2 only: can this RS actually serve the projection the grant approved?
  //
  // The retained declaration is the RS's only authority for what a record of
  // this stream means. A granted member the declaration does not declare has
  // no meaning the RS can stand behind: omitting it asserts "no such value"
  // (unknown), nulling it is forbidden outright by `v0.2-4-3`, and serving
  // whatever the record carries under that key discloses an undeclared member
  // — which is repairing the projection with unauthorized data.
  //
  // So refuse, with the code the spec reserves for exactly this. The
  // distinction from `grant_invalid` is the client's remedy: the grant is
  // well-formed and this RS cannot serve it, so the answer is to reauthorize
  // against the current declaration, not to treat the grant as corrupt.
  //
  // Checked here rather than at each endpoint because all three client read
  // surfaces (list, single record, stream metadata) resolve through this
  // function, and a refusal one of them forgot would be a surface that
  // discloses what the other two refuse.
  if (grantIsV02(context.grant) && declaration.declaredFields) {
    const declared = new Set(declaration.declaredFields);
    const undeclared = streamGrant.fields.filter((f) => !declared.has(f));
    if (undeclared.length > 0) {
      throw new PdppError(
        "disclosure_unavailable",
        `Grant authorizes ${undeclared.join(", ")} on stream '${stream}', which the retained declaration does not declare; the projection cannot be served without disclosing an undeclared member`,
      );
    }
  }

  return {
    instanceIds: streamGrant.instance_ids,
    fields: resolveReadFields(
      requestedFields,
      streamGrant.fields,
      schemaRequiredFloor ? requiredFloor : [],
    ),
    streamGrant,
    schemaRequiredFloor,
  };
}

/** Selection policy shared by list, detail, sync, metadata and blob reads. */
function resolveReadFields(
  requested: string[] | undefined,
  granted: string[],
  requiredFloor: string[],
): string[] {
  const allowed = [...granted];
  if (!requested || requested.length === 0) return allowed;
  for (const field of requested) {
    if (!allowed.includes(field)) {
      throw new PdppError(
        "invalid_request",
        `Field '${field}' is not in this grant's authorized fields for the stream`,
        { param: "fields" },
      );
    }
  }
  const floor = requiredFloor.filter((field) => granted.includes(field));
  return [...new Set([...requested, ...floor])];
}

/**
 * Validates that a record's time field satisfies the grant's frozen
 * time_constraint, if any. Callers filter store results through this before
 * returning them (the store itself is time_constraint-agnostic).
 */
export function recordWithinGrantTimeConstraint(
  data: Record<string, unknown>,
  streamGrant: StreamGrant | undefined,
): boolean {
  if (!streamGrant?.time_constraint) return true;
  const value = data[streamGrant.time_constraint.field];
  return withinTimeConstraint(
    typeof value === "string" ? value : undefined,
    streamGrant.time_constraint,
  );
}

/** Validates a canonical record_key is within the grant's `resources` allowlist, if constrained. */
export function recordKeyWithinGrantResources(
  recordKey: string,
  streamGrant: StreamGrant | undefined,
): boolean {
  if (!streamGrant?.resources) return true; // absent = all records
  return streamGrant.resources.includes(recordKey);
}

/**
 * The PdppError an inactive token maps to.
 *
 * Exported so every route answers an inactive token with the SAME reason.
 * `/v1/streams` previously inlined a flat `authentication_error` while record
 * reads used this mapping, so one revoked grant produced a 401 on one endpoint
 * and a 403 `grant_revoked` on another.
 */
export function mapInactiveToError(context: PdppTokenContext): PdppError {
  switch (context.inactiveReason) {
    case "grant_revoked":
      return new PdppError("grant_revoked", "Grant has been revoked");
    case "grant_expired":
      return new PdppError("grant_expired", "Grant has expired");
    case "expired":
    case "revoked":
    case "unknown":
    default:
      return new PdppError(
        "authentication_error",
        "Missing or invalid access token",
      );
  }
}

/** What the chain said about a PDPP grant's permission, carried by the lease. */
export interface PdppChainEvidence {
  /** The permission's expiry (ISO 8601); absent or null when it has none. */
  expiresAt?: string | null;
}

/**
 * A bearer as admitted: the token, what it resolved to, and when the
 * resolution started. The time is part of the admission because a remote
 * AS's answer is as old as the moment its introspection started; a lease
 * built from an admission cannot date it later.
 */
export interface BearerAdmission {
  readonly token: string;
  readonly context: PdppTokenContext;
  readonly resolvedAt: EvidenceTime;
}

/** Resolve a bearer, dated before the resolution is awaited. */
export async function admitBearer(
  auth: Pick<PdppAuthorizationService, "resolveToken">,
  token: string,
): Promise<BearerAdmission> {
  const resolvedAt = evidenceTime();
  const context = await auth.resolveToken(token);
  return { token, context, resolvedAt };
}

/**
 * The connections a read result was selected from, as a release dependency:
 * once any of them is unavailable (deleted or unbound), the release refuses
 * with `instance_unavailable`. A selection holds exactly the connections it
 * used; an aggregate (stream discovery) holds all of its own.
 */
export function connectionsLease(
  instanceIds: readonly string[],
  isConnectionAvailable: ((instance: string) => boolean) | undefined,
): DeliveryLease {
  const held = [...new Set(instanceIds)];
  return {
    evidence: () => [],
    assertLocal() {
      for (const instance of held) {
        if (isConnectionAvailable?.(instance) === false) {
          throw new PdppError(
            "instance_unavailable",
            "The connection for this grant is unavailable",
          );
        }
      }
    },
  };
}

/**
 * The bearer half of a PDPP read's release dependencies (records, metadata,
 * discovery and blobs). See `policy/delivery-lease.ts` for the release rule.
 * What the read selected (its connections) is a separate dependency, produced
 * by the selection (`connectionsLease`).
 *
 * Remote evidence: the chain permission, when the deployment enforces one
 * (its answer carries the permission's expiry); and, for a remote AS, its
 * introspection answer. Each is dated from when its check started
 * (`verifiedAt`), and `deliver` asks it again once it is older than
 * `REMOTE_GRANT_REVERIFY_AFTER_MS` (30 s).
 *
 * Local checks, synchronous, at release: the bearer resolved again (a local
 * AS through `resolveTokenNow`, which reports a revoked or expired grant, a
 * revoked or expired token, and a revoked refresh family; a remote AS's last
 * answer); the same grant the read was admitted under; and every carried
 * token, PDPP grant and chain deadline. Malformed deadlines fail closed.
 */
export function pdppBearerReadLease(
  auth: PdppAuthorizationService,
  admission: BearerAdmission,
  options: {
    chain?: {
      admitted: PdppChainEvidence;
      reverify: () => Promise<PdppChainEvidence>;
      verifiedAt?: EvidenceTime;
    };
  } = {},
): DeliveryLease {
  if (auth.locality !== "local" && auth.locality !== "remote") {
    // Fail closed: the lease cannot know how to re-check this bearer.
    throw new PdppError(
      "api_error",
      "The PDPP authorization server's locality is not declared",
    );
  }
  const { token, context: admitted, resolvedAt } = admission;
  const grantId = admitted.grant?.grant_id;
  const chain = options.chain
    ? remoteEvidence(options.chain.admitted, options.chain.reverify, {
        ...(options.chain.verifiedAt && {
          verifiedAt: options.chain.verifiedAt,
        }),
      })
    : undefined;
  const remoteAs =
    auth.locality === "remote"
      ? remoteEvidence(admitted, () => auth.resolveToken(token), {
          verifiedAt: resolvedAt,
        })
      : undefined;
  const evidence = [chain, remoteAs].filter(
    (piece): piece is NonNullable<typeof piece> => piece !== undefined,
  );
  return {
    evidence: () => evidence,
    assertLocal() {
      const current =
        auth.locality === "local"
          ? auth.resolveTokenNow(token)
          : remoteAs!.current;
      if (!current.active) throw mapInactiveToError(current);
      if (current.grant?.grant_id !== grantId) {
        throw mapInactiveToError({ active: false, inactiveReason: "unknown" });
      }
      const now = Date.now();
      if (
        current.expiresAt !== undefined &&
        !liveDeadline(current.expiresAt, now)
      ) {
        throw mapInactiveToError({ active: false, inactiveReason: "expired" });
      }
      const grantExpiry = current.grant?.expires_at;
      if (grantExpiry !== undefined && !liveDeadline(grantExpiry, now)) {
        throw mapInactiveToError({
          active: false,
          inactiveReason: "grant_expired",
        });
      }
      const chainExpiry = chain?.current.expiresAt;
      if (
        chainExpiry !== undefined &&
        chainExpiry !== null &&
        !liveDeadline(chainExpiry, now)
      ) {
        throw new PdppError("grant_expired", "Chain permission has expired");
      }
    },
  };
}

/** A carried deadline is authority, even before remote evidence ages out. */
function liveDeadline(deadline: string, now: number): boolean {
  const at = Date.parse(deadline);
  return Number.isFinite(at) && at > now;
}
