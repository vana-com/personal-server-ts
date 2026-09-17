import { PdppError } from "../../errors/pdpp-catalog.js";
import {
  findStreamGrant,
  withinTimeConstraint,
  type PdppTokenContext,
  type StreamGrant,
} from "../../ports/pdpp-auth.js";
import {
  withRequiredFields,
  type StreamDeclaration,
} from "./stream-declaration.js";

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
}

export function resolveReadScope(
  context: PdppTokenContext,
  stream: string,
  declaration: StreamDeclaration | undefined,
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
    return { instanceIds: [], fields: undefined };
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

  return {
    instanceIds: streamGrant.instance_ids,
    fields: withRequiredFields(streamGrant.fields, declaration.requiredFields),
    streamGrant,
  };
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

function mapInactiveToError(context: PdppTokenContext): PdppError {
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
