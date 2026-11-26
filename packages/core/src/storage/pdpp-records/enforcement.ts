import { grantUsesLockedRules } from "../../pdpp/types.js";
import { PdppError } from "../../errors/pdpp-catalog.js";
import {
  findStreamGrant,
  grantIsV02,
  withinTimeConstraint,
  type PdppTokenContext,
  type StreamGrant,
} from "../../ports/pdpp-auth.js";
import type { StreamDeclaration } from "./stream-declaration.js";

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
  /**
   * The current declaration, or a lookup for it. A client read resolves the
   * lookup only after its grant checks pass, so a `fields` request outside
   * the grant is refused before any source-schema lookup (spec-core §4
   * "Effective projection"; §9 RS item 32).
   */
  declarationOrLookup:
    | StreamDeclaration
    | undefined
    | (() => StreamDeclaration | undefined),
  requestedFields?: string[],
): ResolvedReadScope {
  if (!context.active) {
    throw mapInactiveToError(context);
  }
  const lookup = () =>
    typeof declarationOrLookup === "function"
      ? declarationOrLookup()
      : declarationOrLookup;

  if (context.tokenKind === "owner") {
    if (!lookup()) {
      throw new PdppError("not_found", `Stream '${stream}' not found`);
    }
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
    grantUsesLockedRules(context.grant) &&
    streamGrant.time_constraint &&
    !["date", "date-time"].includes(streamGrant.time_constraint.type ?? "")
  ) {
    throw new PdppError(
      "grant_invalid",
      "Candidate time constraint has no valid frozen type",
    );
  }

  // spec-core §4 "Effective projection": "If Q is not a subset of G, the RS
  // MUST reject the whole read with HTTP 403 `field_not_granted` before any
  // source-schema or record-data lookup." The grant and stream are resolved
  // above; the declaration is looked up only after this check (RS 31, 32).
  if (requestedFields && requestedFields.length > 0) {
    const ungranted = [
      ...new Set(requestedFields.filter((f) => !streamGrant.fields.includes(f))),
    ];
    if (ungranted.length > 0) {
      throw new PdppError(
        "field_not_granted",
        `Fields not granted for stream '${stream}': ${ungranted.join(", ")}`,
        { param: "fields" },
      );
    }
  }

  const declaration = lookup();
  if (!declaration) {
    throw new PdppError("not_found", `Stream '${stream}' not found`);
  }

  // Issuance resolves required fields into grant.fields. A later declaration
  // never adds authority. The current v0.1 sparse-read floor is restricted to
  // fields the grant already carries; private v0.2 selects exactly. The
  // candidate freezes its floor in the grant itself.
  const schemaRequiredFloor = !grantIsV02(context.grant);
  let requiredFloor = declaration.requiredFields ?? [];
  if (grantUsesLockedRules(context.grant)) {
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
  // `resolveReadScope` refused every requested name outside the grant before
  // the declaration lookup (field_not_granted); none reaches here.
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
 * and a 401 `grant_revoked` on another.
 */
export function mapInactiveToError(context: PdppTokenContext): PdppError {
  switch (context.inactiveReason) {
    case "grant_revoked":
      return new PdppError("grant_revoked", "Grant has been revoked");
    case "grant_expired":
      return new PdppError("grant_expired", "Grant has expired");
    case "unsupported_legacy_shape":
      return new PdppError(
        "authorization_state.unsupported_legacy_shape",
        "This grant was issued under rules that predate PDPP Core v0.1.0; fresh consent is required",
      );
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
