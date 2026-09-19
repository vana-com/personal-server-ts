/**
 * PDPP Core §6 selection-request validation.
 *
 * This is the shape gate that runs before consent. It answers one question:
 * is this request expressible against the retained declaration snapshot? It
 * does not resolve anything — `resolve.ts` does that, and only against the
 * same snapshot this module validated against.
 *
 * "Fails neutrally" in §6 means the both/neither `streams`/`selection_preset`
 * failure is a Source validation failure the binding maps to an error code; it
 * must not leak which of the two the client got wrong, and it must not depend
 * on any owner-specific state. We return a binding-neutral failure and let the
 * OAuth/RAR layer map it to RFC 9396 `invalid_authorization_details`.
 */

import {
  PDPP_DATA_ACCESS_TYPE,
  PDPP_DATA_ACCESS_TYPE_V02,
  type DeclarationSnapshot,
  type DeclaredStream,
  type SelectionRequest,
  type StreamRequest,
} from "./types.js";

/**
 * Binding-neutral validation failure codes. The OAuth/RAR binding maps these
 * to wire errors in `../../../server/src/routes/pdpp-authorize.ts`; Core
 * itself stays binding-neutral (§9 AS item 5).
 */
export type SelectionFailureCode =
  /** Both or neither of `streams` and `selection_preset`. */
  | "source_validation_failed"
  | "unknown_stream"
  | "unknown_preset"
  | "unknown_view"
  | "unknown_field"
  | "unsupported_selection_parameter"
  | "invalid_resource_key"
  /**
   * A v0.2 `minimum` the AS cannot interpret. Distinct from
   * `unsupported_selection_parameter` (a v0.2 member on a v0.1 request) and
   * from the issuance-time `access_denied` a well-formed but unsatisfiable
   * minimum produces: only this one is fixable by the client resending.
   */
  | "invalid_minimum"
  | "invalid_request";

export interface SelectionFailure {
  code: SelectionFailureCode;
  message: string;
}

export type SelectionValidation =
  { ok: true } | { ok: false; failure: SelectionFailure };

function fail(
  code: SelectionFailureCode,
  message: string,
): SelectionValidation {
  return { ok: false, failure: { code, message } };
}

/**
 * Canonical key strings: a plain string for a simple key, a minified JSON
 * array for a compound key (§6 `resources`). We validate arity and type
 * against the declaration's `primary_key` here so an unsatisfiable resource
 * list is rejected at issuance rather than silently matching nothing at the RS.
 */
function validateResourceKey(raw: string, primaryKey: string[]): string | null {
  if (primaryKey.length <= 1) {
    // A simple key is a plain string. A JSON array here is an arity error.
    if (raw.startsWith("[")) {
      return "expected a simple key string, got a compound key array";
    }
    return raw.length > 0 ? null : "resource key must not be empty";
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return "compound resource key must be a minified JSON array";
  }
  if (!Array.isArray(parsed)) {
    return "compound resource key must be a JSON array";
  }
  if (parsed.length !== primaryKey.length) {
    return `compound resource key has ${parsed.length} parts, declaration primary_key has ${primaryKey.length}`;
  }
  if (!parsed.every((part) => typeof part === "string")) {
    return "compound resource key parts must be strings";
  }
  return null;
}

/**
 * The field set a `minimum.fields` member must be drawn from: the *expanded
 * request*, not the declaration.
 *
 * v0.2 requires rejecting fields "outside the expanded request", which is a
 * stricter gate than the declared schema. A floor naming a field the client
 * did not request is incoherent — the upper limit already excludes it, so the
 * minimum could never be met and the request could never succeed. Catching it
 * here turns a guaranteed `access_denied` at issuance into a fixable shape
 * error before a human is asked to decide anything.
 */
function expandedRequestFields(
  stream: StreamRequest,
  declared: DeclaredStream,
  snapshot: DeclarationSnapshot,
): string[] {
  if (stream.view !== undefined) {
    const view = snapshot.views?.find((v) => v.name === stream.view);
    // An unresolvable view already failed above; treat it as empty here.
    return view ? view.fields.filter((f) => declared.fields.includes(f)) : [];
  }
  if (stream.fields !== undefined) {
    return stream.fields.filter((f) => declared.fields.includes(f));
  }
  // Omitting both asks for all permitted fields, so the whole declared set is
  // in the expanded request.
  return declared.fields;
}

/**
 * Validate a request `time_range`'s own shape, independent of which stream
 * carries it.
 *
 * Shared by the named-stream path and the wildcard path so the two cannot
 * disagree about what a well-formed window is. Before this was factored out,
 * a wildcard's window skipped every check here — unparseable bounds, an
 * inverted `since`/`until`, and an empty `{}` were all accepted, while the
 * same values written longhand were rejected. A shorthand that validates less
 * than the form it stands for is a hole, not a convenience.
 *
 * `value` is untrusted JSON, so the object and string types are checked
 * rather than assumed: a `null` or a number here must be a validation failure,
 * not a `TypeError` that the binding turns into a 500.
 */
function validateTimeRangeBounds(
  value: unknown,
  subject: string,
): SelectionValidation {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return fail("invalid_request", `${subject} time_range must be an object`);
  }
  const { since, until } = value as { since?: unknown; until?: unknown };
  if (since === undefined && until === undefined) {
    return fail("invalid_request", `${subject} has an empty time_range`);
  }
  for (const [label, bound] of [
    ["since", since],
    ["until", until],
  ] as const) {
    if (bound === undefined) continue;
    if (typeof bound !== "string" || Number.isNaN(Date.parse(bound))) {
      return fail(
        "invalid_request",
        `${subject} time_range.${label} is not a valid ISO 8601 instant`,
      );
    }
  }
  if (typeof since === "string" && typeof until === "string") {
    if (Date.parse(since) >= Date.parse(until)) {
      return fail(
        "invalid_request",
        `${subject} time_range.since must precede time_range.until`,
      );
    }
  }
  return { ok: true };
}

/**
 * Validate one v0.2 `minimum` against the request that carries it.
 *
 * Everything here is a shape question answerable without the owner, the
 * inventory, or any record. Whether the *owner's* narrowing then satisfies a
 * well-formed minimum is an issuance question, handled in `resolve.ts`.
 */
function validateMinimum(
  stream: StreamRequest,
  declared: DeclaredStream,
  snapshot: DeclarationSnapshot,
): SelectionValidation {
  const minimum = stream.minimum;
  if (minimum === undefined) return { ok: true };

  const bad = (message: string) =>
    fail("invalid_minimum", `stream '${stream.name}' minimum: ${message}`);

  if (typeof minimum !== "object" || minimum === null) {
    return bad("must be an object");
  }

  // Only `fields` and `time_range` are recognized. An unknown member must not
  // pass silently: the client would believe it imposed a condition the AS
  // never evaluates.
  const unknown = Object.keys(minimum).filter(
    (key) => key !== "fields" && key !== "time_range",
  );
  if (unknown.length > 0) {
    return bad(`unknown member(s) ${unknown.join(", ")}`);
  }
  if (minimum.fields === undefined && minimum.time_range === undefined) {
    return bad("must specify at least one of fields or time_range");
  }

  if (minimum.fields !== undefined) {
    const fields = minimum.fields;
    if (!Array.isArray(fields) || fields.length === 0) {
      return bad("fields must be a non-empty array");
    }
    if (!fields.every((f) => typeof f === "string" && f.length > 0)) {
      return bad("fields must contain non-empty strings");
    }
    if (new Set(fields).size !== fields.length) {
      return bad("fields must not contain duplicates");
    }
    const permitted = expandedRequestFields(stream, declared, snapshot);
    const outside = fields.filter((f) => !permitted.includes(f));
    if (outside.length > 0) {
      return bad(`fields outside the expanded request: ${outside.join(", ")}`);
    }
  }

  if (minimum.time_range !== undefined) {
    const { since, until } = minimum.time_range;
    // Unlike a request `time_range`, a minimum window must be closed: an open
    // floor would mean "at least everything", which no narrowing can satisfy
    // and which the request's own upper limit already bounds.
    if (typeof since !== "string" || typeof until !== "string") {
      return bad("time_range must contain both since and until");
    }
    const from = Date.parse(since);
    const to = Date.parse(until);
    if (Number.isNaN(from) || Number.isNaN(to)) {
      return bad("time_range bounds must be valid ISO 8601 instants");
    }
    if (from >= to) {
      return bad("time_range.since must precede time_range.until");
    }
    if (!declared.consent_time_field) {
      return bad(
        "stream declares no consent_time_field and cannot carry a time minimum",
      );
    }
    // The floor must sit inside the ceiling. Comparisons are on instants, so
    // an offset-bearing timestamp is ordered by the moment it names rather
    // than by its string form.
    const requested = stream.time_range;
    const ceilingSince =
      requested?.since !== undefined ? Date.parse(requested.since) : -Infinity;
    const ceilingUntil =
      requested?.until !== undefined ? Date.parse(requested.until) : Infinity;
    if (from < ceilingSince || to > ceilingUntil) {
      return bad("time_range falls outside the requested time_range");
    }
  }

  return { ok: true };
}

function validateStreamRequest(
  stream: StreamRequest,
  snapshot: DeclarationSnapshot,
  revision: "0.1" | "0.2",
): SelectionValidation {
  if (stream.necessity !== undefined) {
    if (stream.necessity !== "required" && stream.necessity !== "optional") {
      return fail(
        "invalid_request",
        `stream '${stream.name}' necessity must be required or optional`,
      );
    }
  }

  if (stream.minimum !== undefined && revision === "0.1") {
    // v0.1 has no `minimum`. Accepting and ignoring it is the one outcome
    // worse than rejecting: the client would ship believing a floor is
    // enforced. A client that wants minima moves to the v0.2 type.
    return fail(
      "unsupported_selection_parameter",
      `stream '${stream.name}' carries minimum, which requires the ${PDPP_DATA_ACCESS_TYPE_V02} detail type`,
    );
  }

  // A wildcard is checked by the caller (it must be the sole entry) and
  // expands during resolution, so there is no declared stream to match yet.
  if (stream.name === "*") {
    if (stream.view !== undefined) {
      return fail(
        "unsupported_selection_parameter",
        "view cannot be combined with a wildcard stream selection",
      );
    }
    if (stream.minimum !== undefined) {
      // A wildcard minimum would be one floor asserted over every stream the
      // declaration happens to contain, including streams whose schema has no
      // such field and streams that cannot carry a time window at all. v0.2
      // defines a minimum per named stream; it says nothing about what a
      // fanned-out one would mean, so we do not invent semantics for it.
      return fail(
        "unsupported_selection_parameter",
        "minimum cannot be combined with a wildcard stream selection",
      );
    }
    if (stream.time_range !== undefined) {
      // A wildcard is shorthand for naming every declared stream, so it
      // cannot mean something weaker than naming them. §6's rule for a named
      // stream — "no consent_time_field, no time_range" — therefore applies
      // to every stream the wildcard expands to.
      //
      // The alternative was to keep accepting this and let resolution drop
      // the window for time-incapable streams, which is what the code did.
      // That silently issued unbounded access to those streams from a request
      // whose own words asked for a bounded one: the owner approved, and the
      // client received, more than either had read. A request that cannot be
      // carried out as written is refused, not quietly reinterpreted.
      const incapable = snapshot.streams
        .filter((s) => !s.consent_time_field)
        .map((s) => s.name);
      if (incapable.length > 0) {
        return fail(
          "unsupported_selection_parameter",
          `wildcard time_range expands to stream(s) that declare no consent_time_field and cannot accept it: ${incapable.join(", ")}`,
        );
      }
      // The window's own shape is checked by the same rule a named stream's
      // is; a wildcard must not be the weaker form.
      const bounds = validateTimeRangeBounds(
        stream.time_range,
        "wildcard stream selection",
      );
      if (!bounds.ok) return bounds;
    }
    return { ok: true };
  }

  const declared = snapshot.streams.find((s) => s.name === stream.name);
  if (!declared) {
    return fail(
      "unknown_stream",
      `stream '${stream.name}' is not declared by the retained snapshot`,
    );
  }

  if (stream.view !== undefined && stream.fields !== undefined) {
    return fail(
      "invalid_request",
      `stream '${stream.name}' specifies both view and fields, which are mutually exclusive`,
    );
  }

  if (stream.view !== undefined) {
    const view = snapshot.views?.find((v) => v.name === stream.view);
    if (!view) {
      return fail(
        "unknown_view",
        `view '${stream.view}' is not defined for this source`,
      );
    }
    // §9 AS item 12: a view naming a field absent from the retained schema is
    // not resolvable, and we reject rather than silently dropping the field.
    const absent = view.fields.filter((f) => !declared.fields.includes(f));
    if (absent.length > 0) {
      return fail(
        "unknown_field",
        `view '${stream.view}' names fields absent from stream '${stream.name}': ${absent.join(", ")}`,
      );
    }
  }

  if (stream.fields !== undefined) {
    if (stream.fields.length === 0) {
      return fail(
        "invalid_request",
        `stream '${stream.name}' specifies an empty fields list`,
      );
    }
    const absent = stream.fields.filter((f) => !declared.fields.includes(f));
    if (absent.length > 0) {
      return fail(
        "unknown_field",
        `stream '${stream.name}' requests fields absent from the retained schema: ${absent.join(", ")}`,
      );
    }
  }

  if (stream.time_range !== undefined) {
    // §6: the declaration's consent_time_field is the authoritative signal
    // that a stream is time-range-capable. No field, no time_range.
    if (!declared.consent_time_field) {
      return fail(
        "unsupported_selection_parameter",
        `stream '${stream.name}' declares no consent_time_field and cannot accept time_range`,
      );
    }
    const bounds = validateTimeRangeBounds(
      stream.time_range,
      `stream '${stream.name}'`,
    );
    if (!bounds.ok) return bounds;
  }

  if (stream.resources !== undefined) {
    if (stream.resources.length === 0) {
      return fail(
        "invalid_request",
        `stream '${stream.name}' specifies an empty resources list`,
      );
    }
    for (const raw of stream.resources) {
      const problem = validateResourceKey(raw, declared.primary_key);
      if (problem) {
        return fail(
          "invalid_resource_key",
          `stream '${stream.name}' resource '${raw}': ${problem}`,
        );
      }
    }
  }

  // Last, so a minimum naming a field that is itself undeclared reports the
  // undeclared field rather than the floor built on it.
  return validateMinimum(stream, declared, snapshot);
}

/**
 * Validate one selection request against the retained declaration snapshot.
 *
 * The caller must have already retrieved and pinned `snapshot`; this function
 * never fetches. §9 AS item 16 requires that the same snapshot carry through
 * consent and issuance, so passing a freshly fetched declaration here and a
 * different one to `resolveGrant` would defeat the whole guarantee.
 */
export function validateSelectionRequest(
  request: SelectionRequest,
  snapshot: DeclarationSnapshot,
): SelectionValidation {
  // Exactly two types are recognized, each resolved under its own revision.
  // Anything else is rejected rather than processed as the nearest PDPP type:
  // a type URI the AS does not implement carries rules it does not apply.
  const revision =
    request.type === PDPP_DATA_ACCESS_TYPE_V02
      ? "0.2"
      : request.type === PDPP_DATA_ACCESS_TYPE
        ? "0.1"
        : null;
  if (revision === null) {
    return fail(
      "invalid_request",
      `authorization detail type must be ${PDPP_DATA_ACCESS_TYPE} or ${PDPP_DATA_ACCESS_TYPE_V02}`,
    );
  }

  if (request.source.id !== snapshot.source_id) {
    return fail(
      "invalid_request",
      "request source.id does not match the retained declaration snapshot",
    );
  }

  // §6: the purpose code must be a syntactically valid absolute URI, and that
  // is the only syntactic gate. §9 AS item 6 forbids rejecting a code merely
  // for being absent from the registry — an unregistered code renders from its
  // description or raw URI instead.
  if (!isAbsoluteUri(request.purpose_code)) {
    return fail("invalid_request", "purpose_code must be an absolute URI");
  }

  if (
    request.access_mode !== "single_use" &&
    request.access_mode !== "continuous"
  ) {
    return fail(
      "invalid_request",
      "access_mode must be single_use or continuous",
    );
  }

  if (request.retention !== undefined) {
    const { on_expiry } = request.retention;
    if (on_expiry !== "delete" && on_expiry !== "anonymize") {
      // `archive` was dropped in v0.1 and is the likely wrong value here.
      return fail(
        "invalid_request",
        "retention.on_expiry must be delete or anonymize",
      );
    }
  }

  const hasStreams = request.streams !== undefined;
  const hasPreset = request.selection_preset !== undefined;
  if (hasStreams === hasPreset) {
    // Both or neither. Deliberately one message for both cases: the failure
    // is about the pair, and distinguishing them tells a probing client which
    // half the server accepted.
    return fail(
      "source_validation_failed",
      "exactly one of streams or selection_preset is required",
    );
  }

  if (hasPreset) {
    const preset = snapshot.selection_presets?.find(
      (p) => p.name === request.selection_preset,
    );
    if (!preset) {
      return fail(
        "unknown_preset",
        `selection preset '${request.selection_preset}' is not defined by the retained snapshot`,
      );
    }
    // The preset's own streams still have to be expressible against the
    // snapshot; a declaration that ships a preset naming a dropped stream is
    // invalid and we would rather fail here than resolve an empty grant.
    for (const stream of preset.streams) {
      const result = validateStreamRequest(stream, snapshot, revision);
      if (!result.ok) return result;
    }
    return { ok: true };
  }

  const streams = request.streams ?? [];
  if (streams.length === 0) {
    return fail("invalid_request", "streams must not be empty");
  }

  const wildcards = streams.filter((s) => s.name === "*");
  if (wildcards.length > 0 && streams.length > 1) {
    // §6 clause 6.8-3: a wildcard entry must be the only entry. Like the
    // streams/preset exactly-one check above, this is a Source validation
    // failure and must map to the same RFC 9396 code.
    return fail(
      "source_validation_failed",
      "a wildcard stream entry must be the only entry in streams",
    );
  }

  const seen = new Set<string>();
  for (const stream of streams) {
    if (seen.has(stream.name)) {
      // §6 clause 6.8-3: stream names must be unique — also a Source
      // validation failure.
      return fail(
        "source_validation_failed",
        `stream '${stream.name}' appears more than once`,
      );
    }
    seen.add(stream.name);

    const result = validateStreamRequest(stream, snapshot, revision);
    if (!result.ok) return result;
  }

  return { ok: true };
}

function isAbsoluteUri(value: string): boolean {
  try {
    // URL rejects relative references, which is exactly the check we want.
    new URL(value);
    return true;
  } catch {
    return false;
  }
}
