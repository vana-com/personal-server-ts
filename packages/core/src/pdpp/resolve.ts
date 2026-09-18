/**
 * PDPP Core §6→§7 resolution: turn a validated selection request into the
 * explicit grant facts that get frozen at issuance.
 *
 * Every request-only convenience dies here. Wildcards and presets expand to
 * concrete stream rows, views resolve to field lists, omitted fields become
 * the declaration's full field set, omitted instance handles resolve against
 * the owner's connection inventory, and `time_range` freezes against the
 * declaration's `consent_time_field`. §7 is explicit that none of these
 * conveniences are continuing authority in the grant — the RS must never have
 * to resolve anything, which is also what the AS→RS contract promises.
 *
 * Resolution runs against the same retained snapshot `selection.ts` validated
 * against. Passing a newer declaration here is the bug §9 AS item 16 exists to
 * prevent: it would let a later declaration widen an in-flight authorization.
 */

import {
  PDPP_DATA_ACCESS_TYPE_V02,
  type DeclarationSnapshot,
  type DeclaredStream,
  type RequestedStream,
  type SelectionRequest,
  type StreamGrant,
  type StreamRequest,
  type TimeConstraint,
  type TimeRange,
} from "./types.js";

/**
 * The owner's v0.2 narrowing decisions, keyed by stream name.
 *
 * Every member narrows and none widens. That is enforced by intersection
 * rather than by trust: a choice is applied against the request's own upper
 * limit, so a caller that forwards a tampered choice gets the ceiling, not an
 * escalation. Instance picks stay where they already are — overlaid onto the
 * `InstanceInventory` — because they narrow *eligibility*, which is owner
 * state rather than request shape.
 *
 * Ignored entirely for a v0.1 request: that revision defines no narrowing
 * step, and a v0.1 client's grant must be the same one it has always had.
 */
export interface OwnerChoices {
  /** Streams the owner removed. Only an `optional` stream may appear. */
  declined_streams?: string[];
  /** Per-stream field narrowing, intersected with the requested allowlist. */
  fields?: Record<string, string[]>;
  /** Per-stream window narrowing, clamped into the requested window. */
  time_ranges?: Record<string, TimeRange>;
}

/**
 * The owner's connected instances for a source, as the AS knows them at
 * resolution time. §6 is strict that omitting `instance_ids` never means
 * fan-in: the AS resolves exactly one eligible handle or requires an explicit
 * owner choice.
 */
export interface InstanceInventory {
  /** Eligible opaque handles for a given stream, in the owner's connection state. */
  eligibleFor(streamName: string): string[];
}

export type ResolutionFailureCode =
  | "unknown_stream"
  | "unknown_instance"
  | "instance_choice_required"
  | "no_eligible_instance"
  | "unknown_view"
  | "empty_field_set"
  /** v0.2: a required stream's explicit minimum cannot be satisfied. */
  | "minimum_not_met"
  /** v0.2: the owner declined a stream the request marks `required`. */
  | "required_stream_declined"
  /** v0.2: nothing survived the owner's choices. No empty grants. */
  | "no_streams_approved";

export interface ResolutionFailure {
  code: ResolutionFailureCode;
  message: string;
  /** The stream that could not be resolved, when the failure is stream-scoped. */
  stream?: string;
  /** For `instance_choice_required`: the handles the owner must choose between. */
  candidates?: string[];
}

export type ResolutionResult =
  | {
      ok: true;
      streams: StreamGrant[];
      /**
       * v0.2: optional streams the owner removed, or whose minimum their
       * narrowing could not meet. Present only when non-empty, and only for
       * v0.2 — an omitted stream is not a grant and must never read as
       * authorized, so it travels beside the approved streams rather than in
       * them.
       */
      omittedStreams?: string[];
      /**
       * v0.2: the requested upper limits, so the grant can record what was
       * asked for beside what was approved.
       */
      requestedStreams?: RequestedStream[];
    }
  | { ok: false; failure: ResolutionFailure };

function failure(
  code: ResolutionFailureCode,
  message: string,
  extra?: Partial<ResolutionFailure>,
): ResolutionResult {
  return { ok: false, failure: { code, message, ...extra } };
}

/** Stable de-duplication. Grant field and instance lists must be unique (§7). */
function unique(values: string[]): string[] {
  return Array.from(new Set(values));
}

/**
 * The requested field ceiling for one stream, before owner choices.
 *
 * Under v0.1 the declaration's `required_fields` are unioned in: §6 called
 * them the per-stream consent floor, so a client asking for fewer fields got
 * the floor rather than an error.
 *
 * Under v0.2 that union is gone. PR #1 changes the rule deliberately: the
 * record format describes a complete record, while the owner's approval
 * determines which fields the app receives. A schema can require a field of
 * every valid record and the owner can still withhold it, and the RS must not
 * add it back. Keeping the union here would make the whole withholding
 * guarantee unreachable — the AS would re-add the field before the owner ever
 * saw a choice about it.
 */
function requestedFields(
  request: StreamRequest,
  declared: DeclaredStream,
  snapshot: DeclarationSnapshot,
  revision: "0.1" | "0.2",
): { ok: true; fields: string[] } | { ok: false; failure: ResolutionFailure } {
  let requested: string[];

  if (request.view !== undefined) {
    const view = snapshot.views?.find((v) => v.name === request.view);
    if (!view) {
      return {
        ok: false,
        failure: {
          code: "unknown_view",
          message: `view '${request.view}' is not defined for this source`,
          stream: declared.name,
        },
      };
    }
    requested = view.fields;
  } else if (request.fields !== undefined) {
    requested = request.fields;
  } else {
    // §6 "Note on defaults": omitting both asks the AS to resolve all
    // permitted fields from the retained snapshot.
    requested = declared.fields;
  }

  // Intersect with the declared schema first, so a view or allowlist can
  // never introduce a field the snapshot does not define.
  const permitted = requested.filter((f) => declared.fields.includes(f));
  const fields =
    revision === "0.1"
      ? unique([...permitted, ...declared.required_fields])
      : unique(permitted);

  if (fields.length === 0) {
    return {
      ok: false,
      failure: {
        code: "empty_field_set",
        message: `stream '${declared.name}' resolved to an empty field set`,
        stream: declared.name,
      },
    };
  }

  return { ok: true, fields };
}

/**
 * Apply the owner's field narrowing by intersection with the ceiling.
 *
 * Intersection rather than replacement is the security property: a choice
 * naming a field the request never asked for cannot add it. An *absent*
 * choice means "no narrowing", which is different from an empty one — an
 * empty choice is a real decision to share nothing from this stream, and
 * silently reading it as "all fields" would invert it.
 */
function narrowFields(
  ceiling: string[],
  chosen: string[] | undefined,
): string[] {
  if (chosen === undefined) return ceiling;
  return ceiling.filter((f) => chosen.includes(f));
}

/** Instant for a bound, with an absent bound reading as the open end. */
function instant(value: string | undefined, open: number): number {
  return value === undefined ? open : Date.parse(value);
}

/**
 * Clamp the owner's window into the requested window.
 *
 * The result is the intersection, so the later `since` and the earlier
 * `until` win. An owner asking for more history than the client requested
 * gets the client's limit, not their own ask.
 */
function narrowTimeRange(
  ceiling: TimeRange | undefined,
  chosen: TimeRange | undefined,
): TimeRange | undefined {
  if (chosen === undefined) return ceiling;
  const since = [ceiling?.since, chosen.since]
    .filter((v): v is string => v !== undefined)
    .sort((a, b) => Date.parse(b) - Date.parse(a))[0];
  const until = [ceiling?.until, chosen.until]
    .filter((v): v is string => v !== undefined)
    .sort((a, b) => Date.parse(a) - Date.parse(b))[0];
  if (since === undefined && until === undefined) return undefined;
  return {
    ...(since !== undefined && { since }),
    ...(until !== undefined && { until }),
  };
}

/**
 * Whether one stream's resolved shape satisfies its explicit minimum.
 *
 * This answers a permission question and nothing else. A satisfied minimum
 * says the grant *permits* those fields and that window; v0.2 is explicit
 * that it asserts nothing about record existence, freshness, completeness, or
 * suitability, and that the AS must not require records to exist to satisfy
 * one. So this function never touches a record.
 */
function minimumSatisfied(
  minimum: StreamRequest["minimum"],
  fields: string[],
  window: TimeRange | undefined,
): { ok: true } | { ok: false; reason: string } {
  if (!minimum) return { ok: true };

  if (minimum.fields) {
    const missing = minimum.fields.filter((f) => !fields.includes(f));
    if (missing.length > 0) {
      return {
        ok: false,
        reason: `the approved fields omit the required minimum field(s) ${missing.join(", ")}`,
      };
    }
  }

  if (minimum.time_range) {
    // The resolved window must *contain* the entire minimum window. An absent
    // resolved lower bound is negative infinity and an absent upper bound is
    // positive infinity, so an unbounded window contains every floor.
    const from = instant(window?.since, -Infinity);
    const to = instant(window?.until, Infinity);
    if (
      Date.parse(minimum.time_range.since) < from ||
      Date.parse(minimum.time_range.until) > to
    ) {
      return {
        ok: false,
        reason:
          "the approved time window does not contain the required minimum window",
      };
    }
  }

  return { ok: true };
}

/**
 * Resolve instance handles for one stream.
 *
 * Three outcomes, per §6 and §7: explicit handles are verified for
 * eligibility; a single eligible handle resolves automatically; anything else
 * is an owner choice the AS must surface before the final approval surface.
 */
function resolveInstances(
  request: StreamRequest,
  streamName: string,
  inventory: InstanceInventory,
):
  | { ok: true; instanceIds: string[] }
  | { ok: false; failure: ResolutionFailure } {
  const eligible = inventory.eligibleFor(streamName);

  if (request.instance_ids !== undefined && request.instance_ids.length > 0) {
    const ineligible = request.instance_ids.filter(
      (id) => !eligible.includes(id),
    );
    if (ineligible.length > 0) {
      return {
        ok: false,
        failure: {
          code: "unknown_instance",
          message: `stream '${streamName}' requests instance handles that are not eligible: ${ineligible.join(", ")}`,
          stream: streamName,
        },
      };
    }
    // Explicitly listing more than one handle is how a client asks for
    // fan-in, and it is allowed precisely because it is explicit.
    return { ok: true, instanceIds: unique(request.instance_ids) };
  }

  if (eligible.length === 0) {
    return {
      ok: false,
      failure: {
        code: "no_eligible_instance",
        message: `stream '${streamName}' has no connected instance to authorize`,
        stream: streamName,
      },
    };
  }

  if (eligible.length > 1) {
    // Omission never means fan-in. The owner picks.
    return {
      ok: false,
      failure: {
        code: "instance_choice_required",
        message: `stream '${streamName}' has ${eligible.length} eligible instances and the request named none`,
        stream: streamName,
        candidates: eligible,
      },
    };
  }

  return { ok: true, instanceIds: [eligible[0]] };
}

/**
 * Freeze `time_range` into the grant's `time_constraint`, binding the
 * declaration's `consent_time_field` as the field the RS evaluates against.
 * Freezing the field name (not just the bounds) is what stops a later
 * declaration that renames its time field from silently re-scoping the grant.
 */
function resolveTimeConstraint(
  window: TimeRange | undefined,
  declared: DeclaredStream,
): TimeConstraint | undefined {
  if (!window) return undefined;
  const { since, until } = window;
  if (since === undefined && until === undefined) return undefined;
  // Validation already rejected time_range on a stream with no time field.
  const field = declared.consent_time_field;
  if (!field) return undefined;
  return {
    field,
    ...(since !== undefined && { since }),
    ...(until !== undefined && { until }),
  };
}

/**
 * One stream's outcome. `minimum_unmet` is distinct from a hard failure
 * because what happens next depends on the stream's `necessity`, and only the
 * caller knows whether this stream is the one that must refuse the whole
 * authorization or the one that simply drops out of it.
 */
type StreamOutcome =
  | { kind: "resolved"; stream: StreamGrant }
  | { kind: "minimum_unmet"; reason: string }
  | { kind: "failed"; failure: ResolutionFailure };

function resolveOneStream(
  request: StreamRequest,
  declared: DeclaredStream,
  snapshot: DeclarationSnapshot,
  inventory: InstanceInventory,
  revision: "0.1" | "0.2",
  choices: OwnerChoices | undefined,
): StreamOutcome {
  const ceiling = requestedFields(request, declared, snapshot, revision);
  if (!ceiling.ok) return { kind: "failed", failure: ceiling.failure };

  // v0.1 has no narrowing step, so its resolution is untouched by choices.
  const fields =
    revision === "0.2"
      ? narrowFields(ceiling.fields, choices?.fields?.[declared.name])
      : ceiling.fields;

  if (fields.length === 0) {
    // The resolved selection must contain at least one field per retained
    // stream, so an owner who narrowed everything away has refused the
    // stream, not asked for all of it.
    return {
      kind: "failed",
      failure: {
        code: "empty_field_set",
        message: `stream '${declared.name}' resolved to an empty field set`,
        stream: declared.name,
      },
    };
  }

  const window =
    revision === "0.2"
      ? narrowTimeRange(request.time_range, choices?.time_ranges?.[declared.name])
      : request.time_range;

  if (revision === "0.2") {
    // Checked before instance resolution: an unsatisfiable minimum is a
    // decision about this stream that does not depend on which handle serves
    // it, and an optional stream that is about to drop out should not fail
    // the whole authorization on a missing instance it will never use.
    const satisfied = minimumSatisfied(request.minimum, fields, window);
    if (!satisfied.ok) {
      return { kind: "minimum_unmet", reason: satisfied.reason };
    }
  }

  const instances = resolveInstances(request, declared.name, inventory);
  if (!instances.ok) return { kind: "failed", failure: instances.failure };

  const timeConstraint = resolveTimeConstraint(window, declared);

  return {
    kind: "resolved",
    stream: {
      name: declared.name,
      instance_ids: instances.instanceIds,
      fields,
      ...(timeConstraint && { time_constraint: timeConstraint }),
      ...(request.resources && { resources: unique(request.resources) }),
    },
  };
}

/**
 * Expand the request's stream selections into the concrete list to resolve.
 *
 * A wildcard entry fans out to every declared stream, carrying its own
 * per-stream parameters with it — §6 says a wildcard's `instance_ids` apply to
 * every expanded stream, and each handle is then verified per stream by
 * `resolveInstances`. A preset expands from the snapshot instead.
 */
function expandSelections(
  request: SelectionRequest,
  snapshot: DeclarationSnapshot,
): StreamRequest[] {
  if (request.selection_preset !== undefined) {
    const preset = snapshot.selection_presets?.find(
      (p) => p.name === request.selection_preset,
    );
    return preset ? preset.streams : [];
  }

  const streams = request.streams ?? [];
  const wildcard = streams.find((s) => s.name === "*");
  if (wildcard) {
    return snapshot.streams.map((declared) => ({
      ...wildcard,
      name: declared.name,
      // A wildcard cannot carry a view (validation rejects that pairing), and
      // its time_range only applies to streams that can accept one. Dropping
      // it for time-incapable streams is what makes `{"name":"*"}` with a
      // time_range usable on a mixed-capability source at all.
      ...(wildcard.time_range && !declared.consent_time_field
        ? { time_range: undefined }
        : {}),
    }));
  }

  return streams;
}

/**
 * Resolve every enforcement axis for a validated selection request.
 *
 * Call this before showing the final approval surface: §7 requires the
 * approval artifact to contain the exact resolved instance handles, stream
 * names, fields, resources, and temporal bounds, which only exist once this
 * has run.
 */
export function resolveSelection(
  request: SelectionRequest,
  snapshot: DeclarationSnapshot,
  inventory: InstanceInventory,
  choices?: OwnerChoices,
): ResolutionResult {
  const revision =
    request.type === PDPP_DATA_ACCESS_TYPE_V02 ? "0.2" : "0.1";
  const selections = expandSelections(request, snapshot);
  if (selections.length === 0) {
    return failure(
      "unknown_stream",
      "the selection resolved to no streams against the retained snapshot",
    );
  }

  const resolved: StreamGrant[] = [];
  const omitted: string[] = [];
  const requestedStreams: RequestedStream[] = [];

  for (const selection of selections) {
    const declared = snapshot.streams.find((s) => s.name === selection.name);
    if (!declared) {
      return failure(
        "unknown_stream",
        `stream '${selection.name}' is not declared by the retained snapshot`,
        { stream: selection.name },
      );
    }

    // `necessity` defaults to `required`, so an unmarked stream is one the AS
    // must retain or refuse. Inferring "optional" from omission would let a
    // client's silence become the owner's permission to drop a stream the
    // client actually depends on.
    const necessity = selection.necessity ?? "required";

    if (revision === "0.2") {
      const ceiling = requestedFields(selection, declared, snapshot, "0.2");
      requestedStreams.push({
        name: declared.name,
        necessity,
        fields: ceiling.ok ? ceiling.fields : [],
        ...(selection.time_range && { time_range: selection.time_range }),
        ...(selection.minimum && { minimum: selection.minimum }),
      });

      if (choices?.declined_streams?.includes(declared.name)) {
        if (necessity === "required") {
          // A required stream is retained or the authorization is refused.
          // There is no third outcome, and in particular no weaker grant.
          return failure(
            "required_stream_declined",
            `stream '${declared.name}' is required by the request and cannot be declined`,
            { stream: declared.name },
          );
        }
        omitted.push(declared.name);
        continue;
      }
    }

    const outcome = resolveOneStream(
      selection,
      declared,
      snapshot,
      inventory,
      revision,
      choices,
    );

    if (outcome.kind === "failed") {
      return { ok: false, failure: outcome.failure };
    }

    if (outcome.kind === "minimum_unmet") {
      if (necessity === "required") {
        // Refuse issuance rather than issue a weaker grant for this stream.
        // The OAuth binding reports this as `access_denied`: the request was
        // well-formed and the owner decided: the two are simply incompatible.
        return failure(
          "minimum_not_met",
          `stream '${declared.name}' is required and ${outcome.reason}`,
          { stream: declared.name },
        );
      }
      // For an optional stream, failing its minimum permits omission of the
      // whole stream — never a retained stream with a weaker projection.
      omitted.push(declared.name);
      continue;
    }

    resolved.push(outcome.stream);
  }

  if (resolved.length === 0) {
    // No empty grants, and nothing added to compensate for a refused
    // selection. A different proposal needs a new authorization request.
    return failure(
      "no_streams_approved",
      "the owner approved no streams; a grant with no authorized stream cannot be issued",
    );
  }

  return {
    ok: true,
    streams: resolved,
    ...(omitted.length > 0 && { omittedStreams: omitted }),
    ...(revision === "0.2" && { requestedStreams }),
  };
}
