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
  type DeclarationSnapshot,
  type DeclaredStream,
  type SelectionRequest,
  type StreamGrant,
  type StreamRequest,
  type TimeConstraint,
} from "./types.js";

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
  | "empty_field_set";

export interface ResolutionFailure {
  code: ResolutionFailureCode;
  message: string;
  /** The stream that could not be resolved, when the failure is stream-scoped. */
  stream?: string;
  /** For `instance_choice_required`: the handles the owner must choose between. */
  candidates?: string[];
}

export type ResolutionResult =
  | { ok: true; streams: StreamGrant[] }
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
 * Resolve the field allowlist for one stream.
 *
 * Schema-required fields are unioned in unconditionally: §6 calls them the
 * per-stream consent floor, because a record missing them is not a valid
 * record of that stream. That means a client asking for fewer fields than the
 * floor gets the floor, not an error.
 */
function resolveFields(
  request: StreamRequest,
  declared: DeclaredStream,
  snapshot: DeclarationSnapshot,
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

  // Intersect with the declared schema before adding the floor, so a view or
  // allowlist can never introduce a field the snapshot does not define.
  const permitted = requested.filter((f) => declared.fields.includes(f));
  const fields = unique([...permitted, ...declared.required_fields]);

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
  request: StreamRequest,
  declared: DeclaredStream,
): TimeConstraint | undefined {
  if (!request.time_range) return undefined;
  const { since, until } = request.time_range;
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

function resolveOneStream(
  request: StreamRequest,
  declared: DeclaredStream,
  snapshot: DeclarationSnapshot,
  inventory: InstanceInventory,
):
  | { ok: true; stream: StreamGrant }
  | { ok: false; failure: ResolutionFailure } {
  const fields = resolveFields(request, declared, snapshot);
  if (!fields.ok) return fields;

  const instances = resolveInstances(request, declared.name, inventory);
  if (!instances.ok) return instances;

  const timeConstraint = resolveTimeConstraint(request, declared);

  return {
    ok: true,
    stream: {
      name: declared.name,
      instance_ids: instances.instanceIds,
      fields: fields.fields,
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
): ResolutionResult {
  const selections = expandSelections(request, snapshot);
  if (selections.length === 0) {
    return failure(
      "unknown_stream",
      "the selection resolved to no streams against the retained snapshot",
    );
  }

  const resolved: StreamGrant[] = [];
  for (const selection of selections) {
    const declared = snapshot.streams.find((s) => s.name === selection.name);
    if (!declared) {
      return failure(
        "unknown_stream",
        `stream '${selection.name}' is not declared by the retained snapshot`,
        { stream: selection.name },
      );
    }

    const result = resolveOneStream(selection, declared, snapshot, inventory);
    if (!result.ok) return { ok: false, failure: result.failure };
    resolved.push(result.stream);
  }

  return { ok: true, streams: resolved };
}
