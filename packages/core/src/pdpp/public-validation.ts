/**
 * Owner-independent validation of one authorization-details object.
 *
 * spec-core §6 "Authorization privacy boundary" (L1212-L1241) splits request
 * checking in two:
 *
 *   - **Public invalidity** — "request structure and owner-independent
 *     capabilities" (L1222): unknown members, invalid value grammar,
 *     unsupported public capabilities. The OAuth/RAR binding answers these
 *     with `invalid_authorization_details` (L1222, AS items 2, 5, 14, 33).
 *   - **Owner-dependent eligibility** — anything whose answer depends on
 *     protected owner state: "source acceptance held privately for the owner
 *     and the existence or eligibility of requested instance handles"
 *     (L1220). That is deferred to authenticated review and, when it refuses,
 *     surfaces only as `access_denied` (L1230).
 *
 * This module is the first half. It reads nothing but the detail itself and
 * this build's fixed capabilities — never a declaration, a connection or an
 * instance — so its answer is the same for every owner (AS item 52:
 * "Performs owner-independent syntax and binding checks without querying
 * private owner availability").
 *
 * On a Personal Server the declaration registry is per-owner state: a
 * submitted declaration is admitted only for a source the owner holds data
 * for (`server/src/pdpp/declaration-registry.ts`). So every check that needs
 * the declaration — stream and view names, field names, temporal capability
 * and bound type, `resources` arity — is owner-dependent here and runs later,
 * in `validateSelectionRequest`, whose failures the route defers to review.
 */

import {
  parseTime,
  compareTime,
  compareLegacyTimeBounds,
  legacyTimeBound,
  type TimeType,
} from "./time.js";
import {
  PDPP_DATA_ACCESS_TYPE,
  PDPP_DATA_ACCESS_TYPE_V02,
  PDPP_DATA_ACCESS_TYPE_CANDIDATE,
  usesLockedRules,
} from "./types.js";

/**
 * Appendix A purposes (spec-core L3225-L3231). Membership is the only thing
 * the AS reads off a purpose code: outside it, a non-empty
 * `purpose_description` is required (L1091, AS item 6), never a rejection on
 * its own. `https://pdpp.dev/purpose/ai_training` is withdrawn (L3233) and is
 * therefore an ordinary non-Appendix-A code that confers nothing.
 */
export const APPENDIX_A_PURPOSE_CODES: ReadonlySet<string> = new Set([
  "https://pdpp.dev/purpose/personalization",
  "https://pdpp.dev/purpose/analytics",
  "https://pdpp.dev/purpose/export",
  "https://pdpp.dev/purpose/agent_context",
  "https://pdpp.dev/purpose/research",
]);

/**
 * Processing permissions this AS implements (AS item 14, spec-core L1122).
 * Empty: Core defines only `https://pdpp.dev/processing/ai_training`, which is
 * "Reserved and unsupported until that profile is published" (L1120), and no
 * independent-recipient permission exists (L1118). The AS advertises exactly
 * this list in `pdpp_processing_permissions_supported`, so discovery can never
 * name a value the AS would refuse (case O7).
 */
export const SUPPORTED_PROCESSING_PERMISSIONS: readonly string[] = [];

/** Members Core defines for a `data-access` detail (spec-core L1085-L1099). */
const DETAIL_MEMBERS = new Set([
  "type",
  "source",
  "purpose_code",
  "purpose_description",
  "access_mode",
  "processing_permissions",
  "retention",
  "streams",
  "selection_preset",
  "client_claims",
]);

/** Members Core defines for a `StreamRequest` (spec-core L1176-L1189). */
const STREAM_MEMBERS = new Set([
  "name",
  "necessity",
  "instance_ids",
  "time_range",
  "view",
  "fields",
  "resources",
  "minimum",
]);

/** The binding-neutral failure; the OAuth/RAR binding maps it to `invalid_authorization_details`. */
export interface PublicDetailFailure {
  code: "invalid_authorization_details";
  message: string;
}

export type PublicDetailValidation =
  { ok: true } | { ok: false; failure: PublicDetailFailure };

function invalid(message: string): PublicDetailValidation {
  return {
    ok: false,
    failure: { code: "invalid_authorization_details", message },
  };
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isAbsoluteUri(value: unknown): value is string {
  if (typeof value !== "string" || value.length === 0) return false;
  try {
    new URL(value);
    return true;
  } catch {
    return false;
  }
}

function unknownMembers(
  value: Record<string, unknown>,
  allowed: ReadonlySet<string>,
): string[] {
  return Object.keys(value).filter((key) => !allowed.has(key));
}

function nonEmptyUniqueStrings(value: unknown): value is string[] {
  return (
    Array.isArray(value) &&
    value.length > 0 &&
    value.every((v) => typeof v === "string" && v.length > 0) &&
    new Set(value).size === value.length
  );
}

/** The RFC 3339 type of a bound, when it is valid as exactly one of them. */
function boundType(value: unknown): TimeType | undefined {
  if (parseTime(value, "date") !== null) return "date";
  if (parseTime(value, "date-time") !== null) return "date-time";
  return undefined;
}

/**
 * The owner-independent half of the time-bound rules (spec-core L1193): a
 * bound is a valid RFC 3339 `full-date` or `date-time`, both bounds have one
 * type (the field has one format), and `since` precedes `until`. Whether the
 * type matches the stream's field needs the declaration and is deferred.
 */
function checkWindow(
  value: unknown,
  subject: string,
  closed: boolean,
  locked: boolean,
): PublicDetailValidation {
  if (!isObject(value)) return invalid(`${subject} must be an object`);
  const extra = unknownMembers(value, new Set(["since", "until"]));
  if (extra.length > 0)
    return invalid(
      `${subject} carries undefined member(s): ${extra.join(", ")}`,
    );
  const { since, until } = value;
  if (since === undefined && until === undefined)
    return invalid(`${subject} has no bound`);
  if (closed && (since === undefined || until === undefined))
    return invalid(`${subject} must contain both since and until`);
  if (!locked) {
    // The v0.2 type keeps its own (pre-lock) bound grammar; only the shape
    // and ordering are owner-independent questions here.
    for (const [label, bound] of [
      ["since", since],
      ["until", until],
    ] as const) {
      if (bound === undefined) continue;
      if (typeof bound !== "string" || legacyTimeBound(bound) === null)
        return invalid(`${subject}.${label} is not a valid ISO 8601 instant`);
    }
    if (
      typeof since === "string" &&
      typeof until === "string" &&
      compareLegacyTimeBounds(since, until)! >= 0
    )
      return invalid(`${subject}.since must precede until`);
    return { ok: true };
  }
  const types: TimeType[] = [];
  for (const [label, bound] of [
    ["since", since],
    ["until", until],
  ] as const) {
    if (bound === undefined) continue;
    const type = boundType(bound);
    if (!type)
      return invalid(
        `${subject}.${label} is not a valid RFC 3339 full-date or date-time`,
      );
    types.push(type);
  }
  if (types.length === 2) {
    if (types[0] !== types[1])
      return invalid(`${subject} bounds must have the same type`);
    if (compareTime(since as string, until as string, types[0]!)! >= 0)
      return invalid(`${subject}.since must precede until`);
  }
  return { ok: true };
}

/**
 * spec-core L1189: "Values are canonical key strings, as Compound key encoding
 * in Section 4 defines: the RFC 8785 serialization of the component array for
 * compound keys, the plain string for simple keys, never percent-encoded."
 *
 * A value that opens with `[` is read as a compound key and must be the RFC
 * 8785 form of an array of non-empty strings. For an array of strings RFC 8785
 * serialization is exactly ECMAScript `JSON.stringify`, so canonical means
 * "re-serializes to itself". The value is never percent-decoded (AS item 11):
 * `%2F` stays three characters. Arity against `primary_key` needs the
 * declaration and is checked later.
 */
function checkResource(raw: unknown): string | null {
  if (typeof raw !== "string" || raw.length === 0)
    return "resources entries must be non-empty strings";
  if (!raw.startsWith("[")) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return `resource '${raw}' is not a canonical compound key`;
  }
  if (
    !Array.isArray(parsed) ||
    parsed.length === 0 ||
    !parsed.every((part) => typeof part === "string" && part.length > 0)
  )
    return `resource '${raw}' must be an array of non-empty key strings`;
  if (JSON.stringify(parsed) !== raw)
    return `resource '${raw}' is not in RFC 8785 canonical form`;
  return null;
}

function checkStream(stream: unknown, locked: boolean): PublicDetailValidation {
  if (!isObject(stream)) return invalid("each stream entry must be an object");
  // RFC 9396 §5 / spec-core L1099 "Unknown members": reject, never ignore.
  const extra = unknownMembers(stream, STREAM_MEMBERS);
  if (extra.length > 0)
    return invalid(
      `stream entry carries undefined member(s): ${extra.join(", ")}`,
    );
  if (typeof stream.name !== "string" || stream.name.length === 0)
    return invalid("each stream entry must carry a non-empty name");
  const name = stream.name;
  if (
    stream.necessity !== undefined &&
    stream.necessity !== "required" &&
    stream.necessity !== "optional"
  )
    return invalid(`stream '${name}' necessity must be required or optional`);
  if (stream.view !== undefined && stream.fields !== undefined)
    // L1185: "both MUST NOT be present simultaneously".
    return invalid(`stream '${name}' carries both view and fields`);
  if (
    stream.view !== undefined &&
    (typeof stream.view !== "string" || stream.view.length === 0)
  )
    return invalid(`stream '${name}' view must be a non-empty string`);
  if (stream.fields !== undefined) {
    const fields = stream.fields;
    if (
      !Array.isArray(fields) ||
      fields.length === 0 ||
      !fields.every((f) => typeof f === "string" && f.length > 0) ||
      new Set(fields).size !== fields.length ||
      (fields.includes("*") && fields.length !== 1)
    )
      return invalid(
        `stream '${name}' fields must be a non-empty list of unique names; '*' must appear alone`,
      );
  }
  if (locked && stream.fields === undefined && stream.view === undefined)
    // L1205: "MUST carry either `fields` or `view`".
    return invalid(`stream '${name}' must carry fields or view`);
  if (name === "*" && stream.view !== undefined)
    return invalid("view cannot be combined with a wildcard stream selection");
  if (name === "*" && stream.minimum !== undefined)
    return invalid(
      "minimum cannot be combined with a wildcard stream selection",
    );
  if (
    stream.instance_ids !== undefined &&
    !nonEmptyUniqueStrings(stream.instance_ids)
  )
    return invalid(
      `stream '${name}' instance_ids must be non-empty unique strings`,
    );
  if (stream.resources !== undefined) {
    if (!Array.isArray(stream.resources) || stream.resources.length === 0)
      return invalid(`stream '${name}' resources must be a non-empty array`);
    if (new Set(stream.resources).size !== stream.resources.length)
      return invalid(`stream '${name}' resources must be unique`);
    for (const raw of stream.resources) {
      const problem = checkResource(raw);
      if (problem) return invalid(`stream '${name}': ${problem}`);
    }
    // L1189 / AS item 11: "MUST reject a request that has `resources` and
    // more than one `instance_ids` entry for the stream".
    if (Array.isArray(stream.instance_ids) && stream.instance_ids.length > 1)
      return invalid(
        `stream '${name}' carries resources with more than one instance_ids entry`,
      );
  }
  if (stream.time_range !== undefined) {
    const window = checkWindow(
      stream.time_range,
      `stream '${name}' time_range`,
      false,
      locked,
    );
    if (!window.ok) return window;
  }
  if (stream.minimum !== undefined) {
    const minimum = stream.minimum;
    if (!isObject(minimum))
      return invalid(`stream '${name}' minimum must be an object`);
    // spec-core L1258: only `fields` and `time_range`, never empty.
    const extraMin = unknownMembers(minimum, new Set(["fields", "time_range"]));
    if (extraMin.length > 0)
      return invalid(
        `stream '${name}' minimum carries undefined member(s): ${extraMin.join(", ")}`,
      );
    if (minimum.fields === undefined && minimum.time_range === undefined)
      return invalid(`stream '${name}' minimum must not be empty`);
    if (minimum.fields !== undefined && !nonEmptyUniqueStrings(minimum.fields))
      return invalid(
        `stream '${name}' minimum.fields must be a non-empty list of unique names`,
      );
    // spec-core L1260: minimum fields come from the field ceiling. When the
    // request names its fields explicitly, that ceiling is visible without
    // the declaration (schema-required fields aside, which a client cannot
    // know publicly), so a field outside it is checked later, not here.
    if (minimum.time_range !== undefined) {
      const window = checkWindow(
        minimum.time_range,
        `stream '${name}' minimum.time_range`,
        true,
        locked,
      );
      if (!window.ok) return window;
      // L1264: "The AS MUST reject a minimum window outside the requested
      // time window" -- both windows are in the request, so this is public.
      const floor = minimum.time_range as { since: string; until: string };
      const ceiling = stream.time_range as
        { since?: string; until?: string } | undefined;
      const compare = (a: string, b: string): number | null =>
        locked
          ? (() => {
              const type = boundType(a);
              return type && boundType(b) === type
                ? compareTime(a, b, type)
                : null;
            })()
          : compareLegacyTimeBounds(a, b);
      if (ceiling?.since !== undefined) {
        const order = compare(floor.since, ceiling.since);
        if (order === null)
          return invalid(
            `stream '${name}' minimum.time_range and time_range bounds must have the same type`,
          );
        if (order < 0)
          return invalid(
            `stream '${name}' minimum.time_range falls outside the requested time_range`,
          );
      }
      if (ceiling?.until !== undefined) {
        const order = compare(floor.until, ceiling.until);
        if (order === null)
          return invalid(
            `stream '${name}' minimum.time_range and time_range bounds must have the same type`,
          );
        if (order > 0)
          return invalid(
            `stream '${name}' minimum.time_range falls outside the requested time_range`,
          );
      }
    }
  }
  return { ok: true };
}

/**
 * Validate one detail's public structure. `candidateEnabled` mirrors the
 * deployment's profile switch, an owner-independent capability.
 */
export function validatePublicDetail(
  detail: unknown,
  options: { candidateEnabled?: boolean } = {},
): PublicDetailValidation {
  if (!isObject(detail))
    return invalid("each authorization_details entry must be an object");

  // AS item 5 / item 33: an unsupported type is rejected, not reinterpreted.
  const type = detail.type;
  const supported =
    type === PDPP_DATA_ACCESS_TYPE ||
    type === PDPP_DATA_ACCESS_TYPE_V02 ||
    (type === PDPP_DATA_ACCESS_TYPE_CANDIDATE &&
      options.candidateEnabled === true);
  if (!supported)
    return invalid(
      type === PDPP_DATA_ACCESS_TYPE_CANDIDATE
        ? "candidate protocol profile is not enabled on this deployment"
        : `unsupported authorization_details type '${String(type)}'`,
    );
  const locked = usesLockedRules(type as string);

  // AS item 33, spec-core L1099: a member Core does not define is rejected.
  const extra = unknownMembers(detail, DETAIL_MEMBERS);
  if (extra.length > 0)
    return invalid(
      `authorization detail carries undefined member(s): ${extra.join(", ")}`,
    );

  // AS item 14 / L1122 "Closed issuance": malformed, duplicate, unknown or
  // unsupported values are rejected, never ignored or narrowed, and never
  // replaced by an ordinary grant. An empty array requests nothing (L1116).
  if (detail.processing_permissions !== undefined) {
    const permissions = detail.processing_permissions;
    if (
      !Array.isArray(permissions) ||
      !permissions.every((p) => isAbsoluteUri(p))
    )
      return invalid(
        "processing_permissions must be an array of absolute URIs",
      );
    if (new Set(permissions).size !== permissions.length)
      return invalid("processing_permissions must not contain duplicates");
    const unsupported = (permissions as string[]).filter(
      (p) => !SUPPORTED_PROCESSING_PERMISSIONS.includes(p),
    );
    if (unsupported.length > 0)
      return invalid(
        `unsupported processing permission(s): ${unsupported.join(", ")}`,
      );
  }

  // L1087: `source` carries `id` alone, an absolute URI.
  if (!isObject(detail.source)) return invalid("source must be an object");
  const sourceExtra = unknownMembers(detail.source, new Set(["id"]));
  if (sourceExtra.length > 0)
    return invalid(
      `source carries undefined member(s): ${sourceExtra.join(", ")}; provenance is derived, never asserted`,
    );
  // L1087 makes `source.id` an absolute URI. Only non-emptiness is checked
  // here: deployed declarations still use short legacy ids (e.g. `spotify`,
  // see `server/src/pdpp/source-id-compat.ts`), and an id no declaration
  // accepts is an owner-dependent miss that review handles, not a public
  // grammar error.
  if (typeof detail.source.id !== "string" || detail.source.id.length === 0)
    return invalid("source.id must be a non-empty string");

  if (!isAbsoluteUri(detail.purpose_code))
    return invalid("purpose_code must be an absolute URI");
  if (
    detail.purpose_description !== undefined &&
    typeof detail.purpose_description !== "string"
  )
    return invalid("purpose_description must be a string");
  // AS item 6 / L1091: a code outside Appendix A needs a non-empty
  // description the owner can understand. Never rejected on the code alone.
  if (
    locked &&
    !APPENDIX_A_PURPOSE_CODES.has(detail.purpose_code) &&
    (typeof detail.purpose_description !== "string" ||
      detail.purpose_description.trim().length === 0)
  )
    return invalid(
      "purpose_code is outside Appendix A and requires a non-empty purpose_description",
    );

  if (
    detail.access_mode !== "single_use" &&
    detail.access_mode !== "continuous"
  )
    return invalid("access_mode must be single_use or continuous");

  if (detail.retention !== undefined) {
    const retention = detail.retention;
    if (!isObject(retention)) return invalid("retention must be an object");
    const retentionExtra = unknownMembers(
      retention,
      new Set(["max_duration", "on_expiry"]),
    );
    if (retentionExtra.length > 0)
      return invalid(
        `retention carries undefined member(s): ${retentionExtra.join(", ")}`,
      );
    if (retention.on_expiry !== "delete" && retention.on_expiry !== "anonymize")
      return invalid("retention.on_expiry must be delete or anonymize");
    // AS item 31: "Rejects a `retention.max_duration` that is not in the form
    // `PnD`." A positive day count; no other ISO 8601 designator.
    if (
      locked &&
      (typeof retention.max_duration !== "string" ||
        !/^P[1-9][0-9]*D$/.test(retention.max_duration))
    )
      return invalid("retention.max_duration must have the form PnD");
  }

  if (detail.client_claims !== undefined) {
    const claims = detail.client_claims;
    if (!isObject(claims)) return invalid("client_claims must be an object");
    const claimsExtra = unknownMembers(claims, new Set(["commitments"]));
    if (claimsExtra.length > 0)
      return invalid(
        `client_claims carries undefined member(s): ${claimsExtra.join(", ")}`,
      );
    if (
      claims.commitments !== undefined &&
      (!Array.isArray(claims.commitments) ||
        !claims.commitments.every((c) => typeof c === "string"))
    )
      return invalid("client_claims.commitments must be an array of strings");
  }

  const hasStreams = detail.streams !== undefined;
  const hasPreset = detail.selection_preset !== undefined;
  if (hasStreams === hasPreset)
    // AS item 5: the Source validation failure for both/neither.
    return invalid("exactly one of streams or selection_preset is required");
  if (hasPreset) {
    if (
      typeof detail.selection_preset !== "string" ||
      detail.selection_preset.length === 0
    )
      return invalid("selection_preset must be a non-empty string");
    return { ok: true };
  }
  const streams = detail.streams;
  if (!Array.isArray(streams) || streams.length === 0)
    return invalid("streams must be a non-empty array");
  for (const stream of streams) {
    const result = checkStream(stream, locked);
    if (!result.ok) return result;
  }
  const names = streams.map((s) => (s as { name: string }).name);
  if (names.includes("*") && names.length > 1)
    return invalid("a wildcard stream entry must be the only entry in streams");
  if (new Set(names).size !== names.length)
    return invalid("stream names must be unique within the request");
  return { ok: true };
}
