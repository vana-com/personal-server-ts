/**
 * `PDPP-Version` negotiation for the Resource Server operations of PDPP Core
 * v0.1.0 (spec-core.md §8 "API versioning").
 *
 * The locked spec assigns the RS HTTP contract the identifier `0.1`:
 *
 * - An absent field selects `0.1`.
 * - A present field must be one RFC 9110 token. An empty value, a quoted
 *   string, a comma-separated list or duplicate field lines (which HTTP
 *   field parsing joins with a comma) is invalid: HTTP 400 `invalid_request`,
 *   `param: "PDPP-Version"`.
 * - A valid token that is not a supported identifier gets HTTP 400
 *   `unsupported_version`. "`0.1.0`, `v0.1`, and `2026-04-06` are not aliases
 *   for `0.1`", so the earlier date-shaped value this server used to send is
 *   now refused rather than mapped.
 * - When negotiation fails no contract is selected, and the response omits
 *   `PDPP-Version`.
 *
 * `PDPP-Version` does not negotiate OAuth authorization, token, revocation or
 * introspection endpoints (spec-core.md §8; §9 AS item 17 is "Not used"), so
 * the Authorization Server surface does not call this.
 */
export const PDPP_VERSION = "0.1";

/** The RS contracts this server implements. Exactly one in v0.1.0. */
export const SUPPORTED_PDPP_VERSIONS: readonly string[] = [PDPP_VERSION];

/** RFC 9110 §5.6.2 `token`: one or more tchar. */
const TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

export type PdppVersionNegotiation =
  | { ok: true; selected: string }
  | {
      ok: false;
      code: "invalid_request" | "unsupported_version";
      message: string;
    };

/**
 * Select the RS contract for a request.
 *
 * `raw` is the field value after HTTP parsing (`Headers.get`): `null` or
 * `undefined` when the field is absent. Surrounding whitespace is removed by
 * HTTP parsing, so it is trimmed here as well; interior whitespace is not a
 * token character and is invalid.
 */
export function negotiatePdppVersion(
  raw: string | null | undefined,
): PdppVersionNegotiation {
  if (raw === null || raw === undefined) {
    return { ok: true, selected: PDPP_VERSION };
  }
  const value = raw.trim();
  if (!TOKEN.test(value)) {
    return {
      ok: false,
      code: "invalid_request",
      message:
        "PDPP-Version must be exactly one HTTP token (no empty value, quotes, list or duplicate field)",
    };
  }
  if (!SUPPORTED_PDPP_VERSIONS.includes(value)) {
    return {
      ok: false,
      code: "unsupported_version",
      message: "Unsupported HTTP API contract.",
    };
  }
  return { ok: true, selected: value };
}
