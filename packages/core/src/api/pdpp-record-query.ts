import { PdppError } from "../errors/pdpp-catalog.js";

const PARAMETERS = {
  listStreams: [],
  streamMetadata: [],
  listRecords: [
    "limit",
    "order",
    "cursor",
    "fields",
    "changes_since",
    "source",
  ],
  // spec-core §8 "Get a single record" / "Delete a record": `instance_id`
  // selects the record's instance (RS items 1, 23).
  getRecord: ["fields", "instance_id"],
  deleteRecord: ["instance_id"],
  // spec-core §8 "Get a blob": `instance_id` is the only parameter, and an
  // unknown one is a 400 like on every other route (RS items 10, 23).
  getBlob: ["instance_id"],
} satisfies Record<string, string[]>;

type Endpoint = keyof typeof PARAMETERS;

/** The sole parsing boundary for canonical record read queries. */
export function parseRecordQuery(
  url: string,
  endpoint: Endpoint,
  tokenKind?: "owner" | "client",
) {
  const params = new URL(url).searchParams;
  const allowed: readonly string[] = PARAMETERS[endpoint];
  for (const key of params.keys()) {
    // spec-core §8 "List records": "A `changes_since` request with
    // `expand[]` or `expand_limit[...]` is rejected with 400
    // `invalid_request` for every token kind" (RS item 21).
    const base = key.replace(/\[.*$/, "");
    if (
      params.has("changes_since") &&
      (base === "expand" || base === "expand_limit")
    ) {
      throw new PdppError(
        "invalid_request",
        "Expansion is not supported on a changes_since request",
        { param: key },
      );
    }
    // spec-core §8: `view` is an owner-token current-capability read;
    // client-token record requests reject it (below, as unsupported).
    const ownerView =
      key === "view" &&
      tokenKind === "owner" &&
      (endpoint === "listRecords" || endpoint === "getRecord");
    if (!allowed.includes(key) && !ownerView) {
      const ownerExpand =
        tokenKind === "owner" &&
        (endpoint === "listRecords" || endpoint === "getRecord") &&
        (base === "expand" || base === "expand_limit");
      throw new PdppError(
        ownerExpand ? "invalid_expand" : "invalid_request",
        ownerExpand
          ? "No expandable relation is declared"
          : `Unsupported query parameter '${key}'`,
        { param: key },
      );
    }
    if (params.getAll(key).length !== 1) {
      throw new PdppError(
        "invalid_request",
        `Parameter '${key}' must occur once`,
        { param: key },
      );
    }
  }
  const rawLimit = params.get("limit");
  const limit = rawLimit === null ? 25 : Number(rawLimit);
  if (
    rawLimit !== null &&
    (!/^[0-9]+$/.test(rawLimit) || !Number.isSafeInteger(limit) || limit <= 0)
  ) {
    throw new PdppError(
      "invalid_request",
      "limit must be a positive safe integer",
      { param: "limit" },
    );
  }
  if (params.has("view") && params.has("fields")) {
    throw new PdppError(
      "invalid_request",
      "Parameters 'view' and 'fields' are mutually exclusive",
      { param: "view" },
    );
  }
  const rawFields = params.get("fields");
  const fieldNames = rawFields?.split(",").map((f) => f.trim());
  // An empty name is malformed, not a field outside the grant.
  if (fieldNames?.some((f) => f === "")) {
    throw new PdppError("invalid_request", "fields names must not be empty", {
      param: "fields",
    });
  }
  const order = params.get("order") ?? "desc";
  if (order !== "asc" && order !== "desc") {
    throw new PdppError("invalid_request", "order must be 'asc' or 'desc'", {
      param: "order",
    });
  }
  return {
    limit: Math.min(limit, 100),
    clamped: limit > 100,
    order: order as "asc" | "desc",
    fields: fieldNames,
    view: params.get("view") ?? undefined,
    cursor: params.get("cursor") ?? undefined,
    changesSince: params.get("changes_since") ?? undefined,
    source: params.get("source") ?? undefined,
    instanceId: params.get("instance_id") ?? undefined,
  };
}

/**
 * The count grade a `Prefer` header asks for (`count=none|estimated|exact`),
 * read among its other tokens. Anything else is `none`: a count is opt-in.
 */
export function requestedCountGrade(
  prefer: string | null | undefined,
): "none" | "estimated" | "exact" {
  for (const token of (prefer ?? "").split(",")) {
    const [name, value] = token.split("=").map((part) => part.trim());
    if (
      name?.toLowerCase() === "count" &&
      (value === "estimated" || value === "exact")
    )
      return value;
  }
  return "none";
}
