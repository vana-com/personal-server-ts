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
    if (!allowed.includes(key)) {
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
    fields: params
      .get("fields")
      ?.split(",")
      .map((f) => f.trim()),
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
