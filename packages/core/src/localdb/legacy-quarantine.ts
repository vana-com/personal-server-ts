/**
 * Legacy rows an import leaves out, and how that is recorded.
 *
 * A row with no full identity (no primary key, or a key a record cannot hold)
 * cannot become a record. It is left out and counted, by reason, and it never
 * stops the rest of its stream. Whole-stream refusals stay for faults that
 * make the source untrustworthy: a changed source, a conflicting duplicate, a
 * deleted connection, a mismatched declaration.
 *
 * The count outlives the legacy files. It goes on the import receipt, so an
 * audit after the old copies are gone still says what was left out and why.
 */

/**
 * Reasons a row has no full identity. Hosts and folds may add reasons of
 * their own (a row of another source, for one); a reason is a stable name.
 *
 * - `not_an_object`: the source gave a value that is not a JSON object.
 * - `missing_key_field`: a primary-key field is absent from the row.
 * - `bad_key_value`: a key field is null, or not a string, finite number or
 *   boolean. The same rule as run intake and the seed staging.
 * - `unserializable_body`: the row has no canonical JSON form.
 */
export type QuarantineReason =
  | "not_an_object"
  | "missing_key_field"
  | "bad_key_value"
  | "unserializable_body";

/** A valid delete envelope in a layer's records. It is no row to import and no
 * fault: it is counted under this reason so every stored record is accounted
 * for. Like `superseded`, a benign reason. */
export const DELETE_ENVELOPE = "delete_envelope";

const QUARANTINED_ROW = Symbol.for("personal-server-ts.quarantined-row");

/**
 * A row a source has already judged unfit (a row of another source, a row with
 * no identity claim). A source yields it where the row would have been; the
 * import leaves it out and counts it under `reason`, as for any other row.
 */
export class QuarantinedRow {
  /** A registered symbol, so a row is recognised even when a bundler or a test
   * loads this module twice and `instanceof` would fail. */
  readonly [QUARANTINED_ROW] = true;
  constructor(readonly reason: string) {}
}

export function isQuarantinedRow(value: unknown): value is QuarantinedRow {
  return (
    typeof value === "object" &&
    value !== null &&
    (value as Record<symbol, unknown>)[QUARANTINED_ROW] === true
  );
}

/** Rows left out of an import, by reason. Zero counts are absent. */
export type QuarantineCounts = Readonly<Record<string, number>>;

/** Counts rows by reason. A reason is a host's string, so it is held in a
 * `Map`: as a plain-object key, `__proto__` would be dropped and `constructor`
 * would find `Object`'s own function. The counts come out as own properties
 * (`Object.fromEntries`), which `Object.entries` and JSON read back faithfully. */
export function quarantineTally() {
  const counts = new Map<string, number>();
  return {
    add(reason: string, rows = 1) {
      if (rows > 0) counts.set(reason, (counts.get(reason) ?? 0) + rows);
    },
    get total() {
      let sum = 0;
      for (const rows of counts.values()) sum += rows;
      return sum;
    },
    counts: (): QuarantineCounts => Object.fromEntries(counts),
  };
}

/** What an import receipt says about the rows that did not become records. */
export interface ReceiptOutcomes {
  /** Staged rows the fill-only rules kept out (a live row, a deletion, or a
   * removal waiting to publish holds the key). They are in the receipt's
   * `rows`; they are not imported. */
  readonly blocked: number;
  /** Rows left out of the staging, by reason. Not in the receipt's `rows`. */
  readonly quarantined: QuarantineCounts;
}

const PREFIX = "outcomes:";
/** The first format: the quarantine counts alone. Still read. */
const FIRST_PREFIX = "quarantined:";

const positive = (value: unknown): value is number =>
  typeof value === "number" && Number.isSafeInteger(value) && value > 0;

function countsOf(value: unknown): QuarantineCounts {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  // Own properties, so a reason named `__proto__` survives the round trip.
  return Object.fromEntries(
    Object.entries(value).filter(([, rows]) => positive(rows)),
  ) as QuarantineCounts;
}

/** The receipt's `reason`: null for a clean import, else the outcomes. */
export function receiptReason(outcomes: ReceiptOutcomes): string | null {
  const names = Object.keys(outcomes.quarantined).sort();
  if (names.length === 0 && outcomes.blocked === 0) return null;
  return (
    PREFIX +
    JSON.stringify({
      ...(outcomes.blocked > 0 ? { blocked: outcomes.blocked } : {}),
      ...(names.length > 0
        ? {
            quarantined: Object.fromEntries(
              names.map((n) => [n, outcomes.quarantined[n]]),
            ),
          }
        : {}),
    })
  );
}

/** The outcomes an `imported` receipt carries; none for any other reason. */
export function receiptOutcomes(reason: string | null): ReceiptOutcomes {
  const none = { blocked: 0, quarantined: {} };
  if (reason === null) return none;
  try {
    if (reason.startsWith(FIRST_PREFIX))
      return {
        blocked: 0,
        quarantined: countsOf(JSON.parse(reason.slice(FIRST_PREFIX.length))),
      };
    if (!reason.startsWith(PREFIX)) return none;
    const parsed: unknown = JSON.parse(reason.slice(PREFIX.length));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
      return none;
    const { blocked, quarantined } = parsed as Record<string, unknown>;
    return {
      blocked: positive(blocked) ? blocked : 0,
      quarantined: countsOf(quarantined),
    };
  } catch {
    return none;
  }
}
