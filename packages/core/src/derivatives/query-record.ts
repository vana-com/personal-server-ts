/**
 * The adapter that turns a query-layer `QueryAnswer` into the derivative
 * answer record the builder docs publish (§2.4), so a query-layer answer can
 * be persisted at a derived scope and read back through
 * `GET /v1/data/<derivedScope>` like any other derived record.
 *
 * ## Why an adapter and not an engine swap
 *
 * `compute.ts` keeps calling the completion path. Nothing here is wired into
 * it. This exists so the swap is a *later* change of one call site rather than
 * a simultaneous change of the persisted contract: the record shape is pinned
 * and tested first, on its own.
 *
 * ## The one property that governs every decision below
 *
 * The record must be **indistinguishable in shape from a completion-path
 * record** — a builder must not be able to tell which engine produced the
 * answer. `compute.ts`'s literal (`compute.ts`, `DerivativeAnswerRecord` and
 * the object built beside `ingestDataContract`) is therefore the whole
 * specification, and the interesting work is deciding what happens to the
 * `QueryAnswer` fields that have no slot in it. Every one of them is dropped:
 * see {@link buildQueryAnswerRecord} for the field-by-field argument. A key
 * present only on query-layer records would be exactly the tell this property
 * forbids, and — because `dataHash` commits to the record — it would also be a
 * permanent public contract.
 *
 * ## What this deliberately does NOT do
 *
 * - It does not build `$lineage`. `$lineage` is server-stamped by
 *   `stampLineage` inside `ingestDataContract`, and `ingestDataContract`
 *   rejects a body that already carries the key (`contracts/data.ts`,
 *   `hasReservedLineageKey` ⇒ 400 `INVALID_BODY`). So this returns the
 *   caller-side {@link StoredLineage} to *pass* to that path, exactly as
 *   `compute.ts` does, and the record itself carries only the mirrored
 *   `lineage` field.
 * - It does not emit `coverage`. See the seam in
 *   {@link buildQueryAnswerRecord}.
 */

import type { StoredLineage } from "../lineage/lineage.js";
import { computeDataPointId } from "../sync/data-point-id.js";
import type { QueryAnswer } from "../query/agent/types.js";
import type { DerivativeAnswerRecord } from "./compute.js";
import type { QuestionRegistration } from "./types.js";

/**
 * One source scope as the **host** saw it, which is the only authority for a
 * `sources[]` entry.
 *
 * `version` and `collectedAt` are optional here because they are optional at
 * every seam the query layer reads through — `McpDataReadEnvelopeResult.version`
 * and, downstream of it, the query service's own scope payload and
 * materialized-scope shapes. They are *required* by the record, so a missing
 * one is refused rather than defaulted: see
 * {@link QueryRecordMappingError}.
 */
export interface QueryRecordSource {
  scope: string;
  /**
   * The local index version of the read. Accepted as a string because the
   * read client reports `String(entry.version)`; it must parse to a safe
   * integer.
   */
  version?: string | number;
  collectedAt?: string;
}

export interface BuildQueryAnswerRecordInput {
  /**
   * The registration, passed whole and read verbatim.
   *
   * The record's `question` is the builder's stale-answer check: they compare
   * it (trimmed) against the question they registered and must not act on a
   * mismatch. So it is taken straight off the registration row and never
   * reconstructed from the answer, re-derived from a prompt, trimmed,
   * normalized or re-encoded here. Taking the registration rather than a bare
   * string is the point: there is no argument for a caller to hand-assemble.
   */
  registration: Pick<QuestionRegistration, "questionId" | "question">;
  answer: QueryAnswer;
  /**
   * Host-authored descriptors for the scopes the host made readable to the
   * run. Entries for scopes the run never read are ignored.
   */
  sources: readonly QueryRecordSource[];
  /** The model that actually answered. `QueryAnswer` does not carry it. */
  model: string;
  /** The write's timestamp. `QueryAnswer` does not carry one. */
  computedAt: string;
  /** For `computeDataPointId`, the same input `compute.ts` gives it. */
  serverOwner: string;
}

export interface QueryAnswerRecordBuild {
  record: DerivativeAnswerRecord;
  /**
   * Pass to `ingestDataContract({ lineage })`, which stamps `$lineage`. Never
   * merge it into `record`.
   */
  lineage: StoredLineage;
}

/**
 * The mapping could not be completed honestly.
 *
 * Fails closed on purpose. A record whose `sources[]` silently omits a scope
 * the run demonstrably read, or carries a defaulted version for one, is a
 * false provenance statement wearing the shape of a true one — and the
 * completion path can never produce one, so a consumer has no reason to
 * suspect it. Refusing to build the record is the only outcome that keeps
 * `sources[]` worth reading.
 */
export class QueryRecordMappingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "QueryRecordMappingError";
  }
}

function readVersion(
  scope: string,
  version: string | number | undefined,
): number {
  if (version === undefined) {
    throw new QueryRecordMappingError(
      `scope ${scope} was read but the host reported no version for it`,
    );
  }
  const parsed = typeof version === "number" ? version : Number(version);
  if (!Number.isSafeInteger(parsed)) {
    throw new QueryRecordMappingError(
      `scope ${scope} was read but its version is not an integer`,
    );
  }
  return parsed;
}

/**
 * Map a `QueryAnswer` onto a `DerivativeAnswerRecord` plus the lineage to
 * stamp with it.
 *
 * ## `sources[]` — host-authored, and NOT from the citations
 *
 * `sources[]` on a completion-path record is unforgeable host provenance: the
 * scopes whose data entered the computation, each with the exact version read.
 * (It is `{scope, version, collectedAt}`. It is *not* a list of data point ids
 * — those live in the `lineage` field, mirrored to `$lineage`.)
 *
 * `QueryAnswer.citations` cannot fill it, and the reason is not a missing
 * lookup:
 *
 * 1. A `QueryCitation` is `{scope, recordId?, blockRef?}`. It carries neither
 *    `version` nor `collectedAt` — two of the three required fields — and
 *    nothing in the query layer records a version *per citation*.
 * 2. Citations are **model-authored**: they are parsed out of the model's
 *    `vana:answer` block, and the parser accepts any string as a scope. A
 *    citation can therefore name a scope the host never read. Routing that
 *    into `sources[]` would put model-authored data behind a host-authored
 *    key, which is the same category error as putting host-authored coverage
 *    behind the model-authored `evidence` key, run in the opposite direction.
 * 3. `recordId`/`blockRef` point at a record *inside* a scope. A `sources[]`
 *    entry is a per-scope version pointer. Different granularity; no join
 *    exists between them.
 *
 * So `sources[]` is built from the two host-authored facts that do exist:
 * `answer.coverage.scopesScanned` (only a confined run can move it) selects
 * *which* scopes, and {@link QueryRecordSource} supplies each one's version
 * and `collectedAt`. Citations contribute nothing and are dropped.
 *
 * The scanned list is de-duplicated and **sorted here**, not trusted as it
 * arrives: the per-run coverage merge unions it with a `Set`, so its order is
 * read order across runs. `dataHash` is a canonical-JSON commitment, and JCS
 * preserves array order — so an unsorted `sources[]` would make the hash a
 * function of the order the model happened to read in rather than of content.
 *
 * ## `evidence: null`
 *
 * `evidence` is model-authored prose — "a short summary of which parts of the
 * data support the answer", asked for by name in the completion path's prompt
 * and read straight off the model's JSON. The query layer's response contract
 * has no such field: nothing the model writes in a `vana:answer` block answers
 * that question in prose.
 *
 * `null` is the honest value, and it is already in contract: `parseAnswer`
 * returns `evidence: null` whenever the completion-path model omits it, so a
 * builder's null handling is already exercised by records this engine did not
 * write. The alternatives are all worse:
 *
 * - Synthesizing a sentence from citations or coverage would be *host*-authored
 *   text behind a model-authored key. Coverage's whole value is that it is
 *   host-authored and unforgeable; laundering it through `evidence` destroys
 *   that distinction for every reader of the field.
 * - `QueryAnswer.resolution` *is* model-authored, but it answers a different
 *   question — which set was aggregated over, not what supports the answer.
 *   Putting it here would silently redefine the field for anyone reading a
 *   scope that both engines write into.
 *
 * ## Everything else on `QueryAnswer` is dropped
 *
 * `determinism`, `cost`, `value`, `resolution`, `script`, `citations` and
 * `receiptIds` have no slot in the documented envelope, and each is dropped
 * rather than carried additively:
 *
 * - **`determinism`** — always `"generated"` on this path; the loop hardcodes
 *   it. A constant is not information.
 * - **`cost`** — host-authored run telemetry about *producing* the answer, not
 *   about the answer. Persisting it would publish the server's token and relay
 *   volumes to every grantee of the scope, and would make `dataHash` depend on
 *   token counts, so two recomputes over byte-identical data would hash
 *   differently. It already travels on `QueryEvent`, which is where operational
 *   telemetry belongs.
 * - **`value`**, **`resolution`** — genuinely useful and genuinely model-
 *   authored, but the completion path emits no counterpart, so either one would
 *   make the engine detectable. If builders need a typed numeric answer or a
 *   stated set resolution, the field has to be added to *both* engines'
 *   records, which is a contract decision and not this adapter's to take.
 * - **`script`** — model-authored code of unbounded size. It is the run's
 *   reproducibility artifact, which belongs with the run record, not inside a
 *   record a third party reads as an answer.
 * - **`citations`** — see `sources[]` above. Provenance is already carried,
 *   host-authored, by `sources[]` and `lineage`.
 * - **`receiptIds`** — the envelope's optional `inference.receiptId` is
 *   singular by construction, and a query run puts many calls on the wire.
 *   Collapsing N receipts to one would be arbitrary, so `inference` is omitted
 *   entirely — which is in contract: the completion path omits it too whenever
 *   the provider returned no receipt.
 *
 * ## Seam: `coverage` is NOT emitted here — deliberately, do not fill it in
 *
 * `coverage` is the next piece of work and it has a hard prerequisite that is
 * not met yet. `dataHash` is now a canonical-JSON commitment (`json/jcs.ts`,
 * used by `sync/workers/upload.ts`), so every key order in a persisted record
 * must be a function of content. Today's coverage object is assembled in
 * `query/agent/loop.ts` by spreading the host snapshot and then conditionally
 * mutating it, and it carries a `perScope` map whose key order is read order.
 * Persisting it as-is would make the golden commitment depend on the order the
 * model read in.
 *
 * Before adding a `coverage` key to this literal:
 *
 * 1. Emit coverage through a **fixed object literal**, not spread-then-mutate.
 * 2. **Drop `perScope`, or key-sort it.**
 *
 * Until both hold, the record carries no coverage. `queryAnswerRecordKeys`
 * pins the current key set so that adding one is a deliberate, visible change.
 */
export function buildQueryAnswerRecord(
  input: BuildQueryAnswerRecordInput,
): QueryAnswerRecordBuild {
  const { registration, answer, model, computedAt, serverOwner } = input;

  const descriptors = new Map<string, QueryRecordSource>();
  for (const source of input.sources) descriptors.set(source.scope, source);

  const scanned = [...new Set(answer.coverage.scopesScanned)].sort();
  const sources = scanned.map((scope) => {
    const descriptor = descriptors.get(scope);
    if (!descriptor) {
      throw new QueryRecordMappingError(
        `scope ${scope} was read but the host reported no source for it`,
      );
    }
    if (!descriptor.collectedAt) {
      throw new QueryRecordMappingError(
        `scope ${scope} was read but the host reported no collectedAt for it`,
      );
    }
    return {
      scope,
      version: readVersion(scope, descriptor.version),
      collectedAt: descriptor.collectedAt,
    };
  });

  const lineageIds = scanned.map((scope) =>
    computeDataPointId(serverOwner, scope),
  );

  // A fixed object literal, in the completion path's key order, with no
  // conditional keys: the serialized shape of a query-layer record is then a
  // function of the field values alone.
  const record: DerivativeAnswerRecord = {
    questionId: registration.questionId,
    question: registration.question,
    answer: answer.answer,
    evidence: null,
    model,
    computedAt,
    sources,
    lineage: lineageIds,
  };

  return {
    record,
    lineage: { sources: lineageIds, writtenAt: computedAt },
  };
}

/**
 * The exact key set a query-layer record carries.
 *
 * Exported so the seam above is enforced rather than merely documented: a new
 * key — `coverage` most of all — has to change this list, and its test, on
 * purpose.
 */
export const queryAnswerRecordKeys = [
  "questionId",
  "question",
  "answer",
  "evidence",
  "model",
  "computedAt",
  "sources",
  "lineage",
] as const;
