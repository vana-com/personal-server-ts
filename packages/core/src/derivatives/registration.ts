/**
 * Question registration: input validation, the naming rule (shared with the
 * lineage write path) and the cycle guard that keeps recompute-on-refresh
 * bounded.
 */

import {
  DerivativeCycleError,
  DerivativeQuestionInvalidError,
} from "../errors/catalog.js";
import { parseDataScopeContract } from "../contracts/data.js";
import { assertDerivedScopeNaming } from "../lineage/lineage.js";
import { isWriteScopeEntry } from "../policy/data-write.js";
import { scopeCoveredByGrant } from "@opendatalabs/vana-sdk/browser";
import type {
  QuestionMode,
  QuestionRegisteredBy,
  QuestionRegistration,
  QuestionStore,
} from "./types.js";

export const MAX_QUESTION_SOURCE_SCOPES = 16;
export const MAX_QUESTION_CHARS = 8_000;
export const MAX_MODEL_CHARS = 128;
/** Unvalidated scope strings echoed in 400 details are cut to this. */
export const MAX_ECHOED_SCOPE_CHARS = 128;

/** Model ids as providers spell them (`z-ai/glm-5.2`, `gpt-4o-mini`, ...). */
const MODEL_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]*$/;

export interface ParsedQuestionInput {
  derivedScope: string;
  sourceScopes: string[];
  question: string;
  model: string | null;
  mode: QuestionMode;
}

/** Accepted `mode` values, in the order they are echoed in a 400. */
export const QUESTION_MODES: readonly QuestionMode[] = ["completion", "code"];

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function parseScope(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw new DerivativeQuestionInvalidError(
      `${field} must be a scope string`,
      {
        field,
      },
    );
  }
  const parsed = parseDataScopeContract(value);
  if (!parsed.ok) {
    throw new DerivativeQuestionInvalidError(
      `${field} is not a valid scope: ${parsed.body.message}`,
      { field, scope: value.slice(0, MAX_ECHOED_SCOPE_CHARS) },
    );
  }
  return parsed.scope;
}

/**
 * Validate the POST body of a question registration. Throws 400
 * DERIVATIVE_QUESTION_INVALID on shape errors and 400
 * LINEAGE_SCOPE_UNDER_SOURCE_PREFIX when the derived scope shares its
 * first segment with a source (the lineage naming rule, applied up front
 * so a registration that could never be written is refused here).
 */
export function parseQuestionInput(body: unknown): ParsedQuestionInput {
  if (!isRecord(body)) {
    throw new DerivativeQuestionInvalidError("Body must be a JSON object");
  }
  const derivedScope = parseScope(body.derivedScope, "derivedScope");
  if (!Array.isArray(body.sourceScopes) || body.sourceScopes.length === 0) {
    throw new DerivativeQuestionInvalidError(
      "sourceScopes must be a non-empty array of scopes",
      { field: "sourceScopes" },
    );
  }
  if (body.sourceScopes.length > MAX_QUESTION_SOURCE_SCOPES) {
    throw new DerivativeQuestionInvalidError(
      `sourceScopes lists ${body.sourceScopes.length} scopes; the maximum is ${MAX_QUESTION_SOURCE_SCOPES}`,
      { field: "sourceScopes", max: MAX_QUESTION_SOURCE_SCOPES },
    );
  }
  const sourceScopes: string[] = [];
  for (const entry of body.sourceScopes) {
    const scope = parseScope(entry, "sourceScopes[]");
    if (sourceScopes.includes(scope)) {
      throw new DerivativeQuestionInvalidError(
        "sourceScopes lists the same scope twice",
        { field: "sourceScopes", duplicate: scope },
      );
    }
    if (scope === derivedScope) {
      throw new DerivativeQuestionInvalidError(
        "derivedScope cannot be one of its own sources",
        { field: "sourceScopes", scope },
      );
    }
    sourceScopes.push(scope);
  }
  if (typeof body.question !== "string" || body.question.trim() === "") {
    throw new DerivativeQuestionInvalidError(
      "question must be a non-empty string",
      { field: "question" },
    );
  }
  if (body.question.length > MAX_QUESTION_CHARS) {
    throw new DerivativeQuestionInvalidError(
      `question is ${body.question.length} characters; the maximum is ${MAX_QUESTION_CHARS}`,
      { field: "question", max: MAX_QUESTION_CHARS },
    );
  }
  let model: string | null = null;
  if (body.model !== undefined && body.model !== null) {
    if (
      typeof body.model !== "string" ||
      body.model.length > MAX_MODEL_CHARS ||
      !MODEL_ID.test(body.model)
    ) {
      throw new DerivativeQuestionInvalidError(
        "model must be a provider model id",
        { field: "model" },
      );
    }
    model = body.model;
  }
  // Absent or null means the shipping path, so an existing client that has
  // never heard of `mode` keeps working unchanged.
  let mode: QuestionMode = "completion";
  if (body.mode !== undefined && body.mode !== null) {
    if (
      typeof body.mode !== "string" ||
      !QUESTION_MODES.includes(body.mode as QuestionMode)
    ) {
      throw new DerivativeQuestionInvalidError(
        `mode must be one of ${QUESTION_MODES.map((m) => `"${m}"`).join(", ")}`,
        { field: "mode" },
      );
    }
    mode = body.mode as QuestionMode;
  }
  assertDerivedScopeNaming(derivedScope, sourceScopes);
  return { derivedScope, sourceScopes, question: body.question, model, mode };
}

/**
 * Recompute-on-refresh follows edges source -> derived. A registration whose
 * derived scope can reach one of its own sources through other
 * registrations would recompute forever (A from B, B from A). Refuse it.
 * Returns the offending path (derived scope back to itself) or null.
 */
export function findDerivationCycle(
  candidate: Pick<QuestionRegistration, "derivedScope" | "sourceScopes">,
  existing: readonly Pick<
    QuestionRegistration,
    "derivedScope" | "sourceScopes"
  >[],
): string[] | null {
  // derived scope -> the scopes it is computed from
  const sourcesOf = new Map<string, Set<string>>();
  const add = (derived: string, sources: readonly string[]) => {
    const set = sourcesOf.get(derived) ?? new Set<string>();
    for (const source of sources) set.add(source);
    sourcesOf.set(derived, set);
  };
  for (const registration of existing) {
    add(registration.derivedScope, registration.sourceScopes);
  }
  add(candidate.derivedScope, candidate.sourceScopes);

  // Depth-first from the candidate's derived scope through the sources it
  // depends on; reaching the derived scope again is a cycle. Bounded by the
  // number of distinct scopes (visited set), so no unbounded walk.
  const target = candidate.derivedScope;
  const visited = new Set<string>();
  const stack: Array<{ scope: string; path: string[] }> = [
    { scope: target, path: [target] },
  ];
  while (stack.length > 0) {
    const { scope, path } = stack.pop()!;
    for (const source of sourcesOf.get(scope) ?? []) {
      if (source === target) return [...path, source];
      if (visited.has(source)) continue;
      visited.add(source);
      stack.push({ scope: source, path: [...path, source] });
    }
  }
  return null;
}

export interface CreateQuestionRegistrationInput {
  body: unknown;
  registeredBy: QuestionRegisteredBy;
  store: QuestionStore;
  questionId: string;
  now: () => Date;
}

/**
 * Validate, guard against cycles and persist a registration in `pending`.
 * The caller has already authorized the write on `derivedScope`.
 */
export async function createQuestionRegistration(
  input: CreateQuestionRegistrationInput,
): Promise<QuestionRegistration> {
  const parsed = parseQuestionInput(input.body);
  const cycle = findDerivationCycle(parsed, await input.store.list());
  if (cycle) {
    throw new DerivativeCycleError({
      derivedScope: parsed.derivedScope,
      path: cycle,
    });
  }
  const at = input.now().toISOString();
  const registration: QuestionRegistration = {
    questionId: input.questionId,
    derivedScope: parsed.derivedScope,
    sourceScopes: parsed.sourceScopes,
    question: parsed.question,
    model: parsed.model,
    mode: parsed.mode,
    registeredBy: input.registeredBy,
    status: "pending",
    error: null,
    createdAt: at,
    updatedAt: at,
    lastComputedAt: null,
    derivedVersion: null,
    derivedCollectedAt: null,
  };
  await input.store.insert(registration);
  return registration;
}

/**
 * Consent check for a builder question: the sources feed a prompt whose
 * answer the builder reads, so every source scope must be covered by a READ
 * entry of the builder's grant (bare entries; `write:` entries confer
 * nothing). Returns the uncovered scopes; empty = all covered. The system
 * prompt is not a security boundary, this is.
 */
export function uncoveredSourceScopes(
  sourceScopes: readonly string[],
  grantScopes: readonly string[] | undefined,
): string[] {
  const readEntries = (grantScopes ?? []).filter(
    (entry) => !isWriteScopeEntry(entry),
  );
  return sourceScopes.filter(
    (scope) => !scopeCoveredByGrant(scope, readEntries),
  );
}
