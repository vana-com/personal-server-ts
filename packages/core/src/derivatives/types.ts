/**
 * Derivative compute layer: a builder registers a QUESTION over the owner's
 * source scopes; the Personal Server answers it locally with an inference
 * provider and writes the answer as an ordinary derivative record (lineage
 * = the source data points) into the derived scope. See
 * docs/derivative-data-api.md, "Compute (question to derivative)".
 */

export type QuestionStatus = "pending" | "ready" | "failed" | "stale";

/**
 * How the answer is computed: `completion` = one chat completion over the
 * newest-first trimmed sources; `agentic` = a bounded tool loop (search +
 * read over the full sources). See docs/derivative-data-api.md, "Agentic
 * mode".
 */
export type QuestionMode = "completion" | "agentic";

/** Who registered the question; a builder is bound to the write grant. */
export type QuestionRegisteredBy =
  | { kind: "owner" }
  | { kind: "builder"; builder: `0x${string}`; grantId: string };

export interface QuestionRegistration {
  questionId: string;
  derivedScope: string;
  sourceScopes: string[];
  /** The prompt template text (the builder's question). */
  question: string;
  /** Model override; null = the provider's default. */
  model: string | null;
  mode: QuestionMode;
  registeredBy: QuestionRegisteredBy;
  status: QuestionStatus;
  /** Short failure reason (never the prompt or the data). Null unless failed. */
  error: string | null;
  createdAt: string;
  updatedAt: string;
  lastComputedAt: string | null;
  /** Local index version of the derived record the last compute wrote. */
  derivedVersion: number | null;
  derivedCollectedAt: string | null;
}

export type QuestionRegistrationPatch = Partial<
  Pick<
    QuestionRegistration,
    | "status"
    | "error"
    | "updatedAt"
    | "lastComputedAt"
    | "derivedVersion"
    | "derivedCollectedAt"
  >
>;

export interface QuestionStoreListFilter {
  derivedScope?: string;
  sourceScope?: string;
  builder?: `0x${string}`;
}

/**
 * Persistence for question registrations. Small and local: registrations
 * never sync (the replica that holds them computes them). Implementations:
 * sqlite (server), a state-store backed map (PS-Lite), in-memory (tests).
 */
export interface QuestionStore {
  list(filter?: QuestionStoreListFilter): Promise<QuestionRegistration[]>;
  get(questionId: string): Promise<QuestionRegistration | null>;
  insert(registration: QuestionRegistration): Promise<void>;
  /** Returns the updated row, or null when the id is unknown. */
  update(
    questionId: string,
    patch: QuestionRegistrationPatch,
  ): Promise<QuestionRegistration | null>;
  delete(questionId: string): Promise<boolean>;
}

/** Public JSON shape of a registration (GET / list / POST responses). */
export interface QuestionRegistrationView {
  questionId: string;
  derivedScope: string;
  sourceScopes: string[];
  question: string;
  model: string | null;
  mode: QuestionMode;
  registeredBy: QuestionRegisteredBy;
  status: QuestionStatus;
  error: string | null;
  createdAt: string;
  updatedAt: string;
  lastComputedAt: string | null;
  derivedVersion: number | null;
  derivedCollectedAt: string | null;
}

export function questionRegistrationView(
  registration: QuestionRegistration,
): QuestionRegistrationView {
  return {
    questionId: registration.questionId,
    derivedScope: registration.derivedScope,
    sourceScopes: [...registration.sourceScopes],
    question: registration.question,
    model: registration.model,
    mode: registration.mode,
    registeredBy: registration.registeredBy,
    status: registration.status,
    error: registration.error,
    createdAt: registration.createdAt,
    updatedAt: registration.updatedAt,
    lastComputedAt: registration.lastComputedAt,
    derivedVersion: registration.derivedVersion,
    derivedCollectedAt: registration.derivedCollectedAt,
  };
}
