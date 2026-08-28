import type {
  QuestionRegistration,
  QuestionRegistrationPatch,
  QuestionStore,
  QuestionStoreListFilter,
} from "./types.js";

function clone(registration: QuestionRegistration): QuestionRegistration {
  return {
    ...registration,
    sourceScopes: [...registration.sourceScopes],
    registeredBy: { ...registration.registeredBy },
  };
}

export function matchesQuestionFilter(
  registration: QuestionRegistration,
  filter: QuestionStoreListFilter | undefined,
): boolean {
  if (!filter) return true;
  if (filter.derivedScope && registration.derivedScope !== filter.derivedScope)
    return false;
  if (
    filter.sourceScope &&
    !registration.sourceScopes.includes(filter.sourceScope)
  )
    return false;
  if (filter.builder) {
    const by = registration.registeredBy;
    if (
      by.kind !== "builder" ||
      by.builder.toLowerCase() !== filter.builder.toLowerCase()
    )
      return false;
  }
  return true;
}

/** Oldest first, the order every store lists in. */
export function sortQuestions(
  registrations: QuestionRegistration[],
): QuestionRegistration[] {
  return [...registrations].sort(
    (a, b) =>
      a.createdAt.localeCompare(b.createdAt) ||
      a.questionId.localeCompare(b.questionId),
  );
}

/**
 * Map-backed store. The PS-Lite store wraps it with persistence; tests use
 * it as is.
 */
export function createInMemoryQuestionStore(
  options: {
    /** Called after every mutation with the full current list. */
    onChange?: (registrations: QuestionRegistration[]) => Promise<void>;
    initial?: QuestionRegistration[];
  } = {},
): QuestionStore {
  const byId = new Map<string, QuestionRegistration>();
  for (const registration of options.initial ?? []) {
    byId.set(registration.questionId, clone(registration));
  }
  async function changed(): Promise<void> {
    if (!options.onChange) return;
    await options.onChange(sortQuestions([...byId.values()]).map(clone));
  }
  return {
    async list(filter) {
      return sortQuestions(
        [...byId.values()].filter((registration) =>
          matchesQuestionFilter(registration, filter),
        ),
      ).map(clone);
    },
    async get(questionId) {
      const registration = byId.get(questionId);
      return registration ? clone(registration) : null;
    },
    async insert(registration) {
      if (byId.has(registration.questionId)) {
        throw new Error(
          `Question ${registration.questionId} is already registered`,
        );
      }
      byId.set(registration.questionId, clone(registration));
      await changed();
    },
    async update(questionId, patch: QuestionRegistrationPatch) {
      const current = byId.get(questionId);
      if (!current) return null;
      const next = { ...current, ...patch };
      byId.set(questionId, next);
      await changed();
      return clone(next);
    },
    async delete(questionId) {
      const existed = byId.delete(questionId);
      if (existed) await changed();
      return existed;
    },
  };
}
