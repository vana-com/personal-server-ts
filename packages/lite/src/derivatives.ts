/**
 * PS-Lite wiring for the derivative compute layer: a question store that
 * persists through the runtime's state store, and the compute + scheduler
 * built on the browser-safe core pieces (fetch-based inference provider).
 */

import type { ServerConfig } from "@opendatalabs/personal-server-ts-core/schemas";
import type {
  DataStoragePort,
  RuntimeAvailabilityPort,
} from "@opendatalabs/personal-server-ts-core/ports";
import type { ScopeDeletionTracker } from "@opendatalabs/personal-server-ts-core/sync";
import type { DataWritePolicyPorts } from "@opendatalabs/personal-server-ts-core/policy";
import {
  computeQuestion,
  createInMemoryQuestionStore,
  createOpenAiCompatibleInferenceProvider,
  createPhalaE2eeEncryption,
  createRecomputeScheduler,
  DEFAULT_INFERENCE_BASE_URL,
  type ComputeSyncNotifier,
  type InferenceProvider,
  type QuestionRegistration,
  type QuestionStore,
  type RecomputeScheduler,
} from "@opendatalabs/personal-server-ts-core/derivatives";
import type { Logger } from "@opendatalabs/personal-server-ts-core/logger";
import type { RequestSigner } from "@opendatalabs/personal-server-ts-core/signing";
import type { PsLiteStateStore } from "./state.js";

const QUESTIONS_KEY = "derivative-questions-v1";

/** What older builds persisted: `recompute` did not exist yet. */
type PersistedQuestionRegistration = Omit<QuestionRegistration, "recompute"> &
  Partial<Pick<QuestionRegistration, "recompute">>;

interface PsLiteQuestionsState {
  version: 1;
  questions: PersistedQuestionRegistration[];
}

/** A question store persisted as one JSON value in the PS-Lite state store. */
export async function createPsLiteQuestionStore(
  stateStore: PsLiteStateStore,
): Promise<QuestionStore> {
  const saved = await stateStore.get<PsLiteQuestionsState>(QUESTIONS_KEY);
  // Registrations saved before the recompute policy existed keep the old
  // follow-every-change behavior.
  const initial = (saved?.version === 1 ? saved.questions : []).map(
    (question) => ({
      ...question,
      recompute: question.recompute ?? "on-change",
    }),
  );
  return createInMemoryQuestionStore({
    initial,
    onChange: (questions) =>
      stateStore.set<PsLiteQuestionsState>(QUESTIONS_KEY, {
        version: 1,
        questions,
      }),
  });
}

/**
 * The browser build must not call a provider directly with no key: the
 * default base URL is a direct provider, so the compute layer only comes up
 * when `inference.baseUrl` names a relay (or a provider is injected).
 */
export function psLiteInferenceConfigured(config: ServerConfig): boolean {
  return (
    config.inference.baseUrl.replace(/\/+$/, "") !==
    DEFAULT_INFERENCE_BASE_URL.replace(/\/+$/, "")
  );
}

export interface PsLiteDerivativeComputeOptions {
  config: ServerConfig;
  storage: DataStoragePort;
  store: QuestionStore;
  serverOwner: `0x${string}` | undefined;
  /** Resolved per compute so a sync manager created later is still seen. */
  syncManager?: () => ComputeSyncNotifier | null | undefined;
  /** Same: the tracker is built together with the sync manager. */
  scopeDeletions?: () => ScopeDeletionTracker | undefined;
  writePolicyPorts?: DataWritePolicyPorts;
  /** Computes are skipped (status untouched) while the runtime is inactive. */
  runtimeAvailability?: RuntimeAvailabilityPort;
  /** Defaults to the OpenAI-compatible client on `config.inference`. */
  provider?: InferenceProvider;
  /**
   * Signs the relay calls (chat completion and attested-key fetch) as this
   * personal server: the same signer the gateway registration and the
   * lineage reads use in the browser. Without it the relay answers 401.
   */
  requestSigner?: RequestSigner;
  logger?: Logger;
  now?: () => Date;
}

export interface PsLiteDerivativeCompute {
  store: QuestionStore;
  scheduler: RecomputeScheduler;
  provider: InferenceProvider;
}

export function createPsLiteDerivativeCompute(
  options: PsLiteDerivativeComputeOptions,
): PsLiteDerivativeCompute {
  const logger = options.logger
    ? {
        info: (payload: Record<string, unknown>, message: string) =>
          options.logger?.info(payload, message),
        warn: (payload: Record<string, unknown>, message: string) =>
          options.logger?.warn(payload, message),
      }
    : undefined;
  const provider =
    options.provider ??
    createOpenAiCompatibleInferenceProvider({
      baseUrl: options.config.inference.baseUrl,
      model: options.config.inference.model,
      // PS-Lite holds no provider key: it always talks to the Vana relay,
      // which forwards only requests signed as the owner's server.
      requestSigner: options.requestSigner,
      // E2EE v2 to the Phala gateway (WebCrypto only, so it runs in the
      // browser): the relay sees ciphertext. `inference.e2ee: false` turns
      // it off for local development against a provider without ACI.
      encryption: options.config.inference.e2ee
        ? createPhalaE2eeEncryption({
            baseUrl: options.config.inference.baseUrl,
            requestSigner: options.requestSigner,
            logger,
          })
        : undefined,
    });
  const scheduler: RecomputeScheduler = createRecomputeScheduler({
    store: options.store,
    debounceMs: options.config.inference.recomputeDebounceMs,
    serverOwner: options.serverOwner,
    now: options.now,
    logger,
    compute: (questionId) =>
      computeQuestion(questionId, {
        // A -> B -> C: a question reading this derived scope goes stale.
        onDerivedWritten: (event) =>
          scheduler.markSourceChanged(event.scope, {
            lineageSources: event.lineageSources,
          }),
        runtimeAvailability: options.runtimeAvailability,
        storage: options.storage,
        store: options.store,
        provider,
        serverOwner: options.serverOwner,
        maxSourceItems: options.config.inference.maxSourceItems,
        syncManager: options.syncManager?.() ?? null,
        scopeDeletions: options.scopeDeletions?.(),
        writePolicyPorts: options.writePolicyPorts,
        now: options.now,
        logger,
      }),
  });
  return { store: options.store, scheduler, provider };
}
