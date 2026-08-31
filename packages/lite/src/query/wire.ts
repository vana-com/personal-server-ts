/**
 * One-line wiring from the runtime's inference provider to the query route.
 *
 * This module exists so that importing it is the ONLY way to pull the QuickJS
 * engine into a bundle. `runtime.ts` and `browser-runtime.ts` deliberately do
 * not import it: `quickjs-sandbox.ts` statically imports a ~1.1 MB base64
 * inlined WASM engine, and esbuild's single-file output inlines dynamic
 * imports rather than splitting them, so any reference from the runtime's own
 * module graph puts that engine in EVERY PS-Lite bundle — measured at
 * +1,079,786 bytes on `ps-lite-debug.js`, and it would land in the mobile
 * `ps-lite-bundle.js` too, where WASM has never run at all (design §19.18:
 * Android WebView and iOS WKWebView are both UNVERIFIED).
 *
 * So a host that wants the query layer pays for it explicitly:
 *
 * ```ts
 * import { createIndexedDbPsLiteRuntime } from "@opendatalabs/personal-server-ts-lite";
 * import { createLiteQueryAsk } from "@opendatalabs/personal-server-ts-lite";
 *
 * const { runtime } = await createIndexedDbPsLiteRuntime({
 *   ...opts,
 *   query: { ask: createLiteQueryAsk({ provider }) },
 * });
 * ```
 *
 * and a host that does not want it never mentions this module and its bundle
 * is byte-identical to what it was before the route existed.
 */

import type { InferenceProvider } from "@opendatalabs/personal-server-ts-core/derivatives";

import { runLiteQuery } from "./lite-query-service.js";
import type { LiteQueryAsk } from "./http-route.js";

export interface CreateLiteQueryAskOptions {
  /**
   * The runtime's inference provider — E2EE, relay signing and the owner's
   * request signer included. Pass the SAME one the derivative compute layer
   * uses (`createPsLiteDerivativeCompute(...).provider`) so the query layer
   * introduces no second inference path and no egress that layer did not
   * already have.
   */
  provider: InferenceProvider;
  /** T2 scope profiles, when the host has them. */
  profiles?: Readonly<Record<string, string>>;
}

/**
 * Bind a provider (and optional profiles) to `runLiteQuery`.
 *
 * The model's code still runs only inside the QuickJS-WASM VM
 * (`quickjs-sandbox.ts`); nothing here creates another execution path. A run
 * whose VM cannot be built, or whose egress probe finds any of
 * `EGRESS_GLOBALS`, fails closed as `sandboxUnavailable` rather than degrading
 * to the page's realm.
 */
export function createLiteQueryAsk(
  options: CreateLiteQueryAskOptions,
): LiteQueryAsk {
  return (input) =>
    runLiteQuery({
      reader: input.reader,
      provider: options.provider,
      question: input.question,
      ...(options.profiles ? { profiles: options.profiles } : {}),
      ...(input.scopes ? { scopes: input.scopes } : {}),
      ...(input.model ? { model: input.model } : {}),
      ...(input.budget ? { budget: input.budget } : {}),
      ...(input.onEvent ? { onEvent: input.onEvent } : {}),
    });
}
