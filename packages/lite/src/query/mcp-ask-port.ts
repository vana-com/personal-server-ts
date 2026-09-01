/**
 * PS-Lite's implementation of `ask_personal_data`'s engine.
 *
 * `packages/core` declares `McpAskPersonalDataPort` and cannot implement it,
 * so each runtime injects its own. Node injects
 * `packages/server/src/query/mcp-ask-port.ts`; this is the browser one, and
 * the only difference is which sandbox and which materialization it reaches
 * for. Without it the tool answers `query_unavailable`
 * (`packages/core/src/mcp/tools.ts`), which is what PS-Lite did until now.
 *
 * Metering is unchanged and not re-implemented: every scope is read through
 * `McpDataReadClient.readScopeEnvelope`, the same call a single `read_scope`
 * makes, so one scope touched is one grant check and one access-log row. The
 * sweep is N of those calls and nothing more.
 */

import type {
  McpAskPersonalDataInput,
  McpAskPersonalDataPort,
} from "@opendatalabs/personal-server-ts-core/mcp";
import type { QueryAnswer } from "@opendatalabs/personal-server-ts-core/query/agent";
import type { InferenceProvider } from "@opendatalabs/personal-server-ts-core/derivatives";

import {
  runLiteQuery,
  type LiteScopePayload,
  type LiteScopeReader,
} from "./lite-query-service.js";

export interface LiteAskPersonalDataPortDeps {
  /** The runtime's inference provider: E2EE and relay signing included. */
  provider: InferenceProvider;
  /** T2 scope profiles, when the runtime has them. */
  profiles?: Readonly<Record<string, string>>;
}

export function createLiteAskPersonalDataPort(
  deps: LiteAskPersonalDataPortDeps,
): McpAskPersonalDataPort {
  return {
    async ask(input: McpAskPersonalDataInput): Promise<QueryAnswer> {
      const grantByScope = new Map(
        input.scopes.map((s) => [s.scope, s.grantId] as const),
      );
      const readClient = input.readClient;

      const reader: LiteScopeReader = {
        // The grant was resolved and checked by the tool before it got here;
        // this reader can only ever narrow further, never widen.
        grantedScopes: () => [...grantByScope.keys()],
        async readScope(scope: string): Promise<LiteScopePayload> {
          const grantId = grantByScope.get(scope);
          if (!grantId) throw new Error("scope is not in the resolved grant");
          if (typeof readClient.readScopeEnvelope !== "function") {
            throw new Error(
              "this read client cannot serve whole scopes, so coverage could not be trusted",
            );
          }
          const result = await readClient.readScopeEnvelope({ scope, grantId });
          return {
            data: result.envelope,
            collectedAt: result.collectedAt,
            ...(result.version ? { version: result.version } : {}),
          };
        },
      };

      return runLiteQuery({
        reader,
        provider: deps.provider,
        question: input.question,
        ...(deps.profiles ? { profiles: deps.profiles } : {}),
        ...(input.budget ? { budget: input.budget } : {}),
      });
    },
  };
}
