/**
 * The Node implementation of `ask_personal_data`'s engine
 * (implementation plan phase 8).
 *
 * `packages/core` declares `McpAskPersonalDataPort` and cannot implement it:
 * the query layer needs an OS-enforced sandbox, which is a Node subprocess,
 * and core stays browser-safe. So the tool holds an injected port and this is
 * what the Node server injects.
 *
 * ## Metering and access logs
 *
 * Every scope is read through `McpDataReadClient.readScopeEnvelope`, which is
 * `GET /v1/data/:scope` run in-process against the same handler, auth port
 * and access-log writer an external builder read uses. So one scope touched
 * is one grant check, one access-log row and — on a session that enforces
 * payment — one x402 cycle. Nothing about metering is re-implemented here;
 * the sweep is N calls to the path a single `read_scope` already took.
 *
 * The tool refuses to run at all when `readClient.enforcesPayment` is set,
 * because N scopes would need N separately signed proofs and a tool call
 * carries at most one. See `ask_personal_data` in `mcp/tools.ts`.
 */

import type {
  McpAskPersonalDataInput,
  McpAskPersonalDataPort,
} from "@opendatalabs/personal-server-ts-core/mcp";
import type { QueryAnswer } from "@opendatalabs/personal-server-ts-core/query/agent";
import type { InferenceProvider } from "@opendatalabs/personal-server-ts-core/derivatives";

import {
  runQuery,
  type QueryConcurrency,
  type QueryScopePayload,
  type QueryScopeReader,
} from "./query-service.js";

export interface McpAskPersonalDataPortDeps {
  /** The bootstrap's provider: E2EE, relay signing and receipts included. */
  provider: InferenceProvider;
  /** Shared with the HTTP route so one ceiling bounds the whole process. */
  concurrency?: QueryConcurrency;
}

export function createMcpAskPersonalDataPort(
  deps: McpAskPersonalDataPortDeps,
): McpAskPersonalDataPort {
  return {
    async ask(input: McpAskPersonalDataInput): Promise<QueryAnswer> {
      const grantByScope = new Map(
        input.scopes.map((s) => [s.scope, s.grantId] as const),
      );
      const readClient = input.readClient;

      const reader: QueryScopeReader = {
        // The grant was resolved and checked by the tool before it got here;
        // this reader can only ever narrow further, never widen.
        grantedScopes: () => [...grantByScope.keys()],
        async readScope(scope: string): Promise<QueryScopePayload> {
          const grantId = grantByScope.get(scope);
          if (!grantId) throw new Error("scope is not in the resolved grant");
          if (typeof readClient.readScopeEnvelope !== "function") {
            throw new Error(
              "this read client cannot serve whole scopes, so coverage could not be trusted",
            );
          }
          const result = await readClient.readScopeEnvelope({
            scope,
            grantId,
          });
          return {
            data: result.envelope,
            collectedAt: result.collectedAt,
            ...(result.version ? { version: result.version } : {}),
          };
        },
      };

      return runQuery({
        reader,
        provider: deps.provider,
        question: input.question,
        ...(deps.concurrency ? { concurrency: deps.concurrency } : {}),
        ...(input.budget ? { budget: input.budget } : {}),
      });
    },
  };
}
