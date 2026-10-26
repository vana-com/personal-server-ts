import { createHash } from "node:crypto";
import type { DataStoragePort } from "@opendatalabs/personal-server-ts-core/ports";
import {
  coversClaudeTransition,
  type LegacyScopeViewPort,
  type LegacyScopeLatest,
} from "@opendatalabs/personal-server-ts-core/storage/legacy-scope-view";
import {
  PdppBindingError,
  type createSqliteRecordStore,
  type ClaudeTransition,
} from "./pdpp-records-sqlite-store.js";

const scopes = ["claude.conversations", "claude.projects"] as const;
type Store = ReturnType<typeof createSqliteRecordStore>;

/** Owner-only, one-way transition. Preparation reads the old public bodies;
 * the store archives raw rows and binds the live writer in one transaction. */
export function createClaudeMethodTransition(
  store: Store,
  base: LegacyScopeViewPort,
  files: DataStoragePort,
) {
  async function transition(instance: string, expectedGeneration: number) {
    const existing = store.claudeTransition(instance);
    if (existing)
      return store.transitionClaudeToLive({
        instance,
        expectedGeneration,
        expectedWriteClock: 0,
        snapshots: {},
      });
    const clock = store.transitionWriteClock();
    const heads = scopes.map((scope) =>
      JSON.stringify(files.findEntry({ scope })),
    );
    const snapshots: ClaudeTransition["snapshots"] = {};
    for (const scope of scopes) {
      const read = await base.readLatest(scope);
      if (read.kind === "canonical") snapshots[scope] = read.envelope;
      else if (read.kind === "file") {
        const head = files.findEntry({ scope });
        if (head)
          snapshots[scope] = await files.readEnvelope(scope, head.collectedAt);
      } else {
        // An empty failed export is safe to transition. Partial records are
        // retained but cannot be silently passed off as a complete baseline.
        if (!store.getInstanceBinding(instance).empty)
          throw new PdppBindingError("claude_previous_data_not_readable");
      }
    }
    return store.readSnapshot(() => {
      // Legacy file sync has its own index clock. Revalidate it under the same
      // SQLite transaction as the binding/record archive, not just the PDPP clock.
      if (
        scopes.some(
          (scope, index) =>
            JSON.stringify(files.findEntry({ scope })) !== heads[index],
        )
      ) {
        throw new PdppBindingError("binding_generation_mismatch");
      }
      return store.transitionClaudeToLive({
        instance,
        expectedGeneration,
        expectedWriteClock: clock,
        snapshots,
      });
    });
  }

  function snapshot(scope: string) {
    if (
      !scopes.includes(scope as (typeof scopes)[number]) ||
      base.isReset(scope)
    )
      return null;
    const transitions = store.listClaudeTransitions();
    if (transitions.length !== 1) return null;
    const saved = transitions[0];
    const binding = store.getInstanceBinding(saved.instance);
    if (
      binding.deletedAt !== null ||
      binding.method !== "anthropic-live" ||
      binding.generation !== saved.generation ||
      store.listConnections("https://registry.pdpp.dev/sources/claude")
        .length !== 1
    )
      return null;
    const envelope = saved.snapshots[scope as (typeof scopes)[number]];
    return envelope
      ? {
          envelope,
          instance: saved.instance,
          generation: saved.generation,
          covered:
            scope === "claude.conversations" && saved.conversationsCovered,
          revision: `claude-transition:${saved.generation}:${createHash("sha256").update(JSON.stringify(envelope)).digest("hex")}`,
        }
      : null;
  }

  const view: LegacyScopeViewPort = {
    ...base,
    async readLatest(scope): Promise<LegacyScopeLatest> {
      const before = snapshot(scope);
      const current = await base.readLatest(scope);
      if (!before) return current;
      const covered =
        current.kind === "canonical" &&
        (await coversClaudeTransition(current, before.envelope));
      // A reset/deletion or replacement during the asynchronous read invalidates
      // this result, including its archived baseline.
      const after = snapshot(scope);
      if (after?.revision !== before.revision) return base.readLatest(scope);
      if (after.covered !== before.covered) return view.readLatest(scope);
      if (covered) {
        store.confirmClaudeTransition(before.instance, before.generation);
        return current;
      }
      if (before.covered)
        return {
          kind: "refused",
          refusal: {
            status: "unavailable",
            reason: "store_inconsistent_read",
            detail: "Live Claude no longer covers the preserved export",
          },
        };
      return {
        kind: "canonical",
        envelope: before.envelope,
        revision: before.revision,
      };
    },
    listingFor(scope) {
      const previous = snapshot(scope);
      return previous && !previous.covered
        ? { kind: "canonical", collectedAt: previous.envelope.collectedAt }
        : base.listingFor(scope);
    },
    listCanonicalScopes(prefix) {
      const listed = new Map(
        base.listCanonicalScopes(prefix).map((item) => [item.scope, item]),
      );
      for (const scope of scopes) {
        const previous = snapshot(scope);
        if (
          previous &&
          !previous.covered &&
          (!prefix || scope.startsWith(prefix))
        )
          listed.set(scope, {
            scope,
            collectedAt: previous.envelope.collectedAt,
          });
      }
      return [...listed.values()];
    },
    resetTakeover(scope) {
      base.resetTakeover(scope);
      store.clearClaudeTransitionScope(scope);
    },
    ownsScope: (scope) => snapshot(scope) !== null || base.ownsScope(scope),
  };
  return { transition, view };
}
