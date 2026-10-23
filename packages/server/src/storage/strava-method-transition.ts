import { createHash } from "node:crypto";
import type { DataStoragePort } from "@opendatalabs/personal-server-ts-core/ports";
import type {
  LegacyScopeLatest,
  LegacyScopeViewPort,
} from "@opendatalabs/personal-server-ts-core/storage/legacy-scope-view";
import type { DataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import {
  PdppBindingError,
  type createSqliteRecordStore,
  type StravaTransition,
  type StravaTransitionScope,
} from "./pdpp-records-sqlite-store.js";

/*
 * Strava export → browser transition.
 *
 *   owner POST transition-strava-browser
 *        │  snapshot readable export bodies, archive rows, bind strava-browser
 *        ▼
 *   strava.activities ── saved export body ──┐ until a COMPLETED browser run
 *                                            │ holds every saved activity id
 *                                            ▼
 *                         browser rows (normal legacy view from then on)
 *   strava.coverage_diagnostics ── saved export body, frozen
 *
 * Strava browser records carry no athlete id, so id coverage is the only
 * evidence that the browser signed in to the same account. A completed run
 * that misses saved ids keeps the export and reports `account_mismatch`.
 */

/** Runtime contract a host checks before it requests the transition. */
export const STRAVA_BROWSER_TRANSITION_CONTRACT =
  "strava-browser-transition-v1";

const ACTIVITIES = "strava.activities";
const DIAGNOSTICS = "strava.coverage_diagnostics";
const SCOPES: readonly StravaTransitionScope[] = [ACTIVITIES, DIAGNOSTICS];
const SOURCE = "https://registry.pdpp.dev/sources/strava";
const BROWSER_METHOD = "strava-browser";
const ACTIVITIES_STREAM = "activities";

/**
 * `none`: no transition. `pending`: no completed browser run is evaluated yet.
 * `account_mismatch`: a completed run lacks saved ids. `covered`: handed over.
 */
export type StravaTransitionStatus =
  "none" | "pending" | "account_mismatch" | "covered";

type Store = ReturnType<typeof createSqliteRecordStore>;

interface Saved {
  transition: StravaTransition;
  envelope: DataFileEnvelope;
  revision: string;
}

function isStravaScope(scope: string): scope is StravaTransitionScope {
  return (SCOPES as readonly string[]).includes(scope);
}

function activityIds(data: unknown): Set<string> | null {
  const rows = (data as { activities?: unknown } | null)?.activities;
  if (!Array.isArray(rows)) return null;
  const ids = new Set<string>();
  for (const row of rows) {
    const id = (row as { id?: unknown } | null)?.id;
    if (typeof id !== "string") return null;
    ids.add(id);
  }
  return ids;
}

export function createStravaMethodTransition(
  store: Store,
  base: LegacyScopeViewPort,
  files: DataStoragePort,
) {
  /** The export bodies an owner could read before the switch. */
  async function snapshots(instance: string) {
    const saved: StravaTransition["snapshots"] = {};
    for (const scope of SCOPES) {
      const read = await base.readLatest(scope);
      if (read.kind === "canonical") {
        saved[scope] = read.envelope;
        continue;
      }
      if (read.kind === "file") {
        const head = files.findEntry({ scope });
        if (head)
          saved[scope] = await files.readEnvelope(scope, head.collectedAt);
        continue;
      }
      // Diagnostics are informational. Unreadable activities would be lost.
      if (scope === ACTIVITIES && !store.getInstanceBinding(instance).empty)
        throw new PdppBindingError("strava_previous_data_not_readable");
    }
    return saved;
  }

  async function transition(instance: string, expectedGeneration: number) {
    if (store.stravaTransition(instance))
      return store.transitionStravaToBrowser({
        instance,
        expectedGeneration,
        expectedWriteClock: 0,
        snapshots: {},
      });
    const clock = store.transitionWriteClock();
    const heads = SCOPES.map((scope) =>
      JSON.stringify(files.findEntry({ scope })),
    );
    const saved = await snapshots(instance);
    return store.readSnapshot(() => {
      // Legacy files have their own index clock; recheck it with the rows.
      const moved = SCOPES.some(
        (scope, index) =>
          JSON.stringify(files.findEntry({ scope })) !== heads[index],
      );
      if (moved) throw new PdppBindingError("binding_generation_mismatch");
      return store.transitionStravaToBrowser({
        instance,
        expectedGeneration,
        expectedWriteClock: clock,
        snapshots: saved,
      });
    });
  }

  /** The current transition and saved body of `scope`, while still valid. */
  function saved(scope: string): Saved | null {
    if (!isStravaScope(scope) || base.isReset(scope)) return null;
    const transitions = store.listStravaTransitions();
    if (transitions.length !== 1) return null;
    const [current] = transitions;
    const binding = store.getInstanceBinding(current.instance);
    if (
      binding.deletedAt !== null ||
      binding.method !== BROWSER_METHOD ||
      binding.generation !== current.generation ||
      store.listConnections(SOURCE).length !== 1
    )
      return null;
    const envelope = current.snapshots[scope];
    if (!envelope) return null;
    const digest = createHash("sha256")
      .update(JSON.stringify(envelope))
      .digest("hex");
    return {
      transition: current,
      envelope,
      revision: `strava-transition:${current.generation}:${digest}`,
    };
  }

  function completedBrowserRun(transition: StravaTransition): boolean {
    return store
      .listStreamCompletions(transition.instance)
      .some(
        (receipt) =>
          receipt.stream === ACTIVITIES_STREAM &&
          receipt.method === BROWSER_METHOD &&
          receipt.generation === transition.generation,
      );
  }

  /**
   * Judge the browser rows against the saved activities. Only a completed
   * run counts; a covering one records the handover.
   */
  async function evaluate(before: Saved): Promise<{
    status: Exclude<StravaTransitionStatus, "none">;
    current: LegacyScopeLatest;
  }> {
    const current = await base.readLatest(ACTIVITIES);
    if (before.transition.activitiesCovered)
      return { status: "covered", current };
    if (!completedBrowserRun(before.transition) || current.kind !== "canonical")
      return { status: "pending", current };
    const savedIds = activityIds(before.envelope.data) ?? new Set<string>();
    const browserIds = activityIds(current.envelope.data);
    const covers =
      browserIds !== null && [...savedIds].every((id) => browserIds.has(id));
    if (!covers) return { status: "account_mismatch", current };
    store.confirmStravaTransition(
      before.transition.instance,
      before.transition.generation,
    );
    return { status: "covered", current };
  }

  async function status(instance: string): Promise<StravaTransitionStatus> {
    const before = saved(ACTIVITIES);
    if (before?.transition.instance === instance)
      return (await evaluate(before)).status;
    const transition = store.stravaTransition(instance);
    return transition?.activitiesCovered ? "covered" : "none";
  }

  function savedBody(before: Saved): LegacyScopeLatest {
    return {
      kind: "canonical",
      envelope: before.envelope,
      revision: before.revision,
    };
  }

  /** Listed as the saved body until browser rows have taken over. */
  function listedSaved(scope: string): Saved | null {
    const before = saved(scope);
    if (!before) return null;
    if (scope === ACTIVITIES && before.transition.activitiesCovered)
      return null;
    return before;
  }

  const view: LegacyScopeViewPort = {
    ...base,
    async readLatest(scope): Promise<LegacyScopeLatest> {
      const before = saved(scope);
      if (!before) return base.readLatest(scope);
      // Diagnostics stay frozen at the export's last body.
      if (scope === DIAGNOSTICS) return savedBody(before);
      const { status: verdict, current } = await evaluate(before);
      // A reset, deletion or replacement during the read invalidates it.
      if (saved(scope)?.revision !== before.revision)
        return base.readLatest(scope);
      return verdict === "covered" ? current : savedBody(before);
    },
    listingFor(scope) {
      const before = listedSaved(scope);
      return before
        ? { kind: "canonical", collectedAt: before.envelope.collectedAt }
        : base.listingFor(scope);
    },
    listCanonicalScopes(prefix) {
      const listed = new Map(
        base.listCanonicalScopes(prefix).map((item) => [item.scope, item]),
      );
      for (const scope of SCOPES) {
        const before = listedSaved(scope);
        if (!before || (prefix && !scope.startsWith(prefix))) continue;
        listed.set(scope, { scope, collectedAt: before.envelope.collectedAt });
      }
      return [...listed.values()];
    },
    resetTakeover(scope) {
      base.resetTakeover(scope);
      store.clearStravaTransitionScope(scope);
    },
    ownsScope: (scope) => saved(scope) !== null || base.ownsScope(scope),
  };
  return { transition, status, view };
}
