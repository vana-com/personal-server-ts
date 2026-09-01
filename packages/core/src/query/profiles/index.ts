/**
 * T2 source profiles — loading, scope matching, and prompt rendering.
 *
 * The prose lives in the sibling `*.md` files, which are the authored source of
 * truth. `profiles.generated.ts` inlines them as string constants so this module
 * needs no filesystem: `packages/core` is consumed by `packages/lite` in a
 * browser and may not import Node built-ins (plan §5).
 */

import {
  parseFrontmatter,
  requireInteger,
  requireString,
  requireStringList,
} from "./frontmatter.js";
import { PROFILE_DOCUMENTS } from "./profiles.generated.js";
import type { RenderedProfiles, SourceProfile } from "./types.js";

export type {
  RenderedProfiles,
  SourceProfile,
  SourceProfileMeta,
} from "./types.js";

/**
 * Character budget for the rendered `{{PROFILES}}` block. Profiles beyond it
 * degrade to their summary rather than being dropped, and the degradation is
 * reported so it can reach `coverage`.
 *
 * Sized so the **entire shipped set renders in full**, with headroom. It was
 * 40,000 when three profiles existed; at ten the set came to 38,653 and
 * `spotify` silently degraded — the profile carrying the measured
 * account-data trap (a one-year export and a lifetime export share a
 * filename) and the skip-semantics rule. Inclusion is alphabetical by id, so
 * *which* profile degrades is arbitrary with respect to how much it is worth.
 *
 * Trading a measured trap for ~2k tokens inverts design §18.2, whose whole
 * claim is that this prose is the highest-leverage artifact we ship. A test
 * pins the shipped set below this number, so adding a profile past the
 * headroom fails the build and forces a deliberate choice — raise the budget,
 * or make inclusion value-aware — rather than degrading something load-bearing
 * in silence.
 *
 * Raised 56k → 72k when `fx`, `nutrition` and `git` brought the set to 13,
 * rendering 53,856 chars (~13.5k tokens). That is the **worst case only**: the
 * budget binds on an all-scope grant, which is what the eval harness does. A
 * real request holds a grant on a handful of scopes and renders a fraction of
 * it. Paying ~13k tokens on a total-grant request is the right side of the
 * trade when the alternative is dropping a rule that prevents a silently wrong
 * answer — the `fx` profile alone is what stands between a converted total and
 * one 22,000× off.
 */
export const DEFAULT_PROFILE_BUDGET_CHARS = 72_000;

function parseProfile(id: string, source: string): SourceProfile {
  const label = `profile "${id}"`;
  const { meta, body } = parseFrontmatter(source, label);

  const declaredId = requireString(meta, "id", label);
  if (declaredId !== id) {
    throw new Error(
      `${label}: front matter id "${declaredId}" does not match its file name`,
    );
  }
  if (body === "") {
    throw new Error(`${label}: body is empty`);
  }

  for (const scope of requireStringList(meta, "scopes", label)) {
    if (!/^[a-z0-9_]+(\.[a-z0-9_]+)*(\.\*)?$/.test(scope)) {
      throw new Error(`${label}: malformed scope pattern "${scope}"`);
    }
  }

  return {
    id: declaredId,
    title: requireString(meta, "title", label),
    profileVersion: requireInteger(meta, "profileVersion", label),
    schemaVersion: requireString(meta, "schemaVersion", label),
    scopes: requireStringList(meta, "scopes", label),
    summary: requireString(meta, "summary", label),
    body,
  };
}

let cache: SourceProfile[] | null = null;

/** All shipped profiles, parsed once. */
export function listProfiles(): SourceProfile[] {
  if (cache === null) {
    cache = Object.entries(PROFILE_DOCUMENTS)
      .map(([id, source]) => parseProfile(id, source))
      .sort((a, b) => a.id.localeCompare(b.id));
  }
  return cache;
}

function matchesScope(pattern: string, scope: string): boolean {
  if (pattern.endsWith(".*")) {
    return scope.startsWith(pattern.slice(0, -1));
  }
  return pattern === scope;
}

/**
 * The profile covering a scope, or `undefined` when none exists.
 *
 * An exact scope match wins over a wildcard, so a future `oura.sleep` profile
 * would take precedence over `oura.*`.
 */
export function getProfileForScope(scope: string): SourceProfile | undefined {
  const profiles = listProfiles();
  return (
    profiles.find((p) =>
      p.scopes.some((pattern) => !pattern.endsWith(".*") && pattern === scope),
    ) ??
    profiles.find((p) =>
      p.scopes.some((pattern) => matchesScope(pattern, scope)),
    )
  );
}

/** Distinct profiles covering any of `scopes`, plus the scopes none covered. */
export function selectProfiles(scopes: string[]): {
  profiles: SourceProfile[];
  unprofiledScopes: string[];
} {
  const byId = new Map<string, SourceProfile>();
  const unprofiledScopes: string[] = [];

  for (const scope of scopes) {
    const profile = getProfileForScope(scope);
    if (profile) byId.set(profile.id, profile);
    else if (!unprofiledScopes.includes(scope)) unprofiledScopes.push(scope);
  }

  return {
    profiles: [...byId.values()].sort((a, b) => a.id.localeCompare(b.id)),
    unprofiledScopes,
  };
}

function heading(profile: SourceProfile): string {
  return `### ${profile.title} (\`${profile.id}\`, profile v${profile.profileVersion}, schema \`${profile.schemaVersion}\`)`;
}

/**
 * Render the `{{PROFILES}}` block for a request's granted scopes.
 *
 * Full bodies are included while the budget holds — the whole point of a profile
 * is that a model cannot know it needs a rule it has not read, so summaries are
 * a degradation, not a default. Once the budget is exhausted the remaining
 * profiles fall back to their summary and are named in `summarized`.
 */
export function renderProfiles(
  scopes: string[],
  options: { budgetChars?: number } = {},
): RenderedProfiles {
  const budget = options.budgetChars ?? DEFAULT_PROFILE_BUDGET_CHARS;
  const { profiles, unprofiledScopes } = selectProfiles(scopes);

  const sections: string[] = [];
  const full: string[] = [];
  const summarized: string[] = [];
  let used = 0;

  for (const profile of profiles) {
    const section = `${heading(profile)}\n\n${profile.body}`;
    if (used + section.length <= budget) {
      sections.push(section);
      full.push(profile.id);
      used += section.length;
    } else {
      sections.push(
        `${heading(profile)}\n\n${profile.summary}\n\n(Full profile omitted for length — treat conclusions drawn from this source as lower confidence and say so.)`,
      );
      summarized.push(profile.id);
    }
  }

  if (unprofiledScopes.length > 0) {
    sections.push(
      `### No profile\n\nThese granted scopes have no source profile: ${unprofiledScopes.join(", ")}. ` +
        `Their implicit rules are unknown to this system. Inspect their shape before computing anything, ` +
        `state in your answer that no profile exists, and treat the result as lower confidence.`,
    );
  }

  return {
    text: sections.join("\n\n---\n\n"),
    full,
    summarized,
    unprofiledScopes,
  };
}
