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
 */
export const DEFAULT_PROFILE_BUDGET_CHARS = 40_000;

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
