/**
 * T2 source profiles: hand-written prose describing a source's shape and its
 * implicit rules, loaded into the query agent's context for every granted
 * scope.
 *
 * These exist because an agent handed raw Oura rows has no way to discover that
 * a day can hold several sleep periods, and will write a defensible 1:1 join
 * that is wrong by ~11% with nothing in the output to show it. See
 * `docs/260828-query-layer-design.md` §12 and §18.2.
 *
 * Browser-safe: no Node built-ins anywhere in this module or its siblings.
 */

/** Parsed front matter of a profile document. */
export interface SourceProfileMeta {
  /** Stable profile id, matching the file name (`oura`, `spotify`, ...). */
  id: string;
  /** Human-readable source name. */
  title: string;
  /**
   * Bumped whenever the prose changes. Phase 6b keys persisted scripts by
   * question shape plus source schema version; this tracks the prose itself.
   */
  profileVersion: number;
  /**
   * Identifies the upstream export/API schema the prose was written against,
   * e.g. `oura-api-v2/1.37`. A change here invalidates cached scripts.
   */
  schemaVersion: string;
  /**
   * Scope ids this profile applies to. Either an exact id (`oura.sleep`) or a
   * single trailing wildcard segment (`oura.*`).
   */
  scopes: string[];
  /**
   * One or two sentences, safe to show wherever the full body does not fit.
   * Must name the source's headline trap, not just describe the source.
   */
  summary: string;
}

/** A profile document: front matter plus the markdown body. */
export interface SourceProfile extends SourceProfileMeta {
  /** Markdown body, front matter stripped. This is what the agent reads. */
  body: string;
}

/** Result of rendering profiles for a request's granted scopes. */
export interface RenderedProfiles {
  /** The block interpolated into `{{PROFILES}}` in the system prompt. */
  text: string;
  /** Profile ids rendered in full. */
  full: string[];
  /**
   * Profile ids reduced to their summary because the character budget ran out.
   * Non-empty means the agent is working with less than we know; surface it in
   * `coverage` rather than letting it pass silently.
   */
  summarized: string[];
  /**
   * Granted scopes with no profile at all. Per the system prompt's rule 2 and
   * plan §3 risk 3, answers drawing on these must be marked reduced-confidence.
   */
  unprofiledScopes: string[];
}
