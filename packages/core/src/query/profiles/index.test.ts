import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { parseFrontmatter } from "./frontmatter.js";
import {
  DEFAULT_PROFILE_BUDGET_CHARS,
  getProfileForScope,
  listProfiles,
  renderProfiles,
  selectProfiles,
} from "./index.js";
import { PROFILE_DOCUMENTS } from "./profiles.generated.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const GENERATED = join(HERE, "profiles.generated.ts");

function readMarkdownDocuments(): Record<string, string> {
  const entries: Record<string, string> = {};
  for (const file of readdirSync(HERE).sort()) {
    if (!file.endsWith(".md") || file === "README.md") continue;
    entries[file.slice(0, -3)] = readFileSync(join(HERE, file), "utf8");
  }
  return entries;
}

function serialize(documents: Record<string, string>): string {
  const body = Object.entries(documents)
    .map(([id, text]) => {
      const escaped = text
        .replace(/\\/g, "\\\\")
        .replace(/`/g, "\\`")
        .replace(/\$\{/g, "\\${");
      return `  ${JSON.stringify(id)}: \`${escaped}\`,`;
    })
    .join("\n");
  return [
    "// Generated from the sibling *.md profile documents. Do not edit by hand.",
    "// Regenerate with: UPDATE_PROFILES=1 npx vitest run packages/core/src/query/profiles",
    "export const PROFILE_DOCUMENTS: Record<string, string> = {",
    body,
    "};",
    "",
  ].join("\n");
}

// The .md files are the authored source of truth; the generated module is what
// `packages/core` can actually import in a browser. Keeping them in sync is a
// build step we cannot add from this directory, so it is enforced here instead.
// The comparison is on document content rather than on the generated file's
// bytes, so that `npm run format` reformatting either side cannot break it.
describe("generated profile documents", () => {
  const STALE =
    "profiles.generated.ts is stale — run: UPDATE_PROFILES=1 npx vitest run packages/core/src/query/profiles";

  if (process.env.UPDATE_PROFILES === "1") {
    writeFileSync(GENERATED, serialize(readMarkdownDocuments()), "utf8");
  }

  it("covers exactly the markdown profiles on disk", () => {
    expect(Object.keys(PROFILE_DOCUMENTS).sort(), STALE).toEqual(
      Object.keys(readMarkdownDocuments()).sort(),
    );
  });

  it("reproduces each markdown document verbatim", () => {
    for (const [id, text] of Object.entries(readMarkdownDocuments())) {
      expect(PROFILE_DOCUMENTS[id], `${id}: ${STALE}`).toBe(text);
    }
  });
});

describe("parseFrontmatter", () => {
  it("reads scalars, lists and the body", () => {
    const parsed = parseFrontmatter(
      [
        "---",
        "id: demo",
        "scopes:",
        "  - a.b",
        "  - c.*",
        "---",
        "",
        "Body text.",
      ].join("\n"),
    );
    expect(parsed.meta).toEqual({ id: "demo", scopes: ["a.b", "c.*"] });
    expect(parsed.body).toBe("Body text.");
  });

  it("rejects a document with no front matter", () => {
    expect(() => parseFrontmatter("# Just markdown")).toThrow(
      /expected front matter/,
    );
  });

  it("rejects unclosed front matter", () => {
    expect(() => parseFrontmatter("---\nid: demo\n")).toThrow(/not closed/);
  });

  it("rejects a duplicate key", () => {
    expect(() => parseFrontmatter("---\nid: a\nid: b\n---\nx")).toThrow(
      /duplicate/,
    );
  });

  it("rejects a list item with no key", () => {
    expect(() => parseFrontmatter("---\n  - orphan\n---\nx")).toThrow(/no key/);
  });
});

describe("listProfiles", () => {
  it("parses every shipped profile", () => {
    const ids = listProfiles().map((p) => p.id);
    expect(ids).toEqual([
      "bank",
      "browser",
      "calendar",
      "chatgpt",
      "documents",
      "email",
      "fx",
      "git",
      "notes",
      "nutrition",
      "oura",
      "slack",
      "spotify",
    ]);
  });

  it("gives every profile complete metadata", () => {
    for (const profile of listProfiles()) {
      expect(profile.title).not.toBe("");
      expect(profile.summary).not.toBe("");
      expect(profile.schemaVersion).not.toBe("");
      expect(profile.profileVersion).toBeGreaterThanOrEqual(1);
      expect(profile.scopes.length).toBeGreaterThan(0);
      expect(profile.body.length).toBeGreaterThan(500);
    }
  });

  it("declares a known-gaps section in every profile", () => {
    // Plan §3 risk 3: a profile that hides its own uncertainty reintroduces the
    // silent wrongness it exists to prevent.
    for (const profile of listProfiles()) {
      expect(profile.body.toLowerCase()).toContain("known gaps");
    }
  });
});

describe("getProfileForScope", () => {
  it("matches wildcard scope patterns", () => {
    expect(getProfileForScope("oura.sleep")?.id).toBe("oura");
    expect(getProfileForScope("oura.daily_activity")?.id).toBe("oura");
    expect(getProfileForScope("chatgpt.conversations")?.id).toBe("chatgpt");
    expect(getProfileForScope("spotify.streaming_history")?.id).toBe("spotify");
  });

  it("returns undefined for an unprofiled source", () => {
    expect(getProfileForScope("instagram.profile")).toBeUndefined();
  });

  it("does not match a source whose name merely shares a prefix", () => {
    expect(getProfileForScope("ouraring.sleep")).toBeUndefined();
  });
});

describe("selectProfiles", () => {
  it("deduplicates profiles across sibling scopes", () => {
    const { profiles, unprofiledScopes } = selectProfiles([
      "oura.sleep",
      "oura.heartrate",
      "chatgpt.conversations",
    ]);
    expect(profiles.map((p) => p.id)).toEqual(["chatgpt", "oura"]);
    expect(unprofiledScopes).toEqual([]);
  });

  it("matches every fixture-corpus scope to its profile", () => {
    // The scope ids the seeded corpus actually emits. A mismatch here is what
    // made the whole T2 layer inert once already: the eval derived scope ids
    // from filenames (`oura_sleep`), which match no profile's `oura.*`.
    const expected: Record<string, string> = {
      "bank.transactions": "bank",
      "browser.history": "browser",
      "calendar.events": "calendar",
      "chatgpt.conversations": "chatgpt",
      "documents.files": "documents",
      "email.messages": "email",
      "notes.entries": "notes",
      "oura.sleep": "oura",
      "oura.daily_sleep": "oura",
      "oura.heartrate": "oura",
      "oura.workout": "oura",
      "oura.activity": "oura",
      "oura.readiness": "oura",
      "slack.messages": "slack",
      "spotify.streaming": "spotify",
    };
    for (const [scope, id] of Object.entries(expected)) {
      expect(getProfileForScope(scope)?.id, scope).toBe(id);
    }
  });

  it("leaves no fixture-corpus scope unprofiled", () => {
    const { unprofiledScopes } = selectProfiles([
      "bank.transactions",
      "browser.history",
      "calendar.events",
      "chatgpt.conversations",
      "documents.files",
      "email.messages",
      "notes.entries",
      "oura.sleep",
      "slack.messages",
      "spotify.streaming",
    ]);
    expect(unprofiledScopes).toEqual([]);
  });

  it("reports scopes with no profile", () => {
    const { profiles, unprofiledScopes } = selectProfiles([
      "oura.sleep",
      "strava.activities",
    ]);
    expect(profiles.map((p) => p.id)).toEqual(["oura"]);
    expect(unprofiledScopes).toEqual(["strava.activities"]);
  });
});

describe("renderProfiles", () => {
  it("includes full bodies for granted scopes within budget", () => {
    const rendered = renderProfiles([
      "oura.sleep",
      "spotify.streaming_history",
    ]);
    expect(rendered.full.sort()).toEqual(["oura", "spotify"]);
    expect(rendered.summarized).toEqual([]);
    expect(rendered.text).toContain("long_sleep");
    expect(rendered.text).toContain("master_metadata_track_name");
  });

  it("omits profiles for scopes that were not granted", () => {
    const rendered = renderProfiles(["oura.sleep"]);
    expect(rendered.text).not.toContain("current_node");
  });

  it("degrades to summaries when the budget is exhausted, and says which", () => {
    const rendered = renderProfiles(["oura.sleep", "chatgpt.conversations"], {
      budgetChars: 200,
    });
    expect(rendered.full).toEqual([]);
    expect(rendered.summarized.sort()).toEqual(["chatgpt", "oura"]);
    expect(rendered.text).toContain("lower confidence");
  });

  it("names unprofiled scopes in the rendered block", () => {
    const rendered = renderProfiles(["oura.sleep", "strava.activities"]);
    expect(rendered.unprofiledScopes).toEqual(["strava.activities"]);
    expect(rendered.text).toContain("strava.activities");
    expect(rendered.text).toContain("no source profile");
  });

  // The shipped set no longer fits the default budget: ten profiles total
  // ~44k characters of body against a 40k budget that was set when there were
  // three. Degradation is therefore live, and `renderProfiles` includes
  // profiles in alphabetical id order — so *which* profile is degraded is
  // arbitrary with respect to how much it matters. Today that is `spotify`,
  // whose body carries the measured account-data and skip-semantics traps.
  //
  // This test pins the behaviour rather than asserting the budget is
  // sufficient, so the tradeoff stays visible instead of silently shifting to
  // a different profile the next time one is added or edited.
  it("degrades only the last profiles alphabetically once the budget is spent", () => {
    const rendered = renderProfiles(
      listProfiles().flatMap((p) =>
        p.scopes.map((s) => s.replace(".*", ".any")),
      ),
    );
    expect(rendered.text.length).toBeLessThanOrEqual(
      DEFAULT_PROFILE_BUDGET_CHARS,
    );
    // Everything before the cutoff renders in full...
    expect(rendered.full).toContain("bank");
    expect(rendered.full).toContain("oura");
    expect(rendered.full).toContain("chatgpt");
    // ...and the remainder is reported, never dropped in silence.
    expect(rendered.summarized).toEqual(["spotify"]);
    for (const id of rendered.summarized) {
      expect(rendered.text).toContain(`(\`${id}\``);
    }
    expect(rendered.text).toContain("Full profile omitted for length");
  });

  it("renders every profile in full for a realistic single-source grant", () => {
    // The budget only binds on an all-scope grant. A normal request touches a
    // handful of scopes and is never degraded.
    const rendered = renderProfiles([
      "bank.transactions",
      "calendar.events",
      "oura.sleep",
    ]);
    expect(rendered.summarized).toEqual([]);
    expect(rendered.full).toEqual(["bank", "calendar", "oura"]);
  });
});

// Regression tests for the two measured silent-wrongness results in design
// §18.2 and the Spotify parser rules in §12.2. These assert on field names and
// enum values — the load-bearing tokens a model needs in order to write the
// right query — not on the surrounding phrasing, which is free to change.
describe("trap-case rules are present", () => {
  const bodyOf = (id: string) =>
    listProfiles().find((p) => p.id === id)?.body ?? "";

  it("Oura states the nap rule and the sleep-period type vocabulary", () => {
    const body = bodyOf("oura");
    for (const token of [
      "long_sleep",
      "late_nap",
      "deleted",
      "rest",
      "total_sleep_duration",
    ]) {
      expect(body).toContain(token);
    }
    expect(body).toContain("daily_sleep");
    expect(body).toContain("time_in_bed");
  });

  it("Oura tells the agent to bucket by the day field, not by bedtime_start", () => {
    expect(bodyOf("oura")).toContain("bedtime_start");
    expect(bodyOf("oura")).toMatch(/18:00/);
  });

  it("ChatGPT states the branch reconstruction", () => {
    const body = bodyOf("chatgpt");
    for (const token of ["current_node", "parent", "mapping", "reverse"]) {
      expect(body).toContain(token);
    }
    expect(body).toContain("sibling");
  });

  it("Spotify distinguishes the two export packages and the media types", () => {
    const body = bodyOf("spotify");
    for (const token of [
      "ms_played",
      "msPlayed",
      "episode_name",
      "reason_end",
      "skipped",
    ]) {
      expect(body).toContain(token);
    }
  });
});
