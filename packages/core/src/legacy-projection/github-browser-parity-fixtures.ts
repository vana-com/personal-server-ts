import { createHash } from "node:crypto";

// Legacy expected values were derived from frozen github-playwright 1.5.1:
// archive sha256 7ee18936162fa33071a9d347b6493790746c0f72b68855dd43a105731bd654c8
// script.js sha256 06c61e3a238738778f41fb3b7e71c58f5fd52f7df65b1b51291f06b5c5567848
// Modern snapshots below were emitted by the 0.2.0 collector/parser in
// PDP-Connect/data-connectors commit 7e0f299c469f78c6571ea2e0a8ed43568658bb95
// from these same raw event, profile HTML, and four contribution graph inputs.
const fetchedAt = "2026-09-24T12:00:00.000Z";
const dayInputs = (from: string, to: string) => {
  const out: { date: string; count: number; level: number }[] = [];
  for (
    let d = new Date(`${from}T00:00:00Z`);
    d <= new Date(`${to}T00:00:00Z`);
    d.setUTCDate(d.getUTCDate() + 1)
  ) {
    out.push({
      date: d.toISOString().slice(0, 10),
      count: d.getUTCDate() % 3,
      level: d.getUTCDate() % 5,
    });
  }
  return out;
};
const dateHtml = (days: ReturnType<typeof dayInputs>) =>
  days
    .map(
      ({ date, count, level }) =>
        `<td class="ContributionCalendar-day" data-date="${date}" data-count="${count}" data-level="${level}"></td>`,
    )
    .join("");
const currentStart = new Date("2026-09-24T00:00:00Z");
currentStart.setUTCDate(currentStart.getUTCDate() - 364);
const currentFrom = currentStart.toISOString().slice(0, 10);
const contributionGraphInputs = [
  {
    year: 2026,
    headingTotal: 365,
    html: `<h2 class="f4 text-normal mb-2">365 contributions in the last year</h2>${dateHtml(dayInputs(currentFrom, "2026-09-24"))}`,
  },
  {
    year: 2025,
    headingTotal: 600,
    html: `<h2 class="f4 text-normal mb-2">600 contributions in 2025</h2>${dateHtml(dayInputs("2025-01-01", "2025-12-31"))}`,
  },
  {
    year: 2024,
    headingTotal: 601,
    html: `<h2 class="f4 text-normal mb-2">601 contributions in 2024</h2>${dateHtml(dayInputs("2024-01-01", "2024-12-31"))}`,
  },
  {
    year: 2023,
    headingTotal: 602,
    html: `<h2 class="f4 text-normal mb-2">602 contributions in 2023</h2>${dateHtml(dayInputs("2023-01-01", "2023-12-31"))}`,
  },
];
const allContributionDays = [
  ...dayInputs(currentFrom, "2026-09-24"),
  ...dayInputs("2025-01-01", "2025-12-31"),
  ...dayInputs("2024-01-01", "2024-12-31"),
  ...dayInputs("2023-01-01", "2023-12-31"),
];
const days = [
  ...new Map(allContributionDays.map((day) => [day.date, day])).values(),
].sort((a, b) => a.date.localeCompare(b.date));
const monthlyTotals = [
  ...days.reduce((months, day) => {
    const month = day.date.slice(0, 7);
    months.set(month, (months.get(month) ?? 0) + day.count);
    return months;
  }, new Map<string, number>()),
]
  .sort(([a], [b]) => a.localeCompare(b))
  .map(([month, count]) => ({ month, count }));
const topDay = days.reduce((best, day) =>
  day.count > best.count ? day : best,
);

const profileHtml =
  '<meta name="user-login" content="octocat"><span class="p-nickname">octocat</span><span class="p-name">Octo Cat</span><h2 class="f4 text-normal mb-2">1,234 contributions in the last year</h2><a href="/octocat?tab=followers"><span>42</span></a><a href="/octocat?tab=following"><span>7</span></a><a href="/octocat?tab=repositories"><span class="Counter">3</span></a>';
const rawEvent = {
  id: "evt-42",
  type: "PullRequestEvent",
  created_at: "2026-09-20T12:34:56Z",
  public: true,
  repo: { name: "octocat/Hello-World" },
  payload: {
    action: "opened",
    pull_request: {
      title: "Cross-run parity",
      body: "minimal fixture",
      html_url: "https://github.com/octocat/Hello-World/pull/42",
      head: { ref: "parity-branch" },
    },
  },
};

export const GITHUB_BROWSER_PROTECTED_SCOPE_FIXTURES = {
  "github.profile": {
    stream: "profile",
    rawInput: { profileHtml },
    snapshot: {
      id: "octocat:profile",
      username: "octocat",
      fullName: "Octo Cat",
      bio: "",
      company: "",
      location: "",
      website: "",
      avatarUrl: "",
      followers: 42,
      following: 7,
      repositoryCount: 3,
      profileUrl: "https://github.com/octocat",
      pinnedRepositories: [],
      organizations: [],
      achievements: [],
      contributionsLastYear: 1234,
    },
    expectedLegacy: {
      username: "octocat",
      fullName: "Octo Cat",
      bio: "",
      company: "",
      location: "",
      website: "",
      avatarUrl: "",
      followers: 42,
      following: 7,
      repositoryCount: 3,
      profileUrl: "https://github.com/octocat",
      pinnedRepositories: [],
      organizations: [],
      achievements: [],
      contributionsLastYear: 1234,
    },
  },
  "github.events": {
    stream: "events",
    rawInput: { eventApiPage: [rawEvent] },
    snapshot: {
      id: "octocat:events",
      events: [
        {
          id: "evt-42",
          type: "PullRequestEvent",
          createdAt: "2026-09-20T12:34:56Z",
          repo: "octocat/Hello-World",
          repoUrl: "https://github.com/octocat/Hello-World",
          action: "opened",
          title: "Cross-run parity",
          body: "minimal fixture",
          url: "https://github.com/octocat/Hello-World/pull/42",
          branch: "parity-branch",
          commits: null,
          isPublic: true,
        },
      ],
      fetchedAt,
      windowDescription:
        "GitHub public events API retention window (up to 300 events).",
    },
    expectedLegacy: {
      events: [
        {
          id: "evt-42",
          type: "PullRequestEvent",
          createdAt: "2026-09-20T12:34:56Z",
          repo: "octocat/Hello-World",
          repoUrl: "https://github.com/octocat/Hello-World",
          action: "opened",
          title: "Cross-run parity",
          body: "minimal fixture",
          url: "https://github.com/octocat/Hello-World/pull/42",
          branch: "parity-branch",
          commits: null,
          isPublic: true,
        },
      ],
      fetchedAt,
      windowDescription:
        "Up to 300 most recent public events across all repositories (≈90 days, GitHub API limit)",
    },
  },
  "github.contributions": {
    stream: "contributions",
    rawInput: { graphs: contributionGraphInputs },
    snapshot: {
      id: "octocat:contributions",
      totalContributionsLastYear: 365,
      yearTotals: [
        { year: 2026, total: 365 },
        { year: 2025, total: 600 },
        { year: 2024, total: 601 },
        { year: 2023, total: 602 },
      ],
      days,
      monthlyTotals,
      topDay: { date: topDay.date, count: topDay.count },
      fetchedAt,
    },
    // Digest of the archived 1.5.1 formatter's expected legacy payload after
    // normalizing fetchedAt to the fixture clock; avoids a 1,363-row golden.
    expectedLegacySha256:
      "b2e2d9b21596734eb5fa1daba2826bddeac489f476dbc7d07f4b5f6aab74b3b8",
  },
} as const;

/** Execute the exact pinned modern collector bundle against the deterministic raw inputs. */
export async function collectModernGithubBrowserFixtureSnapshot(
  scope: string,
  rawInput: unknown,
): Promise<Record<string, unknown>> {
  const { collectGitHubBrowser } =
    await import("./github-browser-0.2.0-oracle.mjs");
  const input = rawInput as Record<string, unknown>;
  const stream = scope.slice("github.".length);
  const records: Record<string, unknown>[] = [];
  let eventPage = 0;
  const graphByYear = new Map(
    (input.graphs as { year: number; html: string }[] | undefined)?.map(
      (graph) => [graph.year, graph.html],
    ) ?? [],
  );
  await collectGitHubBrowser(
    {
      emit: async () => {},
      emitRecord: async (_stream: string, record: Record<string, unknown>) => {
        records.push(record);
      },
      progress: async () => {},
      requested: new Set([stream]),
      state: {},
    },
    {
      fetchPublicJson: async () =>
        eventPage++ === 0 ? input.eventApiPage : [],
      now: () => new Date(fetchedAt),
      openPage: async (url: string) => {
        if (url === "https://github.com/")
          return '<meta name="user-login" content="octocat">';
        if (scope === "github.profile") return String(input.profileHtml);
        if (scope === "github.contributions") {
          const year = Number(
            /[?&]from=(\d{4})-/.exec(url)?.[1] ??
              new Date(fetchedAt).getUTCFullYear(),
          );
          return graphByYear.get(year) ?? "";
        }
        return "";
      },
      sleep: async () => {},
    },
  );
  if (records.length !== 1)
    throw new Error(
      `modern collector emitted ${records.length} records for ${scope}`,
    );
  return records[0];
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map(
        (key) =>
          `${JSON.stringify(key)}:${canonicalJson((value as Record<string, unknown>)[key])}`,
      )
      .join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

export function matchesFrozenGithubLegacyOutput(
  scope: string,
  payload: Record<string, unknown>,
): boolean {
  if (scope === "github.profile" || scope === "github.events") {
    const fixture = GITHUB_BROWSER_PROTECTED_SCOPE_FIXTURES[scope];
    return canonicalJson(payload) === canonicalJson(fixture.expectedLegacy);
  }
  if (scope !== "github.contributions") return false;
  return (
    createHash("sha256").update(canonicalJson(payload)).digest("hex") ===
    GITHUB_BROWSER_PROTECTED_SCOPE_FIXTURES[scope].expectedLegacySha256
  );
}
