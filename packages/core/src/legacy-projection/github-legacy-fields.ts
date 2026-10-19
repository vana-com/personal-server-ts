// Field-only copies of legacy-schemas/github.*.json. Tests pin the complete
// tree to those schemas. Keep JSON out of the runtime composite TS project.
export type LegacyGithubFields = {
  properties?: Record<string, LegacyGithubFields>;
  items?: LegacyGithubFields;
};

export const GITHUB_LEGACY_FIELDS: Record<string, LegacyGithubFields> = {
  profile: {
    properties: {
      username: {},
      fullName: {},
      bio: {},
      company: {},
      location: {},
      website: {},
      avatarUrl: {},
      followers: {},
      following: {},
      repositoryCount: {},
      profileUrl: {},
      pinnedRepositories: {
        items: {
          properties: {
            fullName: {},
            url: {},
            description: {},
            language: {},
            stars: {},
          },
        },
      },
      organizations: {
        items: {
          properties: {
            login: {},
            label: {},
            url: {},
            avatarUrl: {},
          },
        },
      },
      achievements: {
        items: {
          properties: {
            name: {},
            iconUrl: {},
          },
        },
      },
      contributionsLastYear: {},
    },
  },
  repositories: {
    properties: {
      repositories: {
        items: {
          properties: {
            name: {},
            url: {},
            description: {},
            language: {},
            stars: {},
            forks: {},
            visibility: {},
            topics: {
              items: {},
            },
            updatedAt: {},
          },
        },
      },
    },
  },
  starred: {
    properties: {
      starred: {
        items: {
          properties: {
            fullName: {},
            url: {},
            description: {},
            language: {},
            stars: {},
            updatedAt: {},
          },
        },
      },
    },
  },
  events: {
    properties: {
      events: {
        items: {
          properties: {
            id: {},
            type: {},
            createdAt: {},
            repo: {},
            repoUrl: {},
            action: {},
            title: {},
            body: {},
            url: {},
            branch: {},
            commits: {},
            isPublic: {},
          },
        },
      },
      fetchedAt: {},
      windowDescription: {},
    },
  },
  contributions: {
    properties: {
      totalContributionsLastYear: {},
      yearTotals: {
        items: {
          properties: {
            year: {},
            total: {},
          },
        },
      },
      days: {
        items: {
          properties: {
            date: {},
            count: {},
            level: {},
          },
        },
      },
      monthlyTotals: {
        items: {
          properties: {
            month: {},
            count: {},
          },
        },
      },
      topDay: {
        properties: {
          date: {},
          count: {},
        },
      },
      fetchedAt: {},
    },
  },
  history: {
    properties: {
      pullRequests: {
        items: {
          properties: {
            id: {},
            type: {},
            number: {},
            title: {},
            body: {},
            state: {},
            createdAt: {},
            updatedAt: {},
            closedAt: {},
            mergedAt: {},
            url: {},
            repo: {},
            repoUrl: {},
            labels: {
              items: {},
            },
            comments: {},
            reactionsTotal: {},
            isDraft: {},
          },
        },
      },
      issues: {
        items: {
          properties: {
            id: {},
            type: {},
            number: {},
            title: {},
            body: {},
            state: {},
            createdAt: {},
            updatedAt: {},
            closedAt: {},
            mergedAt: {},
            url: {},
            repo: {},
            repoUrl: {},
            labels: {
              items: {},
            },
            comments: {},
            reactionsTotal: {},
            isDraft: {},
          },
        },
      },
      fetchedAt: {},
      windowDescription: {},
    },
  },
};
