import { readFileSync } from "node:fs";
import Database from "better-sqlite3";
import { describe, expect, it } from "vitest";
import {
  LEGACY_SCOPE_BINDINGS,
  legacyBindingsForProfile,
} from "@opendatalabs/personal-server-ts-core/legacy-projection";
import { readCanonicalLegacyScope } from "@opendatalabs/personal-server-ts-core/storage/canonical-legacy-projection";
import {
  createBearerTokenPsLiteAuth,
  createPsLiteRuntime,
} from "@opendatalabs/personal-server-ts-lite";
import {
  createMemoryPsLiteAccessLogStore,
  createMemoryPsLiteStorage,
  createMemoryPsLiteTokenStore,
} from "../../../lite/src/test-support/memory.js";
import { createMockPsLiteGateway } from "../../../lite/src/test-support/gateway.js";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";

type Streams = Record<string, Record<string, unknown>[]>;

function fixture(scope: string): Streams {
  return (
    JSON.parse(
      readFileSync(
        new URL(
          `../../../core/src/legacy-projection/__fixtures__/parity/${scope}.json`,
          import.meta.url,
        ),
        "utf8",
      ),
    ) as { streams: Streams }
  ).streams;
}

const cases: {
  name: string;
  scope: string;
  profileKey?: string;
  streams: Streams;
  expected?: Record<string, unknown>;
}[] = [
  {
    name: "GitHub browser",
    scope: "github.profile",
    profileKey: "github-browser",
    streams: fixture("github.profile"),
  },
  {
    name: "GitHub default",
    scope: "github.repositories",
    streams: fixture("github.repositories"),
  },
  {
    name: "Oura Browser",
    scope: "oura.sleep",
    profileKey: "oura-browser",
    streams: fixture("oura.sleep"),
    expected: { sleepPeriods: [] },
  },
  {
    name: "Oura Browser session fields",
    scope: "oura.sleep",
    profileKey: "oura-browser",
    streams: {
      sleep: [
        {
          id: "session-1",
          day: "2026-09-01",
          record_type: "sleep_session",
          awake_time: 418,
        },
        {
          id: "score-1",
          day: "2026-09-01",
          record_type: "daily_score",
          sleep_score: 83,
          daily_sleep_id: "daily-1",
          daily_sleep_timestamp: "2026-09-01T07:00:00Z",
        },
      ],
    },
    expected: {
      dailyScores: [{ id: "daily-1", timestamp: "2026-09-01T07:00:00Z" }],
      sleepPeriods: [{ id: "session-1", awakeTime: 418 }],
    },
  },
  {
    name: "Oura default",
    scope: "oura.sleep",
    streams: {
      sleep: [{ id: "legacy-period", day: "2026-09-01", sleep_score: 82 }],
    },
  },
  {
    name: "Meta",
    scope: "instagram.posts",
    profileKey: "meta",
    streams: fixture("instagram.posts"),
    expected: {
      posts: [
        {
          who_liked: [
            {
              profile_pic_url: "https://example.com/liker.jpg",
              pk: "pk-a",
              id: "liker-a",
            },
          ],
        },
      ],
    },
  },
];

describe("Lite and Desktop legacy profile parity", () => {
  it.each(cases)(
    "projects $name through the same binding",
    async (testCase) => {
      const { scope, streams, profileKey } = testCase;
      const binding = profileKey
        ? legacyBindingsForProfile(profileKey).get(scope)
        : LEGACY_SCOPE_BINDINGS.get(scope);
      expect(binding).toBeDefined();
      if (!binding) return;
      const method = profileKey ?? binding.pdppSource.split("/").at(-1)!;
      const sourceId = binding.pdppSource.replace("/connectors/", "/sources/");
      const selection = { instance: "conn", sourceId, method };

      const db = new Database(":memory:");
      const store = createSqliteRecordStore(db);
      try {
        store.registerConnection({ ...selection, label: testCase.name });
        for (const [stream, rows] of Object.entries(streams)) {
          const ingested = store.ingestBatch(
            rows.map((data) => {
              const fields = binding.primaryKey[stream] ?? ["id"];
              return {
                instance: selection.instance,
                stream,
                key:
                  fields.length === 1
                    ? String(data[fields[0]])
                    : fields.map((field) => String(data[field])),
                data,
                emitted_at: "2026-10-01T00:00:00.000Z",
              };
            }),
            () => "mutable_state",
            () => binding.primaryKey[stream] ?? ["id"],
            { method, generation: 1 },
          );
          expect(ingested.rejected).toEqual([]);
        }
        const desktop = await readCanonicalLegacyScope({
          store,
          scope,
          selection,
          profileBy: "method",
        });
        expect(desktop.ok).toBe(true);
        if (!desktop.ok) return;
        if (testCase.expected) {
          expect(desktop.envelope.data).toMatchObject(testCase.expected);
        }

        const storage = createMemoryPsLiteStorage();
        const accessLog = createMemoryPsLiteAccessLogStore();
        const lite = createPsLiteRuntime({
          storage,
          active: true,
          auth: createBearerTokenPsLiteAuth({
            ownerToken: "owner-token",
            builderToken: "builder-token",
          }),
          gateway: createMockPsLiteGateway(),
          accessLogReader: accessLog,
          accessLogWriter: accessLog,
          tokenStore: createMemoryPsLiteTokenStore(),
          saveConfig: async () => {},
          stateCapabilities: { config: "memory" },
        });
        const source = scope.slice(0, scope.indexOf("."));
        for (const [stream, rows] of Object.entries(streams)) {
          const response = await lite.fetch(
            new Request(`https://ps.local/v1/data/${source}.${stream}`, {
              method: "POST",
              headers: {
                Authorization: "Bearer owner-token",
                "Content-Type": "application/json",
              },
              body: JSON.stringify({
                records: rows.map((data) => ({
                  ...data,
                  $pdpp: { sourceId },
                })),
              }),
            }),
          );
          expect(response.status).toBe(201);
        }
        const response = await lite.fetch(
          new Request(`https://ps.local/v1/data/${scope}`, {
            headers: { Authorization: "Bearer owner-token" },
          }),
        );
        expect(response.status).toBe(200);
        expect(((await response.json()) as { data: unknown }).data).toEqual(
          desktop.envelope.data,
        );
      } finally {
        store.close();
      }
    },
  );
});
