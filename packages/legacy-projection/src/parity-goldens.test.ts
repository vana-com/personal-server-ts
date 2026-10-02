/**
 * Parity with the real legacy connectors. Each golden pairs the PDPP streams
 * a PDPP bundle stored with the body the frozen legacy connector delivered,
 * both produced from the same upstream responses (see parity-oracle/). The
 * projection must reproduce that body except for the reviewed differences
 * the golden lists, and must validate against the pinned legacy schema.
 */

import { readFileSync } from "node:fs";
import Ajv from "ajv";
import { describe, expect, it } from "vitest";
import { diffBodies, type BodyDifference } from "./__fixtures__/parity/diff.js";
import { projectPdppRecordsToLegacyPayload } from "./index.js";
import type { PdppRecord } from "./types.js";

interface Golden {
  scope: string;
  provenance: { legacyConnector: string; pdppBundle: string };
  fetchedStreams: string[];
  streams: Record<string, Record<string, unknown>[]>;
  legacyBody: Record<string, unknown>;
  reviewedDifferences: (BodyDifference & { reason: string })[];
}

// The clock both scripts ran under; legacy stamped it into fetched_at and
// into a memory's null created_at.
const ORACLE_CLOCK = "2026-10-01T00:00:00.000Z";
const SCOPES = [
  "chatgpt.conversations",
  "chatgpt.memories",
  "claude.conversations",
  "claude.projects",
];
const ajv = new Ajv({ allErrors: true, strict: false });

function load(scope: string): Golden {
  return JSON.parse(
    readFileSync(
      new URL(`./__fixtures__/parity/${scope}.json`, import.meta.url),
      "utf8",
    ),
  ) as Golden;
}

function records(golden: Golden): PdppRecord[] {
  return Object.entries(golden.streams).flatMap(([stream, rows]) =>
    rows.map((data) => ({ stream, data })),
  );
}

function schemaFor(scope: string): Record<string, unknown> {
  const file = JSON.parse(
    readFileSync(
      new URL(`./legacy-schemas/${scope}.json`, import.meta.url),
      "utf8",
    ),
  ) as { schema: Record<string, unknown> };
  return file.schema;
}

describe.each(SCOPES)("%s parity with the legacy connector", (scope) => {
  const golden = load(scope);

  it("comes from a real legacy connector run, not a PDPP bundle", () => {
    expect(golden.scope).toBe(scope);
    expect(golden.provenance.legacyConnector).toMatch(
      /^(chatgpt-4\.0\.0-vana\.1\.js|claude-export-playwright\.js) .* sha256:[0-9a-f]{64}$/,
    );
    expect(golden.provenance.pdppBundle).toMatch(/sha256:[0-9a-f]{64}$/);
  });

  it.each([
    ["source order", false],
    ["primary-key order", true],
  ])(
    "projects to the legacy body except the reviewed differences (%s)",
    (_label, orderByPrimaryKey) => {
      const result = projectPdppRecordsToLegacyPayload(scope, records(golden), {
        fetchedStreams: golden.fetchedStreams,
        now: ORACLE_CLOCK,
        orderByPrimaryKey,
      });

      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.diagnostics).toBeUndefined();
      expect(diffBodies(golden.legacyBody, result.payload)).toEqual(
        golden.reviewedDifferences.map(({ path, legacy, projected }) => ({
          path,
          legacy,
          projected,
        })),
      );
      const validate = ajv.compile(schemaFor(scope));
      expect(
        validate(result.payload),
        JSON.stringify(validate.errors, null, 2),
      ).toBe(true);
    },
  );

  it("keeps the legacy body's top-level keys", () => {
    const result = projectPdppRecordsToLegacyPayload(scope, records(golden), {
      fetchedStreams: golden.fetchedStreams,
      now: ORACLE_CLOCK,
    });
    expect(result.ok && Object.keys(result.payload)).toEqual(
      Object.keys(golden.legacyBody),
    );
  });

  it("reviews each time-format difference as the same instant", () => {
    for (const difference of golden.reviewedDifferences) {
      if (!difference.reason.startsWith("time format")) continue;
      const instant = (value: unknown) =>
        typeof value === "number"
          ? value * 1000
          : Date.parse(String(value).replace(/(\.\d{3})\d+/, "$1"));
      expect(instant(difference.legacy), difference.path).toBe(
        instant(difference.projected),
      );
    }
  });
});

describe("the parity diff", () => {
  const conversations = [{ id: "a" }, { id: "b" }, { id: "c" }];

  it("reports a different element order", () => {
    expect(
      diffBodies(
        { conversations },
        { conversations: [...conversations].reverse() },
      ),
    ).toEqual([
      {
        path: "conversations[order]",
        legacy: ["a", "b", "c"],
        projected: ["c", "b", "a"],
      },
    ]);
  });

  it("reports a duplicated element", () => {
    expect(
      diffBodies(
        { conversations },
        { conversations: [...conversations, conversations[0]] },
      ),
    ).toEqual([{ path: "conversations[id=a]#count", legacy: 1, projected: 2 }]);
  });
});

describe("chatgpt.conversations in a stable order", () => {
  it("follows legacy's newest-update-first order whatever order rows were stored in", () => {
    const golden = load("chatgpt.conversations");
    const shuffled = records(golden).reverse();
    const result = projectPdppRecordsToLegacyPayload(
      "chatgpt.conversations",
      shuffled,
      {
        fetchedStreams: golden.fetchedStreams,
        now: ORACLE_CLOCK,
        orderByPrimaryKey: true,
      },
    );
    const ids = (body: unknown) =>
      (body as { conversations: { id: string }[] }).conversations.map(
        (conversation) => conversation.id,
      );
    expect(result.ok && ids(result.payload)).toEqual(ids(golden.legacyBody));
  });

  it("breaks an update_time tie by id and puts a missing time last", () => {
    const conversation = (id: string, update_time: string | null) => ({
      stream: "conversations",
      data: {
        id,
        title: id,
        create_time: null,
        update_time,
        current_node: null,
        message_count_on_current_branch: 0,
      },
    });
    const result = projectPdppRecordsToLegacyPayload(
      "chatgpt.conversations",
      [
        conversation("z", null),
        conversation("c", "2026-09-01T00:00:00.000Z"),
        conversation("b", "2026-09-02T00:00:00.000Z"),
        conversation("a", "2026-09-01T00:00:00.000Z"),
      ],
      {
        fetchedStreams: ["conversations", "messages"],
        now: ORACLE_CLOCK,
        orderByPrimaryKey: true,
      },
    );
    expect(
      result.ok &&
        (
          result.payload as { conversations: { id: string }[] }
        ).conversations.map((c) => c.id),
    ).toEqual(["b", "a", "c", "z"]);
  });
});
