/**
 * Captured connector parity and explicitly labelled binding regression goldens.
 * Captured goldens pair the PDPP streams
 * a PDPP bundle stored with the body the frozen legacy connector delivered,
 * both produced from the same upstream responses (see parity-oracle/). The
 * projection must reproduce that body except for the reviewed differences
 * the golden lists, and must validate against the pinned legacy schema.
 * Shop/Spotify expectations are current binding output, not captured
 * legacy-connector output; their passing tests do not establish legacy parity.
 */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import Ajv from "ajv";
import { describe, expect, it } from "vitest";
import { diffBodies, type BodyDifference } from "./__fixtures__/parity/diff.js";
import { projectPdppRecordsToLegacyPayload } from "./index.js";
import type { PdppRecord } from "./types.js";

interface Golden {
  scope: string;
  profileKey?: string;
  case?: string;
  cases?: Golden[];
  expectedResult?: {
    ok: false;
    error: { kind: "empty_singleton"; scope: string };
  };
  provenance: {
    legacyConnector: string;
    pdppBundle: string;
    rawSourceAndExpectedFiles?: string[];
    profileCaveat?: string;
    emptyOrNullEdge?: string;
    expectedSideNote?: string;
  };
  fetchedStreams: string[];
  streams: Record<string, Record<string, unknown>[]>;
  legacyBody?: Record<string, unknown>;
  expectedLegacySha256?: string;
  legacyBodyKeys?: string[];
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
  "github.profile",
  "github.events",
  "github.contributions",
  "oura.readiness",
  "oura.sleep",
  "oura.activity",
  "shop.orders",
  "spotify.profile",
  "spotify.playlists",
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

function payloadSha256(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

describe.each(SCOPES)("%s golden projection contract", (scope) => {
  const golden = load(scope);

  it("records the legacy and fixture provenance", () => {
    expect(golden.scope).toBe(scope);
    if (
      [
        "chatgpt.conversations",
        "chatgpt.memories",
        "claude.conversations",
        "claude.projects",
      ].includes(scope)
    ) {
      expect(golden.provenance.legacyConnector).toMatch(
        /^(chatgpt-4\.0\.0-vana\.1\.js|claude-export-playwright\.js) .* sha256:[0-9a-f]{64}$/,
      );
      expect(golden.provenance.pdppBundle).toMatch(/sha256:[0-9a-f]{64}$/);
    } else if (scope.startsWith("github.")) {
      expect(golden.provenance.legacyConnector).toMatch(
        /^frozen github-playwright 1\.5\.1; archive sha256:[0-9a-f]{64}; script\.js sha256:[0-9a-f]{64}; expected output and PDPP record source: .*github-browser-parity-fixtures\.ts at unity-surfaces commit [0-9a-f]{40} sha256:[0-9a-f]{64}$/,
      );
      expect(golden.provenance.pdppBundle).toMatch(
        /^github-browser 0\.2\.0 snapshots from PDP-Connect\/data-connectors commit [0-9a-f]{40}; frozen inputs recorded in github-browser-parity-fixtures\.ts; provenance source: .*github-browser-parity-fixtures\.ts at unity-surfaces commit [0-9a-f]{40} sha256:[0-9a-f]{64}; read-time projection source: personal-server-ts commit [0-9a-f]{40}; fixture source sha256:[0-9a-f]{64}$/,
      );
    } else if (
      ["shop.orders", "spotify.profile", "spotify.playlists"].includes(scope)
    ) {
      expect(golden.provenance.legacyConnector).toMatch(
        /^current binding output, not captured legacy-connector output; (shop\.orders|spotify\.(profile|playlists)) from packages\/core\/src\/legacy-projection\/bindings\.ts at personal-server-ts commit 81e63d84c38dd45c47073daf790b8905c834c553$/,
      );
      expect(golden.provenance.pdppBundle).toMatch(
        /^synthetic (shop\.orders|spotify\.(profile|playlists)) records against vendored declarations at personal-server-ts commit 81e63d84c38dd45c47073daf790b8905c834c553; no bundle executed$/,
      );
      expect(golden.provenance.expectedSideNote).toBe(
        "current binding output, not captured legacy-connector output",
      );
    } else {
      expect(golden.provenance.legacyConnector).toMatch(
        /^OpenPet nullable-score contract from .*\/client-reconciliation\.md sha256:[0-9a-f]{64} \(evidence checkout has no Git metadata\); expected field assertions from .*\/oura-browser\.test\.ts at unity-surfaces commit [0-9a-f]{40} sha256:[0-9a-f]{64}$/,
      );
      expect(golden.provenance.pdppBundle).toMatch(
        /^oura-browser 0\.1\.2 stream binding from .*\/oura-browser\.test\.ts at unity-surfaces commit [0-9a-f]{40} sha256:[0-9a-f]{64}; PS projection source: personal-server-ts commit [0-9a-f]{40}; fixture source sha256:[0-9a-f]{64}$/,
      );
      expect(golden.provenance.expectedSideNote).toBe(
        "OpenPet-shaped expectation from Desktop's oura-browser test, not a captured legacy-connector output.",
      );
    }
    if (golden.provenance.rawSourceAndExpectedFiles) {
      expect(
        golden.provenance.rawSourceAndExpectedFiles.length,
      ).toBeGreaterThan(0);
      expect(golden.provenance.profileCaveat).toBeTruthy();
      expect(golden.provenance.emptyOrNullEdge).toBeTruthy();
    }
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
        profileKey: golden.profileKey,
      });

      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.diagnostics).toBeUndefined();
      if (golden.expectedLegacySha256) {
        expect(payloadSha256(result.payload)).toBe(golden.expectedLegacySha256);
      } else {
        expect(golden.legacyBody).toBeDefined();
        expect(diffBodies(golden.legacyBody, result.payload)).toEqual(
          golden.reviewedDifferences.map(({ path, legacy, projected }) => ({
            path,
            legacy,
            projected,
          })),
        );
      }
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
      profileKey: golden.profileKey,
    });
    const expectedKeys = golden.legacyBody
      ? Object.keys(golden.legacyBody)
      : golden.legacyBodyKeys;
    expect(result.ok && Object.keys(result.payload)).toEqual(expectedKeys);
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

describe.each(["shop.orders", "spotify.profile", "spotify.playlists"])(
  "%s current-binding empty and dirty-row regressions",
  (scope) => {
    const golden = load(scope);

    it("includes both required edge cases", () => {
      expect(golden.cases?.map((entry) => entry.case)).toEqual([
        "empty",
        "dirty-row",
      ]);
    });

    describe.each(golden.cases ?? [])("$case", (edge) => {
      it("retains the explicitly non-legacy provenance", () => {
        expect(edge.scope).toBe(scope);
        expect(edge.provenance).toEqual(golden.provenance);
        expect(edge.reviewedDifferences).toEqual([]);
      });

      it.each([
        ["source order", false],
        ["primary-key order", true],
      ])(
        "matches the traced binding result (%s)",
        (_label, orderByPrimaryKey) => {
          const result = projectPdppRecordsToLegacyPayload(
            scope,
            records(edge),
            {
              fetchedStreams: edge.fetchedStreams,
              now: ORACLE_CLOCK,
              orderByPrimaryKey,
            },
          );

          if (scope === "spotify.profile" && edge.case === "empty") {
            const expected = {
              ok: false,
              error: { kind: "empty_singleton", scope: "spotify.profile" },
            };
            expect(edge.expectedResult).toEqual(expected);
            expect(edge.legacyBody).toBeUndefined();
            expect(result).toEqual(expected);
            return;
          }

          expect(edge.expectedResult).toBeUndefined();
          expect(edge.legacyBody).toBeDefined();
          expect(result.ok).toBe(true);
          if (!result.ok) return;
          expect(result.diagnostics).toBeUndefined();
          expect(result.payload).toEqual(edge.legacyBody);
          expect(diffBodies(edge.legacyBody, result.payload)).toEqual([]);
          expect(Object.keys(result.payload)).toEqual(
            Object.keys(edge.legacyBody!),
          );
          const validate = ajv.compile(schemaFor(scope));
          expect(
            validate(result.payload),
            JSON.stringify(validate.errors, null, 2),
          ).toBe(true);
        },
      );
    });
  },
);

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

describe("ChatGPT edge-case parity observations", () => {
  const conversation = (
    id: string,
    update_time: string,
    extras: Record<string, unknown> = {},
  ): PdppRecord => ({
    stream: "conversations",
    data: {
      id,
      title: id,
      create_time: "2026-09-01T00:00:00.000Z",
      update_time,
      current_node: null,
      message_count_on_current_branch: 0,
      ...extras,
    },
  });

  it("projects a conversation with zero messages as an empty message list", () => {
    // Current behavior, not legacy-verified: the ChatGPT parity fixture has
    // no zero-message row; the Unity adapter test is a projector assertion,
    // not a captured legacy output (Unity commit 01164027ecac1403b867d8b5fef9a930dbcf69eb).
    const result = projectPdppRecordsToLegacyPayload(
      "chatgpt.conversations",
      [conversation("empty", "2026-09-01T00:00:00.000Z")],
      { fetchedStreams: ["conversations", "messages"], now: ORACLE_CLOCK },
    );

    expect(result).toEqual({
      ok: true,
      payload: {
        conversations: [
          {
            id: "empty",
            title: "empty",
            create_time: "2026-09-01T00:00:00.000Z",
            update_time: "2026-09-01T00:00:00.000Z",
            message_count: 0,
            messages: [],
            fetched_at: ORACLE_CLOCK,
          },
        ],
        total: 1,
      },
    });
  });

  it("omits the bad-timestamp peer, falls back for a missing title, and keeps the valid peer", () => {
    // Current behavior, not legacy-verified: neither the PS ChatGPT parity
    // fixture nor Unity's legacy-scope-adapter index.test.ts captures output
    // from the legacy connector for these peers (Unity commit above).
    const result = projectPdppRecordsToLegacyPayload(
      "chatgpt.conversations",
      [
        conversation("valid", "2026-09-03T00:00:00.000Z"),
        conversation("bad-time", "2026-09-02T00:00:00.000Z", {
          create_time: 17,
        }),
        conversation("missing-title", "2026-09-01T00:00:00.000Z", {
          title: undefined,
        }),
      ],
      {
        fetchedStreams: ["conversations", "messages"],
        now: ORACLE_CLOCK,
        orderByPrimaryKey: true,
      },
    );

    expect(result).toEqual({
      ok: true,
      payload: {
        conversations: [
          {
            id: "valid",
            title: "valid",
            create_time: "2026-09-01T00:00:00.000Z",
            update_time: "2026-09-03T00:00:00.000Z",
            message_count: 0,
            messages: [],
            fetched_at: ORACLE_CLOCK,
          },
          {
            id: "missing-title",
            title: "Untitled",
            create_time: "2026-09-01T00:00:00.000Z",
            update_time: "2026-09-01T00:00:00.000Z",
            message_count: 0,
            messages: [],
            fetched_at: ORACLE_CLOCK,
          },
        ],
        total: 2,
      },
      diagnostics: [
        {
          kind: "records_dropped",
          scope: "chatgpt.conversations",
          stream: "conversations",
          count: 1,
          reasons: ["Conversation timestamps must be strings, null, or absent"],
        },
      ],
    });
  });

  it("projects a zero-row fetched memories stream as an empty payload", () => {
    // Current behavior, not legacy-verified: the existing captured memories
    // fixture contains rows, while Unity's zero-row case is a projector test.
    const result = projectPdppRecordsToLegacyPayload("chatgpt.memories", [], {
      fetchedStreams: ["memories"],
      now: ORACLE_CLOCK,
    });

    expect(result).toEqual({
      ok: true,
      payload: { memories: [], total: 0 },
    });
  });

  it("orders reverse-supplied conversations by newest update first", () => {
    const result = projectPdppRecordsToLegacyPayload(
      "chatgpt.conversations",
      [
        conversation("newer", "2026-09-03T00:00:00.000Z"),
        conversation("older", "2026-09-01T00:00:00.000Z"),
      ],
      {
        fetchedStreams: ["conversations", "messages"],
        now: ORACLE_CLOCK,
        orderByPrimaryKey: true,
      },
    );

    expect(
      result.ok &&
        (result.payload.conversations as { id: string }[]).map(({ id }) => id),
    ).toEqual(["newer", "older"]);
  });
});
