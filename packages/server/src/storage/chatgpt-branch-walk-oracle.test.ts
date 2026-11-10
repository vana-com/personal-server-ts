import { createHash } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import {
  LEGACY_SCOPE_BINDINGS,
  type PdppRecord,
} from "@opendatalabs/personal-server-ts-core/legacy-projection";
import { compareLegacyCoverage } from "@opendatalabs/personal-server-ts-core/storage/legacy-scope-coverage";
import { createLegacyScopeView } from "@opendatalabs/personal-server-ts-core/storage/legacy-scope-view";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import { createLegacyScopeAuthority } from "./legacy-scope-authority.js";
import { initializeDatabase } from "./index-schema.js";

const T = "2026-11-03T00:00:00.000Z";
const CHATGPT = "https://registry.pdpp.dev/sources/chatgpt";
const SCOPE = "chatgpt.conversations";
const HASH_A =
  "559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd";
const HASH_B =
  "df7e70e5021544f4834bbee64a9e3789febc4be81470df629cad6ddb03320a5c";

type Fixture = ReturnType<typeof createReadFixture>;
const openFixtures: Fixture[] = [];

afterEach(() => {
  for (const fixture of openFixtures.splice(0)) fixture.close();
});

function C(id: string, tip: string | null, count: number) {
  return {
    id,
    title: id,
    create_time: T,
    update_time: T,
    current_node: tip,
    message_count_on_current_branch: count,
  };
}

function M(
  conversationId: string,
  node: string,
  parent: string | null,
  flag: boolean,
  text = node,
) {
  return {
    id: `${conversationId}:${node}`,
    conversation_id: conversationId,
    parent_id: parent === null ? null : `${conversationId}:${parent}`,
    on_current_branch: flag,
    role: "user",
    content_type: "text",
    content: text,
    create_time: T,
    model_slug: null,
  };
}

function records(
  conversations: Record<string, unknown>[],
  messages: Record<string, unknown>[],
): PdppRecord[] {
  return [
    ...conversations.map((data) => ({ stream: "conversations", data })),
    ...messages.map((data) => ({ stream: "messages", data })),
  ];
}

function project(input: PdppRecord[]) {
  const result = LEGACY_SCOPE_BINDINGS.get(SCOPE)!.project(input, {
    fetchedStreams: ["conversations", "messages"],
    now: T,
    orderByPrimaryKey: true,
  });
  if (!result.ok) throw new Error(`P rejected the fixture: ${result.error}`);
  return result;
}

function createReadFixture(
  conversations: Record<string, unknown>[],
  messages: Record<string, unknown>[],
  options: {
    legacy?: { collectedAt: string; data: Record<string, unknown> };
    sourceCollectedAt?: string;
  } = {},
) {
  const db = initializeDatabase(":memory:");
  const store = createSqliteRecordStore(db);
  store.registerConnection({
    instance: "chat",
    sourceId: CHATGPT,
    method: "chatgpt",
    label: "",
  });
  const sourceCollectedAt = options.sourceCollectedAt ?? T;
  for (const [stream, rows] of [
    ["conversations", conversations],
    ["messages", messages],
  ] as const) {
    store.replaceStream({
      instance: "chat",
      stream,
      method: "chatgpt",
      generation: 1,
      primaryKey: ["id"],
      emittedAt: T,
      sourceCollectedAt,
      envelopes: rows.map((data) => ({
        instance: "chat",
        stream,
        key: String(data.id),
        data,
        emitted_at: T,
      })),
    });
  }
  const config = {
    authority: createLegacyScopeAuthority(db),
    records: store,
    configuredMethods: (sourceId: string) =>
      sourceId === CHATGPT ? ["chatgpt"] : [],
    ...(options.legacy
      ? {
          readLegacyHead: async () => ({
            version: "1.0",
            scope: SCOPE,
            collectedAt: options.legacy!.collectedAt,
            data: options.legacy!.data,
          }),
        }
      : {}),
  };
  if (options.legacy) {
    db.prepare(
      "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
    ).run(
      "chatgpt/conversations/old.json",
      SCOPE,
      options.legacy.collectedAt,
      1,
    );
  }
  const view = createLegacyScopeView(config);
  const fixture = {
    db,
    store,
    view,
    config,
    close: () => store.close(),
  };
  openFixtures.push(fixture);
  return fixture;
}

type GapCategory =
  "branch_incomplete" | "branch_cycle" | "flag_fallback_ambiguous";
type ExpectedGap = {
  conversationIdHash: string;
  category: GapCategory;
  declaredCount: number;
  walkedCount: number;
};

function normalizeGapReason(reason: string): GapCategory {
  if (reason.includes("cycle")) return "branch_cycle";
  if (/ambiguous|disconnected/.test(reason)) return "flag_fallback_ambiguous";
  if (
    /parent_not_stored|walked_count_below_declared|incomplete|count_mismatch/.test(
      reason,
    )
  )
    return "branch_incomplete";
  throw new Error(`Unrecognized ChatGPT coverage gap reason: ${reason}`);
}

function assertGaps(
  gaps:
    | readonly {
        conversationIdHash: string;
        reason: string;
        declaredCount: number;
        walkedCount: number;
      }[]
    | undefined,
  expected: ExpectedGap[],
) {
  const actual = gaps ?? [];
  expect(actual).toHaveLength(expected.length);
  expect(
    actual
      .map((gap) => ({
        conversationIdHash: gap.conversationIdHash,
        category: normalizeGapReason(gap.reason),
        declaredCount: gap.declaredCount,
        walkedCount: gap.walkedCount,
      }))
      .sort((a, b) => a.conversationIdHash.localeCompare(b.conversationIdHash)),
  ).toEqual(
    [...expected].sort((a, b) =>
      a.conversationIdHash.localeCompare(b.conversationIdHash),
    ),
  );
}

function assertDiagnostics(
  diagnostics:
    | readonly {
        conversationIdHash: string;
        reason: string;
        declaredCount: number;
        walkedCount: number;
      }[]
    | undefined,
  expected: {
    conversationIdHash: string;
    reason: "declared_count_below_walked" | "declared_count_above_walked";
    declaredCount: number;
    walkedCount: number;
  }[],
) {
  expect(diagnostics ?? []).toEqual(expected);
}

async function readCanonical(fixture: Fixture) {
  const read = await fixture.view.readLatest(SCOPE);
  expect(read.kind).toBe("canonical");
  if (read.kind !== "canonical")
    throw new Error("V did not serve canonical data");
  return read;
}

const A2 = {
  conversations: [
    {
      id: "A",
      title: "A",
      create_time: T,
      update_time: T,
      message_count: 2,
      messages: [
        {
          id: "a0",
          role: "user",
          content: "a0",
          content_type: "text",
          create_time: T,
          model: null,
        },
        {
          id: "a1",
          role: "user",
          content: "a1",
          content_type: "text",
          create_time: T,
          model: null,
        },
      ],
      fetched_at: T,
    },
  ],
  total: 1,
};

const A3 = {
  conversations: [
    {
      id: "A",
      title: "A",
      create_time: T,
      update_time: T,
      message_count: 3,
      messages: [
        {
          id: "a0",
          role: "user",
          content: "a0",
          content_type: "text",
          create_time: T,
          model: null,
        },
        {
          id: "a1",
          role: "user",
          content: "a1",
          content_type: "text",
          create_time: T,
          model: null,
        },
        {
          id: "a2",
          role: "user",
          content: "a2",
          content_type: "text",
          create_time: T,
          model: null,
        },
      ],
      fetched_at: T,
    },
  ],
  total: 1,
};

const H2 = {
  conversations: [
    {
      id: "H",
      title: "H",
      create_time: T,
      update_time: T,
      message_count: 2,
      messages: [
        {
          id: "h0",
          role: "user",
          content: "h0",
          content_type: "text",
          create_time: T,
          model: null,
        },
        {
          id: "h1",
          role: "user",
          content: "h1",
          content_type: "text",
          create_time: T,
          model: null,
        },
      ],
      fetched_at: T,
    },
  ],
  total: 1,
};

const H2J1 = {
  conversations: [
    {
      id: "H",
      title: "H",
      create_time: T,
      update_time: T,
      message_count: 2,
      messages: [
        {
          id: "h0",
          role: "user",
          content: "h0",
          content_type: "text",
          create_time: T,
          model: null,
        },
        {
          id: "h1",
          role: "user",
          content: "h1",
          content_type: "text",
          create_time: T,
          model: null,
        },
      ],
      fetched_at: T,
    },
    {
      id: "J",
      title: "J",
      create_time: T,
      update_time: T,
      message_count: 1,
      messages: [
        {
          id: "j0",
          role: "user",
          content: "j0",
          content_type: "text",
          create_time: T,
          model: null,
        },
      ],
      fetched_at: T,
    },
  ],
  total: 2,
};

const B1 = {
  conversations: [
    {
      id: "B",
      title: "B",
      create_time: T,
      update_time: T,
      message_count: 1,
      messages: [
        {
          id: "b0",
          role: "user",
          content: "PRIVATE-B",
          content_type: "text",
          create_time: T,
          model: null,
        },
      ],
      fetched_at: T,
    },
  ],
  total: 1,
};

const AB1 = {
  conversations: [
    {
      id: "A",
      title: "A",
      create_time: T,
      update_time: T,
      message_count: 1,
      messages: [
        {
          id: "a0",
          role: "user",
          content: "a0",
          content_type: "text",
          create_time: T,
          model: null,
        },
      ],
      fetched_at: T,
    },
    {
      id: "B",
      title: "B",
      create_time: T,
      update_time: T,
      message_count: 1,
      messages: [
        {
          id: "b0",
          role: "user",
          content: "PRIVATE-B",
          content_type: "text",
          create_time: T,
          model: null,
        },
      ],
      fetched_at: T,
    },
  ],
  total: 2,
};

const ABX = {
  conversations: [
    {
      id: "A",
      title: "A",
      create_time: T,
      update_time: T,
      message_count: 1,
      messages: [
        {
          id: "x",
          role: "user",
          content: "A text",
          content_type: "text",
          create_time: T,
          model: null,
        },
      ],
      fetched_at: T,
    },
    {
      id: "B",
      title: "B",
      create_time: T,
      update_time: T,
      message_count: 1,
      messages: [
        {
          id: "x",
          role: "user",
          content: "B text",
          content_type: "text",
          create_time: T,
          model: null,
        },
      ],
      fetched_at: T,
    },
  ],
  total: 2,
};

const A1NEW = {
  conversations: [
    {
      id: "A",
      title: "A",
      create_time: T,
      update_time: T,
      message_count: 1,
      messages: [
        {
          id: "a0",
          role: "user",
          content: "new",
          content_type: "text",
          create_time: T,
          model: null,
        },
      ],
      fetched_at: T,
    },
  ],
  total: 1,
};

const AEMPTYFILTERED = {
  conversations: [
    {
      id: "A",
      title: "A",
      create_time: T,
      update_time: T,
      message_count: 2,
      messages: [
        {
          id: "a0",
          role: "user",
          content: "first",
          content_type: "text",
          create_time: T,
          model: null,
        },
        {
          id: "a2",
          role: "user",
          content: "last",
          content_type: "text",
          create_time: T,
          model: null,
        },
      ],
      fetched_at: T,
    },
  ],
  total: 1,
};

describe("independent ChatGPT branch-walk oracle", () => {
  it("O01 — equal count, missing synthetic root is clean", async () => {
    const cs = [C("A", "a1", 2)];
    const ms = [M("A", "a0", "synthetic-root", true), M("A", "a1", "a0", true)];
    const p = project(records(cs, ms));
    expect(p.payload).toEqual(A2);
    expect(p.chatgptCoverageGaps ?? []).toEqual([]);
    expect(p.chatgptBranchDiagnostics ?? []).toEqual([]);
    const f = createReadFixture(cs, ms);
    const v = await readCanonical(f);
    expect(v.envelope.data).toEqual(A2);
    assertGaps(v.chatgptCoverageGaps, []);
    assertDiagnostics(v.chatgptBranchDiagnostics, []);
  });

  it("O02 — walk wins over stale false flags", async () => {
    const cs = [C("A", "a1", 2)];
    const ms = [
      M("A", "a0", "synthetic-root", false),
      M("A", "a1", "a0", false),
    ];
    const p = project(records(cs, ms));
    expect(p.payload).toEqual(A2);
    expect(p.chatgptCoverageGaps ?? []).toEqual([]);
    expect(p.chatgptBranchDiagnostics ?? []).toEqual([]);
    const f = createReadFixture(cs, ms);
    const v = await readCanonical(f);
    expect(v.envelope.data).toEqual(A2);
    assertGaps(v.chatgptCoverageGaps, []);
    assertDiagnostics(v.chatgptBranchDiagnostics, []);
  });

  it("O03 — one false intermediate flag does not break a proved path", async () => {
    const cs = [C("A", "a2", 3)];
    const ms = [
      M("A", "a0", "synthetic-root", true),
      M("A", "a1", "a0", false),
      M("A", "a2", "a1", true),
    ];
    const p = project(records(cs, ms));
    expect(p.payload).toEqual(A3);
    expect(p.chatgptCoverageGaps ?? []).toEqual([]);
    const f = createReadFixture(cs, ms);
    const v = await readCanonical(f);
    expect(v.envelope.data).toEqual(A3);
    assertGaps(v.chatgptCoverageGaps, []);
  });

  it.each([2, 0])("O04 — declared below walked, N=%i", async (count) => {
    const cs = [C("A", "a2", count)];
    const ms = [
      M("A", "a0", "synthetic-root", true),
      M("A", "a1", "a0", true),
      M("A", "a2", "a1", true),
    ];
    const diagnostic = [
      {
        conversationIdHash: HASH_A,
        reason: "declared_count_below_walked" as const,
        declaredCount: count,
        walkedCount: 3,
      },
    ];
    const p = project(records(cs, ms));
    expect(p.payload).toEqual(A3);
    expect(p.chatgptCoverageGaps ?? []).toEqual([]);
    expect(p.chatgptBranchDiagnostics).toEqual(diagnostic);
    const f = createReadFixture(cs, ms);
    const v = await readCanonical(f);
    expect(v.envelope.data).toEqual(A3);
    assertGaps(v.chatgptCoverageGaps, []);
    assertDiagnostics(v.chatgptBranchDiagnostics, diagnostic);
  });

  it("O05 — a stale flagged sibling cannot defeat the current path", async () => {
    const cs = [C("A", "a1", 2)];
    const ms = [
      M("A", "a0", "synthetic-root", true),
      M("A", "a1", "a0", true),
      M("A", "old", "a0", true, "old answer"),
    ];
    const p = project(records(cs, ms));
    expect(p.payload).toEqual(A2);
    expect(p.retainedChatgptMessages).toEqual([
      {
        scope: SCOPE,
        conversationId: "A",
        message: {
          id: "old",
          role: "user",
          content: "old answer",
          content_type: "text",
          create_time: T,
          model: null,
        },
      },
    ]);
    expect(p.chatgptCoverageGaps ?? []).toEqual([]);
    expect(p.chatgptBranchDiagnostics ?? []).toEqual([]);
    const f = createReadFixture(cs, ms);
    const v = await readCanonical(f);
    expect(v.envelope.data).toEqual(A2);
    assertGaps(v.chatgptCoverageGaps, []);
    assertDiagnostics(v.chatgptBranchDiagnostics, []);
  });

  it("O06 — ordinary off-branch edit/regeneration stays omitted", async () => {
    const cs = [C("A", "a1", 2)];
    const ms = [
      M("A", "a0", "synthetic-root", true),
      M("A", "a1", "a0", true),
      M("A", "old", "a0", false, "old answer"),
    ];
    for (const input of [records(cs, ms), records(cs, [...ms].reverse())]) {
      const p = project(input);
      expect(p.payload).toEqual(A2);
      expect(p.chatgptCoverageGaps ?? []).toEqual([]);
    }
    for (const ordered of [ms, [...ms].reverse()]) {
      const f = createReadFixture(cs, ordered);
      const v = await readCanonical(f);
      expect(v.envelope.data).toEqual(A2);
      assertGaps(v.chatgptCoverageGaps, []);
    }
  });

  it("O07 — a short current walk recovers a complete flag chain", async () => {
    const cs = [C("A", "tip-not-stored", 2)];
    const ms = [
      M("A", "a0", "synthetic-root", true),
      M("A", "a1", "a0", true),
      M("A", "old", "a0", false),
    ];
    const p = project(records(cs, ms));
    expect(p.payload).toEqual(A2);
    expect(p.chatgptCoverageGaps ?? []).toEqual([]);
    const f = createReadFixture(cs, ms);
    const v = await readCanonical(f);
    expect(v.envelope.data).toEqual(A2);
    assertGaps(v.chatgptCoverageGaps, []);
  });

  it("O08 — short walk and short flags gap only the damaged conversation", async () => {
    const cs = [C("A", "a1", 2), C("H", "h1", 2)];
    const ms = [
      M("A", "a1", "missing-a0", true),
      M("H", "h0", "synthetic-root", true),
      M("H", "h1", "h0", true),
    ];
    const p = project(records(cs, ms));
    expect(p.payload).toEqual(H2);
    assertGaps(p.chatgptCoverageGaps, [
      {
        conversationIdHash: HASH_A,
        category: "branch_incomplete",
        declaredCount: 2,
        walkedCount: 1,
      },
    ]);
    const f = createReadFixture(cs, ms);
    const v = await readCanonical(f);
    expect(v.envelope.data).toEqual(H2);
    assertGaps(v.chatgptCoverageGaps, [
      {
        conversationIdHash: HASH_A,
        category: "branch_incomplete",
        declaredCount: 2,
        walkedCount: 1,
      },
    ]);
    expect(v).not.toHaveProperty("complete", true);
  });

  it("O09 — two damaged conversations keep distinct per-id gaps", async () => {
    const cs = [
      C("A", "a1", 2),
      C("B", "missing-b0", 1),
      C("H", "h1", 2),
      C("J", "j0", 1),
    ];
    const ms = [
      M("A", "a1", "missing-a0", true),
      M("H", "h0", "synthetic-root", true),
      M("H", "h1", "h0", true),
      M("J", "j0", "synthetic-root", true),
    ];
    const expectedGaps = [
      {
        conversationIdHash: HASH_A,
        category: "branch_incomplete" as const,
        declaredCount: 2,
        walkedCount: 1,
      },
      {
        conversationIdHash: HASH_B,
        category: "branch_incomplete" as const,
        declaredCount: 1,
        walkedCount: 0,
      },
    ];
    for (const input of [
      records(cs, ms),
      records([...cs].reverse(), [...ms].reverse()),
    ]) {
      const p = project(input);
      expect(p.payload).toEqual(H2J1);
      assertGaps(p.chatgptCoverageGaps, expectedGaps);
    }
    for (const [conversations, messages] of [
      [cs, ms],
      [[...cs].reverse(), [...ms].reverse()],
    ] as const) {
      const f = createReadFixture(conversations, messages);
      const v = await readCanonical(f);
      expect(v.envelope.data).toEqual(H2J1);
      assertGaps(v.chatgptCoverageGaps, expectedGaps);
    }
  });

  it("O10 — a self-cycle cannot be a one-message success", async () => {
    const cs = [C("A", "a0", 1), C("H", "h1", 2)];
    const ms = [
      M("A", "a0", "a0", true),
      M("H", "h0", "synthetic-root", true),
      M("H", "h1", "h0", true),
    ];
    const expected = [
      {
        conversationIdHash: HASH_A,
        category: "branch_cycle" as const,
        declaredCount: 1,
        walkedCount: 1,
      },
    ];
    const p = project(records(cs, ms));
    expect(p.payload).toEqual(H2);
    assertGaps(p.chatgptCoverageGaps, expected);
    const f = createReadFixture(cs, ms);
    const v = await readCanonical(f);
    expect(v.envelope.data).toEqual(H2);
    assertGaps(v.chatgptCoverageGaps, expected);
  });

  it.each([2, 1])("O11 — a two-node cycle cannot pass, N=%i", async (count) => {
    const cs = [C("A", "a1", count), C("H", "h1", 2)];
    const ms = [
      M("A", "a0", "a1", true),
      M("A", "a1", "a0", true),
      M("H", "h0", "synthetic-root", true),
      M("H", "h1", "h0", true),
    ];
    const expected = [
      {
        conversationIdHash: HASH_A,
        category: "branch_cycle" as const,
        declaredCount: count,
        walkedCount: 2,
      },
    ];
    const p = project(records(cs, ms));
    expect(p.payload).toEqual(H2);
    assertGaps(p.chatgptCoverageGaps, expected);
    expect(p.chatgptBranchDiagnostics ?? []).toEqual([]);
    const f = createReadFixture(cs, ms);
    const v = await readCanonical(f);
    expect(v.envelope.data).toEqual(H2);
    assertGaps(v.chatgptCoverageGaps, expected);
    assertDiagnostics(v.chatgptBranchDiagnostics, []);
  });

  it("O12 — a foreign parent never supplies local history", async () => {
    const foreignParentA0 = {
      ...M("A", "a0", null, true),
      parent_id: "B:b0",
    };
    const cs = [C("A", "a0", 2), C("B", "b0", 1)];
    const ms = [
      foreignParentA0,
      M("B", "b0", "synthetic-root", true, "PRIVATE-B"),
    ];
    const p = project(records(cs, ms));
    expect(p.payload).toEqual(B1);
    assertGaps(p.chatgptCoverageGaps, [
      {
        conversationIdHash: HASH_A,
        category: "branch_incomplete",
        declaredCount: 2,
        walkedCount: 1,
      },
    ]);
    const f = createReadFixture(cs, ms);
    const v = await readCanonical(f);
    expect(v.envelope.data).toEqual(B1);
    assertGaps(v.chatgptCoverageGaps, [
      {
        conversationIdHash: HASH_A,
        category: "branch_incomplete",
        declaredCount: 2,
        walkedCount: 1,
      },
    ]);

    const equalCs = [C("A", "a0", 1), C("B", "b0", 1)];
    const equal = project(records(equalCs, ms));
    expect(equal.payload).toEqual(AB1);
    expect(equal.chatgptCoverageGaps ?? []).toEqual([]);
    const equalFixture = createReadFixture(equalCs, ms);
    const equalRead = await readCanonical(equalFixture);
    expect(equalRead.envelope.data).toEqual(AB1);
    assertGaps(equalRead.chatgptCoverageGaps, []);
  });

  it("O13 — identical bare node ids in two conversations stay isolated", async () => {
    const cs = [C("A", "x", 1), C("B", "x", 1)];
    const ms = [
      M("A", "x", "root", true, "A text"),
      M("B", "x", "root", true, "B text"),
    ];
    for (const input of [records(cs, ms), records(cs, [...ms].reverse())]) {
      const p = project(input);
      expect(p.payload).toEqual(ABX);
      expect(p.chatgptCoverageGaps ?? []).toEqual([]);
    }
    for (const ordered of [ms, [...ms].reverse()]) {
      const f = createReadFixture(cs, ordered);
      const v = await readCanonical(f);
      expect(v.envelope.data).toEqual(ABX);
      assertGaps(v.chatgptCoverageGaps, []);
    }
  });

  it("O14 — bare/prefixed duplicate prefers the prefixed row", async () => {
    const cs = [C("A", "a0", 1)];
    const oldBare = {
      id: "a0",
      conversation_id: "A",
      parent_id: null,
      on_current_branch: true,
      role: "user",
      content_type: "text",
      content: "old",
      create_time: T,
      model_slug: null,
    };
    const current = M("A", "a0", null, true, "new");
    for (const ordered of [
      [oldBare, current],
      [current, oldBare],
    ]) {
      const p = project(records(cs, ordered));
      expect(p.payload).toEqual(A1NEW);
      expect(p.chatgptCoverageGaps ?? []).toEqual([]);
      expect(p.chatgptBranchDiagnostics ?? []).toEqual([]);
    }
    for (const ordered of [
      [oldBare, current],
      [current, oldBare],
    ]) {
      const f = createReadFixture(cs, ordered);
      const v = await readCanonical(f);
      expect(v.envelope.data).toEqual(A1NEW);
      assertGaps(v.chatgptCoverageGaps, []);
    }
  });

  it("O15 — an exact duplicate input row is idempotent", () => {
    const cs = [C("A", "a1", 2)];
    const a0 = M("A", "a0", "synthetic-root", true);
    const a1 = M("A", "a1", "a0", true);
    const p = project(records(cs, [a0, a1, { ...a1 }]));
    expect(p.payload).toEqual(A2);
    expect(p.chatgptCoverageGaps ?? []).toEqual([]);
    expect(p.chatgptBranchDiagnostics ?? []).toEqual([]);
  });

  it("O16 — legacy projection omits empty text and canonical storage retains it", async () => {
    const cs = [C("A", "a2", 3)];
    const ms = [
      M("A", "a0", "root", true, "first"),
      M("A", "a1", "a0", true, ""),
      M("A", "a2", "a1", true, "last"),
    ];
    const p = project(records(cs, ms));
    expect(p.payload).toEqual(AEMPTYFILTERED);
    expect(p.chatgptCoverageGaps ?? []).toEqual([]);
    expect(p.chatgptBranchDiagnostics ?? []).toEqual([]);
    const f = createReadFixture(cs, ms);
    const v = await readCanonical(f);
    expect(v.envelope.data).toEqual(AEMPTYFILTERED);
    // Stored canonical content preserves an explicit empty value. The legacy
    // projection omits it to match the legacy envelope shape.
    const storedEmpty = f.db
      .prepare(
        "SELECT data FROM pdpp_records WHERE instance = ? AND stream = ? AND record_key = ?",
      )
      .get("chat", "messages", "A:a1") as { data: string };
    expect((JSON.parse(storedEmpty.data) as { content: string }).content).toBe(
      "",
    );
    assertGaps(v.chatgptCoverageGaps, []);
    assertDiagnostics(v.chatgptBranchDiagnostics, []);

    const shortCs = [C("A", "a2", 2)];
    const short = project(records(shortCs, ms));
    expect(short.payload).toEqual(AEMPTYFILTERED);
    expect(short.chatgptBranchDiagnostics).toEqual([
      {
        conversationIdHash: HASH_A,
        reason: "declared_count_below_walked",
        declaredCount: 2,
        walkedCount: 3,
      },
    ]);
    const shortFixture = createReadFixture(shortCs, ms);
    const shortRead = await readCanonical(shortFixture);
    expect(shortRead.envelope.data).toEqual(AEMPTYFILTERED);
    assertDiagnostics(shortRead.chatgptBranchDiagnostics, [
      {
        conversationIdHash: HASH_A,
        reason: "declared_count_below_walked",
        declaredCount: 2,
        walkedCount: 3,
      },
    ]);
  });

  it("O17 — invalid flag fallback does not invent a thread", async () => {
    const cs = [C("A", "missing-tip", 2), C("H", "h1", 2)];
    const ms = [
      M("A", "a0", "missing-parent-0", true),
      M("A", "a1", "missing-parent-1", true),
      M("H", "h0", "synthetic-root", true),
      M("H", "h1", "h0", true),
    ];
    const expected = [
      {
        conversationIdHash: HASH_A,
        category: "flag_fallback_ambiguous" as const,
        declaredCount: 2,
        walkedCount: 0,
      },
    ];
    const p = project(records(cs, ms));
    expect(p.payload).toEqual(H2);
    assertGaps(p.chatgptCoverageGaps, expected);
    const f = createReadFixture(cs, ms);
    const v = await readCanonical(f);
    expect(v.envelope.data).toEqual(H2);
    assertGaps(v.chatgptCoverageGaps, expected);
  });

  it("O18 — all damaged conversations return a partial empty payload", async () => {
    const cs = [C("A", "a1", 2), C("B", "missing-b0", 1)];
    const ms = [M("A", "a1", "missing-a0", true)];
    const expected = [
      {
        conversationIdHash: HASH_A,
        category: "branch_incomplete" as const,
        declaredCount: 2,
        walkedCount: 1,
      },
      {
        conversationIdHash: HASH_B,
        category: "branch_incomplete" as const,
        declaredCount: 1,
        walkedCount: 0,
      },
    ];
    const p = project(records(cs, ms));
    expect(p.payload).toEqual({ conversations: [], total: 0 });
    assertGaps(p.chatgptCoverageGaps, expected);
    const f = createReadFixture(cs, ms);
    const v = await readCanonical(f);
    expect(v.envelope.data).toEqual({ conversations: [], total: 0 });
    assertGaps(v.chatgptCoverageGaps, expected);
    expect(v).not.toHaveProperty("complete", true);
  });

  it("O19 — a deleted sole connection refuses even with a legacy file", async () => {
    const legacy = {
      conversations: [
        {
          id: "H",
          title: "H",
          create_time: T,
          update_time: T,
          message_count: 2,
          messages: [
            {
              id: "h0",
              role: "user",
              content: "h0",
              content_type: "text",
              create_time: T,
              model: null,
            },
            {
              id: "h1",
              role: "user",
              content: "h1",
              content_type: "text",
              create_time: T,
              model: null,
            },
          ],
          fetched_at: T,
        },
      ],
      total: 1,
    };
    const f = createReadFixture(
      [C("H", "h1", 2)],
      [M("H", "h0", "root", true), M("H", "h1", "h0", true)],
      {
        legacy: { collectedAt: "2026-11-02T00:00:00.000Z", data: legacy },
      },
    );
    f.store.deleteConnection("chat");
    const read = await f.view.readLatest(SCOPE);
    expect(read).toEqual({
      kind: "refused",
      refusal: {
        status: "unavailable",
        reason: "no_connection",
        candidates: 0,
      },
    });
    expect(read.kind).not.toBe("file");
  });

  it("O20 — missing old entity without deletion proof refuses after takeover", async () => {
    const initialConversations = [C("H", "h1", 2), C("D", "d0", 1)];
    const initialMessages = [
      M("H", "h0", "root", true),
      M("H", "h1", "h0", true),
      M("D", "d0", "root", true),
    ];
    const legacyFixture = createReadFixture(
      initialConversations,
      initialMessages,
    );
    const oldRead = await readCanonical(legacyFixture);
    const legacyData = oldRead.envelope.data as Record<string, unknown>;
    legacyFixture.db
      .prepare(
        "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
      )
      .run("chatgpt/conversations/covered.json", SCOPE, T, 1);
    const f = createLegacyScopeView({
      ...legacyFixture.config,
      readLegacyHead: async () => ({
        version: "1.0",
        scope: SCOPE,
        collectedAt: T,
        data: legacyData,
      }),
    });
    expect((await f.readLatest(SCOPE)).kind).toBe("canonical");

    legacyFixture.store.replaceStream({
      instance: "chat",
      stream: "conversations",
      method: "chatgpt",
      generation: 1,
      primaryKey: ["id"],
      emittedAt: "2026-11-04T00:00:00.000Z",
      sourceCollectedAt: "2026-11-04T00:00:00.000Z",
      envelopes: [
        {
          instance: "chat",
          stream: "conversations",
          key: "H",
          data: C("H", "h1", 2),
          emitted_at: "2026-11-04T00:00:00.000Z",
        },
      ],
    });
    const compared = compareLegacyCoverage(
      legacyData,
      {
        conversations: [
          {
            id: "H",
            title: "H",
            create_time: T,
            update_time: T,
            message_count: 2,
            messages: [
              {
                id: "h0",
                role: "user",
                content: "h0",
                content_type: "text",
                create_time: T,
                model: null,
              },
              {
                id: "h1",
                role: "user",
                content: "h1",
                content_type: "text",
                create_time: T,
                model: null,
              },
            ],
            fetched_at: T,
          },
        ],
        total: 1,
      },
      {
        scope: SCOPE,
        entityKeys: {
          "$.conversations": ["id"],
          "$.conversations[].messages": ["id"],
        },
        canonicalNewer: true,
        allowProvenDeletion: false,
      },
    );
    expect(compared.covered).toBe(false);
    expect(compared.missingEntityCount).toBe(1);
    expect(compared.reasonCounts.missing_entity).toBe(1);
    expect(await f.readLatest(SCOPE)).toMatchObject({
      kind: "refused",
      refusal: { reason: "canonical_view_incomplete" },
    });
  });

  it("O21A — a strictly proven deletion can remain covered", () => {
    const legacy = {
      conversations: [
        {
          id: "H",
          title: "H",
          create_time: T,
          update_time: T,
          message_count: 1,
          messages: [
            {
              id: "h0",
              role: "user",
              content: "h0",
              content_type: "text",
              create_time: T,
              model: null,
            },
          ],
          fetched_at: T,
        },
        {
          id: "D",
          title: "D",
          create_time: T,
          update_time: T,
          message_count: 1,
          messages: [
            {
              id: "d0",
              role: "user",
              content: "d0",
              content_type: "text",
              create_time: T,
              model: null,
            },
          ],
          fetched_at: T,
        },
      ],
      total: 2,
    };
    const canonical = {
      conversations: [
        {
          id: "H",
          title: "H",
          create_time: T,
          update_time: T,
          message_count: 1,
          messages: [
            {
              id: "h0",
              role: "user",
              content: "h0",
              content_type: "text",
              create_time: T,
              model: null,
            },
          ],
          fetched_at: T,
        },
      ],
      total: 1,
    };
    const verdict = compareLegacyCoverage(legacy, canonical, {
      scope: SCOPE,
      entityKeys: {
        "$.conversations": ["id"],
        "$.conversations[].messages": ["id"],
      },
      canonicalNewer: true,
      allowProvenDeletion: true,
    });
    expect(verdict.missingEntityCount).toBe(1);
    expect(verdict.reasonCounts.missing_entity).toBe(1);
    expect(verdict.covered).toBe(true);
  });

  it("O21B — a branch exclusion never becomes deletion authority", async () => {
    const conversations = [C("A", "a1", 2), C("H", "h0", 1)];
    const messages = [
      M("A", "a1", "missing-a0", true),
      M("H", "h0", "root", true),
    ];
    const legacyData = {
      conversations: [
        {
          id: "A",
          title: "A",
          create_time: T,
          update_time: T,
          message_count: 1,
          messages: [
            {
              id: "a1",
              role: "user",
              content: "a1",
              content_type: "text",
              create_time: T,
              model: null,
            },
          ],
          fetched_at: T,
        },
        {
          id: "H",
          title: "H",
          create_time: T,
          update_time: T,
          message_count: 1,
          messages: [
            {
              id: "h0",
              role: "user",
              content: "h0",
              content_type: "text",
              create_time: T,
              model: null,
            },
          ],
          fetched_at: T,
        },
      ],
      total: 2,
    };
    const f = createReadFixture(conversations, messages, {
      legacy: { collectedAt: "2026-11-02T00:00:00.000Z", data: legacyData },
    });
    const read = await f.view.readLatest(SCOPE);
    expect(read.kind).toBe("canonical");
    if (read.kind !== "canonical")
      throw new Error("Branch-gap body was refused");
    expect(read.envelope.data).toEqual({
      conversations: [
        {
          id: "H",
          title: "H",
          create_time: T,
          update_time: T,
          message_count: 1,
          messages: [
            {
              id: "h0",
              role: "user",
              content: "h0",
              content_type: "text",
              create_time: T,
              model: null,
            },
          ],
          fetched_at: T,
        },
      ],
      total: 1,
    });
    assertGaps(read.chatgptCoverageGaps, [
      {
        conversationIdHash: HASH_A,
        category: "branch_incomplete",
        declaredCount: 2,
        walkedCount: 1,
      },
    ]);
    expect(f.view.verdictFor(SCOPE)[0]?.reasonCounts.missing_entity).toBe(1);
  });

  it("O22 — a retained ChatGPT tombstone keeps branch-gap refusal whole-scope", async () => {
    // A retained ChatGPT tombstone must block whole-scope fallback when
    // another conversation cannot be reconstructed.
    const initialConversations = [C("A", "a0", 1), C("H", "h0", 1)];
    const deletedContent = "deleted branch content";
    const deletedContentHash = createHash("sha256")
      .update(deletedContent)
      .digest("hex");
    const initialMessages = [
      M("A", "a0", "root", true, deletedContent),
      M("H", "h0", "root", true),
    ];
    const f = createReadFixture(initialConversations, initialMessages);
    const original = await readCanonical(f);
    const originalMessages = (
      original.envelope.data as {
        conversations: { messages: { id: string; content: string }[] }[];
      }
    ).conversations.flatMap((conversation) => conversation.messages);
    expect(originalMessages.some((message) => message.id === "a0")).toBe(true);
    expect(
      originalMessages.map((message) =>
        createHash("sha256").update(message.content).digest("hex"),
      ),
    ).toContain(deletedContentHash);
    f.db
      .prepare(
        "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
      )
      .run(
        "chatgpt/conversations/covered.json",
        SCOPE,
        "2026-11-02T00:00:00.000Z",
        1,
      );
    const view = createLegacyScopeView({
      authority: createLegacyScopeAuthority(f.db),
      records: f.store,
      configuredMethods: (sourceId: string) =>
        sourceId === CHATGPT ? ["chatgpt"] : [],
      readLegacyHead: async () => original.envelope,
    });
    expect((await view.readLatest(SCOPE)).kind).toBe("canonical");

    f.store.replaceStream({
      instance: "chat",
      stream: "conversations",
      method: "chatgpt",
      generation: 1,
      primaryKey: ["id"],
      emittedAt: "2026-11-04T00:00:00.000Z",
      sourceCollectedAt: "2026-11-04T00:00:00.000Z",
      envelopes: [
        {
          instance: "chat",
          stream: "conversations",
          key: "A",
          data: C("A", "a1", 2),
          emitted_at: "2026-11-04T00:00:00.000Z",
        },
        {
          instance: "chat",
          stream: "conversations",
          key: "H",
          data: C("H", "h0", 1),
          emitted_at: "2026-11-04T00:00:00.000Z",
        },
      ],
    });
    f.store.replaceStream({
      instance: "chat",
      stream: "messages",
      method: "chatgpt",
      generation: 1,
      primaryKey: ["id"],
      emittedAt: "2026-11-04T00:00:00.000Z",
      sourceCollectedAt: "2026-11-04T00:00:00.000Z",
      envelopes: [
        {
          instance: "chat",
          stream: "messages",
          key: "A:a1",
          data: M("A", "a1", "missing-a0", true),
          emitted_at: "2026-11-04T00:00:00.000Z",
        },
        {
          instance: "chat",
          stream: "messages",
          key: "H:h0",
          data: M("H", "h0", "root", true),
          emitted_at: "2026-11-04T00:00:00.000Z",
        },
      ],
    });
    const read = await view.readLatest(SCOPE);
    expect(read).toMatchObject({
      kind: "refused",
      refusal: { status: "incomplete", reason: "canonical_view_incomplete" },
    });
    expect(read).not.toHaveProperty("envelope");
    const refusalListing = view.listingFor(SCOPE);
    expect(refusalListing.kind).not.toBe("file");

    f.store.replaceStream({
      instance: "chat",
      stream: "conversations",
      method: "chatgpt",
      generation: 1,
      primaryKey: ["id"],
      emittedAt: "2026-11-05T00:00:00.000Z",
      sourceCollectedAt: "2026-11-05T00:00:00.000Z",
      envelopes: [
        {
          instance: "chat",
          stream: "conversations",
          key: "H",
          data: C("H", "h0", 1),
          emitted_at: "2026-11-05T00:00:00.000Z",
        },
      ],
    });
    f.store.replaceStream({
      instance: "chat",
      stream: "messages",
      method: "chatgpt",
      generation: 1,
      primaryKey: ["id"],
      emittedAt: "2026-11-05T00:00:00.000Z",
      sourceCollectedAt: "2026-11-05T00:00:00.000Z",
      envelopes: [
        {
          instance: "chat",
          stream: "messages",
          key: "H:h0",
          data: M("H", "h0", "root", true),
          emitted_at: "2026-11-05T00:00:00.000Z",
        },
      ],
    });
    const recovered = await view.readLatest(SCOPE);
    expect(recovered.kind).toBe("canonical");
    if (recovered.kind !== "canonical")
      throw new Error("Expected recovered canonical body");
    expect(recovered.envelope.data).toEqual({
      conversations: [
        {
          id: "H",
          title: "H",
          create_time: T,
          update_time: T,
          message_count: 1,
          messages: [
            {
              id: "h0",
              role: "user",
              content: "h0",
              content_type: "text",
              create_time: T,
              model: null,
            },
          ],
          fetched_at: "2026-11-05T00:00:00.000Z",
        },
      ],
      total: 1,
    });
    const servedMessages = (
      recovered.envelope.data as {
        conversations: { messages: { id: string; content: string }[] }[];
      }
    ).conversations.flatMap((conversation) => conversation.messages);
    expect(servedMessages.some((message) => message.id === "a0")).toBe(false);
    expect(
      servedMessages.map((message) =>
        createHash("sha256").update(message.content).digest("hex"),
      ),
    ).not.toContain(deletedContentHash);
    const recoveryListing = view.listingFor(SCOPE);
    expect(recoveryListing.kind).not.toBe("file");
    expect(recoveryListing.kind).toBe("canonical");
    expect(view.listCanonicalScopes(undefined)).toContainEqual({
      scope: SCOPE,
      collectedAt: "2026-11-05T00:00:00.000Z",
    });
  });
});

describe("rooted current-walk regressions", () => {
  // A complete rooted current walk proves branch membership even when the count differs.
  it.each([
    { caseId: "R2a", withFlags: true },
    { caseId: "R2b", withFlags: false },
  ])(
    "$caseId — a rooted current path wins over a stale high count (flags=$withFlags)",
    async ({ withFlags }) => {
      const cs = [C("A", "a1", 3)];
      const ms = [
        M("A", "a0", null, false),
        M("A", "a1", "a0", false),
        ...(withFlags
          ? [
              M("A", "b0", null, true, "old0"),
              M("A", "b1", "b0", true, "old1"),
              M("A", "b2", "b1", true, "old2"),
            ]
          : []),
      ];
      const expectedDiagnostic = [
        {
          conversationIdHash: HASH_A,
          reason: "declared_count_above_walked" as const,
          declaredCount: 3,
          walkedCount: 2,
        },
      ];
      const p = project(records(cs, ms));
      expect(p.payload).toEqual(A2);
      expect(p.chatgptCoverageGaps ?? []).toEqual([]);
      expect(p.diagnostics ?? []).toEqual([]);
      assertDiagnostics(p.chatgptBranchDiagnostics, expectedDiagnostic);

      const f = createReadFixture(cs, ms);
      for (const view of [f.view, f.view, createLegacyScopeView(f.config)]) {
        const read = await view.readLatest(SCOPE);
        expect(read.kind).toBe("canonical");
        if (read.kind !== "canonical")
          throw new Error("Rooted current path refused");
        expect(read.envelope.data).toEqual(A2);
        for (const oldValue of ["b0", "b1", "b2", "old0", "old1", "old2"]) {
          expect(JSON.stringify(read.envelope.data)).not.toContain(oldValue);
        }
        assertGaps(read.chatgptCoverageGaps, []);
        assertDiagnostics(read.chatgptBranchDiagnostics, expectedDiagnostic);
      }
    },
  );

  // Only an explicit null parent identifies the root; other non-string parents
  // provide no root evidence.
  it.each([undefined, 0, false, {}])(
    "R2d — a non-string parent is not an explicit null root (%j)",
    (parent) => {
      const p = project(
        records(
          [C("A", "a1", 3)],
          [
            { ...M("A", "a0", null, false), parent_id: parent },
            M("A", "a1", "a0", false),
          ],
        ),
      );
      expect(p.payload).toEqual({ conversations: [], total: 0 });
      expect(p.chatgptBranchDiagnostics ?? []).toEqual([]);
      expect(p.diagnostics).toContainEqual({
        kind: "branch_walk_fallback",
        scope: SCOPE,
        stream: "conversations",
        count: 1,
        reasons: ["walked_count_below_declared"],
      });
      assertGaps(p.chatgptCoverageGaps, [
        {
          conversationIdHash: HASH_A,
          category: "branch_incomplete",
          declaredCount: 3,
          walkedCount: 2,
        },
      ]);
    },
  );

  // A cycle cannot prove a complete rooted walk. A coherent flagged chain
  // can provide recovery evidence.
  it("R2c — recovers a coherent flagged chain when current-node history cycles", async () => {
    const cs = [C("A", "cycle", 2)];
    const ms = [
      M("A", "cycle", "cycle", false),
      M("A", "a0", "synthetic-root", true),
      M("A", "a1", "a0", true),
    ];
    const p = project(records(cs, ms));
    expect(p.payload).toEqual(A2);
    expect(p.chatgptCoverageGaps ?? []).toEqual([]);
    expect(p.diagnostics).toContainEqual({
      kind: "branch_walk_fallback",
      scope: SCOPE,
      stream: "conversations",
      count: 1,
      reasons: ["cycle"],
    });
    const f = createReadFixture(cs, ms);
    const read = await readCanonical(f);
    expect(read.envelope.data).toEqual(A2);
    assertGaps(read.chatgptCoverageGaps, []);
  });
});

describe("Round 3 successful recovery diagnostics", () => {
  it.each(["missing-tip", "cycle"] as const)(
    "does not diagnose a recovered flag branch as a trusted current walk: %s",
    async (kind) => {
      const cs = [C("A", kind === "cycle" ? "cycle" : "absent-tip", 2)];
      const ms = [
        ...(kind === "cycle" ? [M("A", "cycle", "cycle", false)] : []),
        M("A", "a0", "synthetic-root", true),
        M("A", "a1", "a0", true),
      ];
      const p = project(records(cs, ms));
      expect(p.payload).toEqual(A2);
      expect(p.chatgptCoverageGaps ?? []).toEqual([]);
      assertDiagnostics(p.chatgptBranchDiagnostics, []);
      expect(p.diagnostics).toContainEqual({
        kind: "branch_walk_fallback",
        scope: SCOPE,
        stream: "conversations",
        count: 1,
        reasons: [kind === "cycle" ? "cycle" : "current_node_not_stored"],
      });
      const f = createReadFixture(cs, ms);
      const read = await readCanonical(f);
      expect(read.envelope.data).toEqual(A2);
      assertGaps(read.chatgptCoverageGaps, []);
      assertDiagnostics(read.chatgptBranchDiagnostics, []);
    },
  );
});
