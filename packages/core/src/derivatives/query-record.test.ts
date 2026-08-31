import { describe, expect, it } from "vitest";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";
import { computeDataPointId } from "../sync/data-point-id.js";
import { readStoredLineage } from "../lineage/lineage.js";
import { ingestDataContract } from "../contracts/data.js";
import { computeQuestion, type QuestionComputeDeps } from "./compute.js";
import { createFakeInferenceProvider } from "./inference.js";
import { createInMemoryQuestionStore } from "./store.js";
import type { QuestionRegistration } from "./types.js";
import type { QueryAnswer } from "../query/agent/types.js";
import {
  QueryRecordMappingError,
  buildQueryAnswerRecord,
  queryAnswerRecordKeys,
  type BuildQueryAnswerRecordInput,
  type QueryRecordSource,
} from "./query-record.js";

const OWNER = "0x1111111111111111111111111111111111111111" as const;

function answer(overrides: Partial<QueryAnswer> = {}): QueryAnswer {
  return {
    answer: "You averaged 7h12m of sleep.",
    citations: [{ scope: "oura.sleep", recordId: "r-9" }],
    coverage: {
      scopesScanned: ["oura.sleep"],
      recordsScanned: 31,
      bytesScanned: 4096,
      scopesSkipped: [],
      method: "full",
    },
    determinism: "generated",
    cost: {
      toolCalls: 2,
      modelTurns: 3,
      relayCalls: 4,
      inputTokens: 900,
      outputTokens: 120,
      usd: 0.0031,
    },
    script: "const rows = vana.read('oura.sleep');",
    value: 7.2,
    resolution: "trailing 31 days ending 2026-08-27",
    receiptIds: ["rcpt-a", "rcpt-b"],
    ...overrides,
  };
}

const HOST_SOURCES: QueryRecordSource[] = [
  { scope: "oura.sleep", version: "3", collectedAt: "2026-08-20T00:00:00Z" },
  {
    scope: "chatgpt.conversations",
    version: "1",
    collectedAt: "2026-08-19T00:00:00Z",
  },
];

function input(
  overrides: Partial<BuildQueryAnswerRecordInput> = {},
): BuildQueryAnswerRecordInput {
  return {
    registration: { questionId: "q-1", question: "How did I sleep?" },
    answer: answer(),
    sources: HOST_SOURCES,
    model: "fake-model",
    computedAt: "2026-08-27T12:00:00.000Z",
    serverOwner: OWNER,
    ...overrides,
  };
}

/* ------------------------------------------------------------------ *
 * The envelope
 * ------------------------------------------------------------------ */

describe("buildQueryAnswerRecord — the documented envelope", () => {
  it("maps a QueryAnswer onto the builder-documented record", () => {
    const { record, lineage } = buildQueryAnswerRecord(input());

    expect(record).toEqual({
      questionId: "q-1",
      question: "How did I sleep?",
      answer: "You averaged 7h12m of sleep.",
      evidence: null,
      model: "fake-model",
      computedAt: "2026-08-27T12:00:00.000Z",
      sources: [
        {
          scope: "oura.sleep",
          version: 3,
          collectedAt: "2026-08-20T00:00:00Z",
        },
      ],
      lineage: [computeDataPointId(OWNER, "oura.sleep")],
    });
    expect(lineage).toEqual({
      sources: [computeDataPointId(OWNER, "oura.sleep")],
      writtenAt: "2026-08-27T12:00:00.000Z",
    });
  });

  it("carries exactly the pinned key set — the coverage seam stays empty", () => {
    const { record } = buildQueryAnswerRecord(input());

    expect(Object.keys(record)).toEqual([...queryAnswerRecordKeys]);
    // Every `QueryAnswer` field with no documented slot is dropped, not
    // carried additively: each one would be a permanent public contract
    // committed by `dataHash`, and a key only this engine emits is exactly
    // the engine tell the record must not have.
    for (const key of [
      "coverage",
      "cost",
      "determinism",
      "value",
      "resolution",
      "script",
      "citations",
      "receiptIds",
      "inference",
    ]) {
      expect(record).not.toHaveProperty(key);
    }
  });

  it("leaks no host-authored coverage into the record at all", () => {
    const { record } = buildQueryAnswerRecord(input());
    const serialized = JSON.stringify(record);

    // Not merely "no coverage key": no coverage *figure* anywhere, and in
    // particular nothing behind the model-authored `evidence` key.
    for (const trace of [
      "recordsScanned",
      "bytesScanned",
      "scopesSkipped",
      "31",
      "4096",
    ]) {
      expect(serialized).not.toContain(trace);
    }
  });

  it("is key-for-key indistinguishable from a completion-path record", async () => {
    const completion = await completionPathRecord({ withReceipt: false });
    const { record } = buildQueryAnswerRecord(input());

    expect(Object.keys(record).sort()).toEqual(Object.keys(completion).sort());
  });

  it("omits `inference`, which the completion path also omits without a receipt", async () => {
    const withReceipt = await completionPathRecord({ withReceipt: true });
    const without = await completionPathRecord({ withReceipt: false });

    expect(withReceipt).toHaveProperty("inference");
    expect(without).not.toHaveProperty("inference");
    expect(buildQueryAnswerRecord(input()).record).not.toHaveProperty(
      "inference",
    );
  });
});

/* ------------------------------------------------------------------ *
 * `question` is the builder's stale-answer check
 * ------------------------------------------------------------------ */

describe("buildQueryAnswerRecord — `question` verbatim", () => {
  // A builder compares the record's `question` (trimmed) against the question
  // they registered and must not act on a mismatch. Anything this adapter
  // normalizes turns a good answer into an unusable one.
  const awkward =
    "  Wie war mein Schlaf letzte Woche? 🌙\n\tvs. der Woche davor​  ";

  it("copies the registered question byte for byte", () => {
    const { record } = buildQueryAnswerRecord(
      input({ registration: { questionId: "q-1", question: awkward } }),
    );

    expect(record.question).toBe(awkward);
    expect([...record.question]).toEqual([...awkward]);
    expect(record.question).not.toBe(awkward.trim());
    expect(record.question.normalize("NFC")).toBe(awkward.normalize("NFC"));
  });

  it("survives a JSON round trip through the persisted record", async () => {
    const stored = await persist(
      input({ registration: { questionId: "q-1", question: awkward } }),
    );

    expect((stored as { question: string }).question).toBe(awkward);
  });

  it("never reconstructs the question from the answer", () => {
    const { record } = buildQueryAnswerRecord(
      input({
        registration: { questionId: "q-7", question: "Registered question?" },
        answer: answer({ answer: "A different question was answered." }),
      }),
    );

    expect(record.question).toBe("Registered question?");
    expect(record.questionId).toBe("q-7");
  });
});

/* ------------------------------------------------------------------ *
 * `sources[]`
 * ------------------------------------------------------------------ */

describe("buildQueryAnswerRecord — sources[]", () => {
  it("takes which scopes from host coverage and the versions from host sources", () => {
    const { record } = buildQueryAnswerRecord(
      input({
        answer: answer({
          coverage: {
            scopesScanned: ["oura.sleep", "chatgpt.conversations"],
            recordsScanned: 5,
            scopesSkipped: [],
          },
        }),
      }),
    );

    expect(record.sources).toEqual([
      {
        scope: "chatgpt.conversations",
        version: 1,
        collectedAt: "2026-08-19T00:00:00Z",
      },
      { scope: "oura.sleep", version: 3, collectedAt: "2026-08-20T00:00:00Z" },
    ]);
  });

  it("sorts and de-duplicates, so the record is not a function of read order", () => {
    const forward = buildQueryAnswerRecord(
      input({
        answer: answer({
          coverage: {
            scopesScanned: ["oura.sleep", "chatgpt.conversations"],
            recordsScanned: 5,
            scopesSkipped: [],
          },
        }),
      }),
    );
    // The per-run coverage merge unions with a `Set`, so the arriving order is
    // read order. `dataHash` is a canonical-JSON commitment and JCS preserves
    // array order, so an unsorted `sources[]` would hash differently for the
    // same content.
    const reversed = buildQueryAnswerRecord(
      input({
        answer: answer({
          coverage: {
            scopesScanned: [
              "chatgpt.conversations",
              "oura.sleep",
              "oura.sleep",
            ],
            recordsScanned: 5,
            scopesSkipped: [],
          },
        }),
      }),
    );

    expect(reversed.record.sources).toEqual(forward.record.sources);
    expect(reversed.record.lineage).toEqual(forward.record.lineage);
  });

  it("excludes a granted scope the run never read", () => {
    const { record } = buildQueryAnswerRecord(input());

    expect(record.sources.map((s) => s.scope)).toEqual(["oura.sleep"]);
    expect(record.lineage).toEqual([computeDataPointId(OWNER, "oura.sleep")]);
  });

  it("refuses to let a model-authored citation manufacture provenance", () => {
    // Citations are parsed out of the model's own answer block and can name a
    // scope the host never read. `sources[]` is host provenance, so the
    // citation contributes nothing.
    const { record } = buildQueryAnswerRecord(
      input({
        answer: answer({
          citations: [
            { scope: "chatgpt.conversations" },
            { scope: "bank.transactions", recordId: "made-up" },
          ],
        }),
        sources: [
          ...HOST_SOURCES,
          {
            scope: "bank.transactions",
            version: "9",
            collectedAt: "2026-08-01T00:00:00Z",
          },
        ],
      }),
    );

    expect(record.sources.map((s) => s.scope)).toEqual(["oura.sleep"]);
    expect(JSON.stringify(record)).not.toContain("bank.transactions");
    expect(JSON.stringify(record)).not.toContain("made-up");
  });

  it("accepts a numeric version as well as the read client's string", () => {
    const { record } = buildQueryAnswerRecord(
      input({
        sources: [
          {
            scope: "oura.sleep",
            version: 12,
            collectedAt: "2026-08-20T00:00:00Z",
          },
        ],
      }),
    );

    expect(record.sources[0]).toEqual({
      scope: "oura.sleep",
      version: 12,
      collectedAt: "2026-08-20T00:00:00Z",
    });
  });

  it("fails closed when a scanned scope has no host source at all", () => {
    expect(() => buildQueryAnswerRecord(input({ sources: [] }))).toThrow(
      QueryRecordMappingError,
    );
  });

  it("fails closed rather than defaulting a missing version", () => {
    expect(() =>
      buildQueryAnswerRecord(
        input({
          sources: [
            { scope: "oura.sleep", collectedAt: "2026-08-20T00:00:00Z" },
          ],
        }),
      ),
    ).toThrow(/no version/);
  });

  it("fails closed rather than defaulting a missing collectedAt", () => {
    expect(() =>
      buildQueryAnswerRecord(
        input({ sources: [{ scope: "oura.sleep", version: "3" }] }),
      ),
    ).toThrow(/no collectedAt/);
  });

  it("fails closed on a version that is not an integer", () => {
    expect(() =>
      buildQueryAnswerRecord(
        input({
          sources: [
            {
              scope: "oura.sleep",
              version: "latest",
              collectedAt: "2026-08-20T00:00:00Z",
            },
          ],
        }),
      ),
    ).toThrow(/not an integer/);
  });
});

/* ------------------------------------------------------------------ *
 * `evidence`
 * ------------------------------------------------------------------ */

describe("buildQueryAnswerRecord — evidence", () => {
  it("is null, because the query layer has no model-authored evidence field", () => {
    const { record } = buildQueryAnswerRecord(input());

    expect(record.evidence).toBeNull();
  });

  it("is still null when the model authored a resolution", () => {
    // `resolution` is model-authored but answers a different question — which
    // set was aggregated over, not what supports the answer. Mapping it here
    // would redefine `evidence` for every reader of a mixed-engine scope.
    const { record } = buildQueryAnswerRecord(
      input({
        answer: answer({ resolution: "calendar month of August 2026" }),
      }),
    );

    expect(record.evidence).toBeNull();
    expect(JSON.stringify(record)).not.toContain("calendar month");
  });

  it("never fabricates evidence out of the citations or the script", () => {
    const { record } = buildQueryAnswerRecord(input());

    expect(record.evidence).toBeNull();
    expect(JSON.stringify(record)).not.toContain("r-9");
    expect(JSON.stringify(record)).not.toContain("vana.read");
  });

  it("matches a completion-path record whose model omitted evidence", async () => {
    const completion = await completionPathRecord({
      withReceipt: false,
      evidence: null,
    });

    expect(completion.evidence).toBeNull();
    expect(buildQueryAnswerRecord(input()).record.evidence).toBeNull();
  });
});

/* ------------------------------------------------------------------ *
 * `$lineage` is stamped, never hand-built
 * ------------------------------------------------------------------ */

describe("buildQueryAnswerRecord — $lineage", () => {
  it("does not put `$lineage` in the record", () => {
    const { record } = buildQueryAnswerRecord(input());

    expect(record).not.toHaveProperty("$lineage");
    expect(JSON.stringify(record)).not.toContain("$lineage");
  });

  it("is stamped by the ingest path from the returned lineage", async () => {
    const built = buildQueryAnswerRecord(input());
    const stored = await persist(input());

    expect(readStoredLineage(stored)).toEqual(built.lineage);
    expect(readStoredLineage(stored)).toEqual({
      sources: [computeDataPointId(OWNER, "oura.sleep")],
      writtenAt: "2026-08-27T12:00:00.000Z",
    });
  });

  it("rejects a hand-built `$lineage` in the body", async () => {
    const { record, lineage } = buildQueryAnswerRecord(input());
    const storage = createMemoryDataStorage();

    const result = await ingestDataContract({
      storage,
      scopeParam: "coach.weekly",
      body: { ...record, $lineage: lineage } as Record<string, unknown>,
      collectedAt: "2026-08-27T12:00:00Z",
      status: "stored",
      lineage,
    });

    expect(result).toMatchObject({
      ok: false,
      status: 400,
      body: { error: "INVALID_BODY" },
    });
  });
});

/* ------------------------------------------------------------------ *
 * Helpers
 * ------------------------------------------------------------------ */

/** Write the built record through the real ingest path and read it back. */
async function persist(
  built: BuildQueryAnswerRecordInput,
): Promise<Record<string, unknown>> {
  const { record, lineage } = buildQueryAnswerRecord(built);
  const storage = createMemoryDataStorage();
  const result = await ingestDataContract({
    storage,
    scopeParam: "coach.weekly",
    body: record,
    collectedAt: "2026-08-27T12:00:00Z",
    status: "stored",
    lineage,
  });
  if (!result.ok) throw new Error("ingest failed");
  const entry = storage.findEntry({ scope: "coach.weekly" });
  const envelope = await storage.readEnvelope(
    "coach.weekly",
    entry!.collectedAt,
  );
  return envelope.data as Record<string, unknown>;
}

/**
 * A genuine completion-path record, produced by running `computeQuestion`.
 *
 * The indistinguishability claim is only worth making against the real thing:
 * a hand-copied literal would drift the moment `compute.ts` changed.
 */
async function completionPathRecord(options: {
  withReceipt: boolean;
  evidence?: string | null;
}): Promise<Record<string, unknown>> {
  const registration: QuestionRegistration = {
    questionId: "q-1",
    derivedScope: "coach.weekly",
    sourceScopes: ["oura.sleep"],
    question: "How did I sleep?",
    model: null,
    recompute: "on-change",
    registeredBy: { kind: "owner" },
    status: "pending",
    error: null,
    createdAt: "2026-08-27T00:00:00.000Z",
    updatedAt: "2026-08-27T00:00:00.000Z",
    lastComputedAt: null,
    derivedVersion: null,
    derivedCollectedAt: null,
  };
  const storage = createMemoryDataStorage();
  const seeded = await ingestDataContract({
    storage,
    scopeParam: "oura.sleep",
    body: { nights: [{ date: "2026-08-19", score: 80 }] },
    collectedAt: "2026-08-20T00:00:00Z",
    status: "stored",
  });
  if (!seeded.ok) throw new Error("seed failed");

  const evidence =
    options.evidence === undefined ? "fake evidence" : options.evidence;
  const deps: QuestionComputeDeps = {
    storage,
    store: createInMemoryQuestionStore({ initial: [registration] }),
    provider: createFakeInferenceProvider({
      respond: () => ({
        content: JSON.stringify({
          answer: "fake answer",
          ...(evidence === null ? {} : { evidence }),
        }),
        ...(options.withReceipt ? { receiptId: "fake-receipt" } : {}),
      }),
    }),
    serverOwner: OWNER,
    now: () => new Date("2026-08-27T12:00:00.000Z"),
    retryDelaysMs: [0, 0],
  };

  const outcome = await computeQuestion("q-1", deps);
  if (outcome.status !== "ready") {
    throw new Error(`compute failed: ${JSON.stringify(outcome)}`);
  }
  const entry = storage.findEntry({ scope: "coach.weekly" });
  const envelope = await storage.readEnvelope(
    "coach.weekly",
    entry!.collectedAt,
  );
  const data = { ...(envelope.data as Record<string, unknown>) };
  // The server-stamped mirror is not part of the caller-side record shape.
  delete data.$lineage;
  return data;
}
