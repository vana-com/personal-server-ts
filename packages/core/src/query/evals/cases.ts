/**
 * The 18 questions of design §3, as graded cases.
 *
 * Expected values are computed by `reference/compute.ts` against the serialized
 * corpus, not asserted as literals here — a literal would go stale the moment
 * the generator changed, and would test nothing about whether the corpus
 * actually contains what the case claims.
 */

import type { FixtureSource } from "./fixtures/sink.js";
import { SCOPES } from "./fixtures/generate.js";
import {
  Q5_RESTAURANT,
  Q5_SPEAKER_ALIAS,
  Q8_CONFLICT_MARKER,
} from "./fixtures/planted.js";
import {
  absenceReference,
  anomalyReference,
  branchTrap,
  conditionalReference,
  identityReference,
  localDateDrift,
  needleReference,
  recurringReference,
  sleepTrap,
  tripReference,
} from "./reference/compute.js";
import {
  arcReference,
  focusWeekReference,
  intentionReference,
  morningPersonReference,
  nutritionReference,
  personBriefReference,
} from "./reference/semantic.js";
import type { QueryEvalCase } from "./types.js";

/** Q1 asks about "the last month"; 31 calendar days is the window the eval grades. */
export const Q1_WINDOW_DAYS = 31;

export async function buildCases(
  source: FixtureSource,
): Promise<QueryEvalCase[]> {
  const sleepWindow = await sleepTrap(source, Q1_WINDOW_DAYS);
  const sleepAll = await sleepTrap(source, null);
  const branches = await branchTrap(source);
  const needle = await needleReference(source);
  const identity = await identityReference(source);
  const recurring = await recurringReference(source);
  const absence = await absenceReference(source);
  const anomaly = await anomalyReference(source);
  const trip = await tripReference(source);
  const conditional = await conditionalReference(source);
  const drift = await localDateDrift(source);

  /*
   * Semantic ground truth. Every one of these returns zeroes on a corpus
   * generated without `semanticProse`, so the enrichment below is conditional:
   * on `small`/`full`/`lite` the seven semantic cases keep exactly the rubrics
   * they had, and on `dogfood` they gain checkable anchors.
   *
   * That asymmetry is deliberate. A rubric with no ground truth behind it can
   * only be graded on whether the answer *sounds* right, which is the failure
   * this whole eval exists to avoid.
   */
  const arcs = await arcReference(source);
  const focus = await focusWeekReference(source);
  const intentions = await intentionReference(source);
  const morning = await morningPersonReference(source);
  const person = await personBriefReference(source);
  const nutrition = await nutritionReference(source);
  const hasSemantics = arcs.some((a) => a.mentions > 0);
  const hasNutrition = nutrition.daysLogged > 0;

  const jobArc = arcs.find((a) => a.arcId === "job-departure");
  const investingArc = arcs.find((a) => a.arcId === "investing-views");
  const abandoned = intentions.filter(
    (i) => !i.followedThrough && i.statedMentions > 0,
  );
  const kept = intentions.filter(
    (i) => i.followedThrough && i.evidenceEvents > 0,
  );

  /** Merges reference facts into a case only when the corpus actually has them. */
  const withFacts = (
    base: QueryEvalCase,
    facts: Record<string, number | string> | undefined,
  ): QueryEvalCase =>
    facts
      ? { ...base, referenceFacts: { ...base.referenceFacts, ...facts } }
      : base;

  const cases: QueryEvalCase[] = [
    {
      id: "Q1",
      question: "How much did I sleep on average over the last month?",
      class: "aggregation",
      scopes: [SCOPES.ouraSleep],
      expect: {
        kind: "numeric",
        value: Number(sleepWindow.correctHours.toFixed(4)),
        tolerance: 0.05,
        denominator: sleepWindow.nights,
      },
      mustCite: true,
      mustReportCoverage: true,
      referenceFacts: {
        naiveHoursIncludingNaps: Number(sleepWindow.naiveHours.toFixed(4)),
        errorPctIfNapsIncluded: Number(sleepWindow.errorPct.toFixed(2)),
        hoursIfOnlyNapsExcluded: Number(
          sleepWindow.excludingNapsOnlyHours.toFixed(4),
        ),
        errorPctIfOnlyNapsExcluded: Number(
          sleepWindow.excludingNapsOnlyErrorPct.toFixed(2),
        ),
        hoursIfNullDurationTreatedAsZero: Number(
          sleepWindow.nullAsZeroHours.toFixed(4),
        ),
        nightsWithData: sleepWindow.nights,
        rowsExcludedAsRestOrDeleted: sleepWindow.excludedRows,
        nullDurationRows: sleepWindow.nullDurationRows,
        windowDays: sleepWindow.windowDays,
        sleepDayDriftRows: drift.mismatched,
        // The whole-corpus figures are the stable regression numbers; the
        // 31-day window is what the question asks for and is noisier.
        fullCorpusCorrectHours: Number(sleepAll.correctHours.toFixed(4)),
        fullCorpusNaiveHours: Number(sleepAll.naiveHours.toFixed(4)),
        fullCorpusErrorPct: Number(sleepAll.errorPct.toFixed(2)),
      },
      notes:
        "Three distinct silent failures: including naps (design §18.2); filtering `type !== 'late_nap'`, " +
        "which looks careful but sweeps in `rest` and `deleted` periods; and coercing a null " +
        "`total_sleep_duration` to zero. Also: `day` is authoritative — re-deriving the date from " +
        `\`bedtime_start\` misdates ${drift.mismatched} rows across the timezone change.`,
    },
    {
      id: "Q2",
      question: "What was my main focus this week?",
      class: "synthesis",
      scopes: [SCOPES.slack, SCOPES.email, SCOPES.calendar, SCOPES.chatgpt],
      expect: {
        kind: "judged",
        rubric:
          "Covers all four granted scopes rather than the loudest one; states the weighting it used (message volume, calendar hours, or similar); cites specific artifacts. Fails if Slack volume alone drives the answer.",
      },
      mustCite: true,
      mustReportCoverage: true,
      requiresJudge: true,
    },
    {
      id: "Q3",
      question: "What is my financial risk appetite?",
      class: "inference",
      scopes: [SCOPES.bank, SCOPES.chatgpt],
      expect: {
        kind: "judged",
        rubric:
          "Decomposes into computable sub-quantities (spend volatility, discretionary share, cadence) and computes each rather than asserting a trait; states calibrated uncertainty and names what data is missing (no brokerage or income data in this corpus).",
      },
      mustCite: true,
      mustReportCoverage: true,
      requiresJudge: true,
      notes:
        "Multi-turn by construction. Design §17.1's DABStep decomposition risk lands here.",
    },
    {
      id: "Q4",
      question: "Did my sleep affect my productivity last quarter?",
      class: "relational",
      scopes: [SCOPES.ouraSleep, SCOPES.calendar, SCOPES.slack],
      expect: {
        kind: "judged",
        rubric:
          "States an explicit productivity proxy and join key, reports a real statistic with n and spread, and does not state correlation as causation.",
      },
      mustCite: true,
      mustReportCoverage: true,
      requiresJudge: true,
    },
    {
      id: "Q5",
      question: "What was the name of that Thai restaurant Sarah recommended?",
      class: "exhaustive",
      scopes: [SCOPES.slack, SCOPES.email, SCOPES.chatgpt],
      expect: {
        kind: "set",
        contains: [Q5_RESTAURANT],
        // The decoys: the other Sarah's recommendation, and a colleague's.
        excludes: ["Golden Orchid Kitchen", "Silver Elephant Noodle House"],
      },
      mustCite: true,
      mustReportCoverage: true,
      referenceFacts: {
        occurrencesInCorpus: needle.occurrences,
        speakerAlias: needle.speakerAlias,
        date: needle.date,
        daysBeforeCorpusEnd: needle.daysBeforeEnd,
      },
      notes: `Single occurrence, spoken by "${Q5_SPEAKER_ALIAS}" not "Sarah Johnson", ${needle.daysBeforeEnd} days before the corpus ends. Recency truncation misses it; matching "Sarah" without resolution hits the wrong person.`,
    },
    {
      id: "Q6",
      question:
        "How many distinct people did I talk to last month, and who were the top 10?",
      class: "relational",
      scopes: [SCOPES.slack, SCOPES.email, SCOPES.calendar],
      /*
       * No `denominator`, deliberately, and this is the one case where its
       * absence is the finding.
       *
       * It used to require `identity.rowsScanned` verbatim in the prose, and
       * that failed every arm — including the run that returned the right
       * number. Three reasons, measured on `dogfood`:
       *
       *  1. It is not a denominator. Q6 answers with a *count of people*;
       *     nothing is divided, so there is no n behind a ratio to state.
       *     `expect.denominator` exists for design §4.3's "6.5h over 28 of 31
       *     nights" — Q1's nights, Q18's matched days. `rowsScanned` is a
       *     coverage figure, and coverage is already asserted by
       *     `mustReportCoverage`.
       *  2. The answer is window-invariant and the figure is not.
       *     `distinctPeople` is 6 over a 28-, 30-, 31- and 60-day window;
       *     `rowsScanned` is 256, 260, 274 and 566, and 297 over calendar
       *     December. So the assertion smuggles design §19.9's window
       *     ambiguity back into the one question `readings.ts` deliberately
       *     refuses to call ambiguous.
       *  3. It is convention-dependent even at a fixed window: the same 31
       *     days are 274 rows counting a calendar event once, and more
       *     counting its 31 attendee references or an email's from and to
       *     separately. Every one of those is an honest count.
       *
       * It only ever held because the reference answerer prints the literal
       * string the case handed it. The 6-vs-5 disagreement over whether the
       * owner is one of the six is a separate, live failure and is left
       * failing.
       */
      expect: {
        kind: "numeric",
        value: identity.distinctPeople,
        tolerance: 0,
      },
      mustCite: true,
      mustReportCoverage: true,
      referenceFacts: {
        distinctRawAliases: identity.distinctAliases,
        rowsScanned: identity.rowsScanned,
      },
      notes:
        "Counting raw handles gives distinctRawAliases; the answer is distinctPeople after alias resolution.",
    },
    {
      id: "Q7",
      question:
        "What are my recurring monthly expenses, and which ones have crept up?",
      class: "aggregation",
      scopes: [SCOPES.bank],
      expect: {
        kind: "set",
        contains: [...recurring.recurringMerchants],
      },
      mustCite: true,
      mustReportCoverage: true,
      referenceFacts: {
        creptMerchants: recurring.crept.map((c) => c.merchant).join(", "),
        transactions: recurring.transactions,
      },
      notes: "Cadence must be detected over the full history, not a window.",
    },
    {
      id: "Q8",
      question:
        "Have I ever agreed to anything that conflicts with this contract?",
      class: "exhaustive",
      scopes: [SCOPES.documents, SCOPES.email],
      expect: { kind: "absence", mustReportCoverage: true },
      mustCite: false,
      mustReportCoverage: true,
      expectedCoverage: {
        recordsScanned: absence.readable,
        unreadable: absence.unreadable,
      },
      referenceFacts: {
        documents: absence.documents,
        readable: absence.readable,
        unreadable: absence.unreadable,
        conflictMarkerOccurrences: absence.conflictMarkerOccurrences,
        nearMissDocuments: absence.nearMisses,
      },
      notes: `No conflicting agreement exists ("${Q8_CONFLICT_MARKER}" occurs ${absence.conflictMarkerOccurrences} times). A bare "no" fails: ${absence.unreadable} documents have no text layer and must be reported.`,
    },
    {
      id: "Q9",
      question: "When did I first start thinking about leaving my job?",
      class: "synthesis",
      scopes: [SCOPES.chatgpt, SCOPES.notes, SCOPES.slack],
      expect: {
        kind: "judged",
        rubric:
          "Orders candidate matches by time rather than relevance score, returns the earliest, and states that it is the earliest *found* rather than the earliest that exists whenever coverage.method is prefiltered.",
      },
      mustCite: true,
      mustReportCoverage: true,
      requiresJudge: true,
      referenceFacts: {
        conversations: branches.conversations,
        correctMessages: branches.correctMessages,
        messagesIfMappingFlattened: branches.naiveMessages,
        phantomPct: Number(branches.phantomPct.toFixed(2)),
      },
      notes:
        "Only meaningful because the corpus now spans 1100 days; the previous generator compressed " +
        "conversations into ~11 days, which made this vacuous. Depends on correct message " +
        "reconstruction twice over: flattening `mapping` invents phantom messages, and a null " +
        "`create_time` coerced to 0 dates a message to 1970 and becomes a false 'first'.",
    },
    {
      id: "Q10",
      question: "What changed in how I think about X over the last two years?",
      class: "synthesis",
      scopes: [SCOPES.chatgpt, SCOPES.notes],
      expect: {
        kind: "judged",
        rubric:
          "Samples from both ends of the period with stated per-period coverage and contrasts them; a summary weighted to recent material fails.",
      },
      mustCite: true,
      mustReportCoverage: true,
      requiresJudge: true,
      notes: "Same date-spread dependency as Q9.",
    },
    {
      id: "Q11",
      question: "Was my resting heart rate unusual last week?",
      class: "aggregation",
      scopes: [SCOPES.ouraSleep, SCOPES.ouraHeartRate],
      expect: {
        kind: "numeric",
        value: Number(anomaly.lastWeekBpm.toFixed(4)),
        tolerance: 0.5,
      },
      mustCite: true,
      mustReportCoverage: true,
      referenceFacts: {
        baselineBpm: Number(anomaly.baselineBpm.toFixed(4)),
        deltaBpm: Number(anomaly.deltaBpm.toFixed(4)),
        baselineStdDev: Number(anomaly.baselineStdDev.toFixed(4)),
        zScore: Number(anomaly.zScore.toFixed(4)),
        restingSamplesLastWeek: anomaly.lastWeekSamples,
        restingSamplesBaseline: anomaly.baselineSamples,
        lastWeekIfSourceIgnored: Number(
          anomaly.unfilteredLastWeekBpm.toFixed(4),
        ),
        baselineIfSourceIgnored: Number(
          anomaly.unfilteredBaselineBpm.toFixed(4),
        ),
        lastWeekFromSleepRows: Number(anomaly.sleepRowLastWeekBpm.toFixed(4)),
        baselineFromSleepRows: Number(anomaly.sleepRowBaselineBpm.toFixed(4)),
      },
      notes:
        "A real excursion is planted in the final week; the baseline needs the full history, not the " +
        "window under test. The graded figure is the resting series itself — `oura_heartrate` rows " +
        "with `source` in rest/sleep — so the contamination filter is load-bearing rather than " +
        "decorative: ignoring `source` returns " +
        `${anomaly.unfilteredLastWeekBpm.toFixed(1)} against ${anomaly.lastWeekBpm.toFixed(1)}, ` +
        "because workout and session samples sit ~45bpm higher. Answering from " +
        `\`oura_sleep.average_heart_rate\` instead returns ${anomaly.sleepRowLastWeekBpm.toFixed(1)} — ` +
        "mean heart rate *during sleep*, which is not a resting series; that route is what this case " +
        "used to grade, and it is why the case passed without ever reading `oura.heartrate`.",
    },
    {
      id: "Q12",
      question:
        "Which of my data has app X seen, and what could it infer from it?",
      class: "introspection",
      scopes: [],
      expect: {
        kind: "judged",
        rubric:
          "Answered from grant records and access logs only, never from content; refused when the caller is the app being asked about.",
      },
      mustCite: true,
      mustReportCoverage: true,
      requiresJudge: true,
      notes:
        "Not gradeable against the fixture corpus: it reads the server's own grant/access ledger, which the fixture does not model. Needs `vana.introspect()` (prompt doc §3) and a grant-ledger fixture. Reported as a gap.",
    },
    {
      id: "Q13",
      question: "Plan my week around my energy levels.",
      class: "synthesis",
      scopes: [SCOPES.ouraSleep, SCOPES.ouraReadiness, SCOPES.calendar],
      expect: {
        kind: "judged",
        rubric:
          "Separates measured history from projection explicitly, and notes calendar freshness. Output is a plan, so only the separation is graded.",
      },
      mustCite: true,
      mustReportCoverage: true,
      requiresJudge: true,
      notes:
        "The corpus has no future calendar data, so the forward half is unexercised. Partial by construction.",
    },
    {
      id: "Q14",
      question: "How much did I spend on my Japan trip?",
      class: "aggregation",
      scopes: [SCOPES.bank, SCOPES.calendar],
      expect: {
        kind: "numeric",
        value: Number(trip.totalUsd.toFixed(2)),
        tolerance: 1,
      },
      mustCite: true,
      mustReportCoverage: true,
      referenceFacts: {
        resolvedStart: trip.startDay,
        resolvedEnd: trip.endDay,
        inWindowOnlyUsd: Number(trip.inWindowOnlyUsd.toFixed(2)),
        preTripFlightUsd: Number(trip.flightUsd.toFixed(2)),
        jpyTransactions: trip.jpyTransactions,
      },
      notes:
        "The flight is charged 61 days before departure. A date-window filter alone returns inWindowOnlyUsd and is wrong.",
    },
    {
      id: "Q15",
      question: "What do I keep saying I'll do but never do?",
      class: "exhaustive",
      scopes: [SCOPES.notes, SCOPES.chatgpt, SCOPES.calendar],
      expect: {
        kind: "judged",
        rubric:
          "Extracts intent statements, then runs a completeness-guaranteed follow-through check per intent; must report coverage.stoppedBecause when the budget is exhausted rather than silently truncating.",
      },
      mustCite: true,
      mustReportCoverage: true,
      requiresJudge: true,
      notes:
        "Unbounded by construction; the graded property is honest budget exhaustion.",
    },
    {
      id: "Q16",
      question: "Am I a morning person?",
      class: "inference",
      scopes: [SCOPES.ouraSleep, SCOPES.slack, SCOPES.chatgpt],
      expect: {
        kind: "judged",
        rubric:
          "Reports the behavioural aggregate (activity timing from the diurnal distribution) and any stated self-description separately, and surfaces disagreement rather than picking one.",
      },
      mustCite: true,
      mustReportCoverage: true,
      requiresJudge: true,
      notes:
        "The corpus has a genuine diurnal signal now: Slack is work-hours weighted, ChatGPT and notes are evening weighted.",
    },
    {
      id: "Q17",
      question:
        "Summarize everything I know about Sarah Johnson before my meeting with them.",
      class: "relational",
      scopes: [SCOPES.slack, SCOPES.email, SCOPES.calendar],
      expect: {
        kind: "set",
        contains: ["sarahj", "sarah@work.com"],
        excludes: ["snguyen"],
      },
      mustCite: true,
      mustReportCoverage: true,
      referenceFacts: {
        aliasesToResolve: "Sarah Johnson, sarahj, sarah@work.com, Sarah 🌸",
        confusableWith: "Sarah Nguyen (snguyen, sarah.nguyen@partner.io)",
      },
      notes:
        "Graded on alias resolution: the gather must include Sarah Johnson's handles and exclude the other Sarah's.",
    },
    {
      id: "Q18",
      question:
        "How many calories do I typically eat on days I run more than 10km?",
      class: "relational",
      scopes: [SCOPES.ouraActivity, SCOPES.ouraWorkout],
      expect: {
        kind: "numeric",
        value: Number(conditional.meanCaloriesOnRunDays.toFixed(2)),
        tolerance: 5,
        denominator: conditional.matchedDays,
      },
      mustCite: true,
      mustReportCoverage: true,
      referenceFacts: {
        matchedDays: conditional.matchedDays,
        unmatchedDays: conditional.unmatchedDays,
        meanCaloriesOtherDays: Number(
          conditional.meanCaloriesOtherDays.toFixed(2),
        ),
        workoutRowsBeforeDedup: conditional.workoutRows,
        dedupedSessions: conditional.dedupedSessions,
        runDaysIfDistanceReadAsKm: conditional.runDaysIfDistanceReadAsKm,
      },
      notes:
        "Two verified traps: `workout.distance` is in metres, so the filter is `> 10000` — reading it " +
        `as km qualifies ${conditional.runDaysIfDistanceReadAsKm} days instead of ${conditional.matchedDays + conditional.unmatchedDays}; ` +
        "and `workout.source` is both `manual` and `autodetected`, so sessions must be deduped before " +
        "the join. Caveat: the corpus has no nutrition log, so `total_calories` stands in for intake — " +
        "a proxy the design does not specify, and one to revisit when a nutrition source exists.",
    },
  ];

  if (!hasSemantics && !hasNutrition) return cases;

  /*
   * Enrichment for the `dogfood` profile.
   *
   * These cases were structurally present and semantically vacuous: the rubrics
   * described what a good answer looks like, but nothing in the corpus made one
   * answer better than another. The facts below are what a grader compares
   * against.
   */
  const byId = new Map(cases.map((c) => [c.id, c]));
  const patch = (id: string, fn: (c: QueryEvalCase) => QueryEvalCase): void => {
    const existing = byId.get(id);
    if (existing) byId.set(id, fn(existing));
  };

  if (hasSemantics) {
    patch("Q2", (c) =>
      withFacts(
        {
          ...c,
          expect: {
            kind: "judged",
            rubric:
              `Identifies "${focus.realTopic}" as the week's focus and does NOT answer "${focus.loudTopic}". ` +
              "States the weighting used, and justifies it with calendar hours, notes or commits rather than " +
              "message volume — Slack volume points at the wrong answer by design.",
          },
          notes:
            `Trap armed: in the final week Slack carries ${focus.loudSlackMessages} messages about ` +
            `"${focus.loudAnchor}" against ${focus.realSlackMessages} about "${focus.realAnchor}" ` +
            `(${focus.loudToRealSlackRatio.toFixed(1)}x), while calendar (${focus.realCalendarEvents}), ` +
            `notes (${focus.realNotes}) and commits (${focus.realCommits}) all point the other way. ` +
            "A volume-weighted answer is wrong; this is design §3 Q2's stated failure mode, made measurable.",
        },
        {
          realTopic: focus.realTopic,
          realAnchor: focus.realAnchor,
          loudTopic: focus.loudTopic,
          loudAnchor: focus.loudAnchor,
          loudSlackMessages: focus.loudSlackMessages,
          realSlackMessages: focus.realSlackMessages,
          realCalendarEvents: focus.realCalendarEvents,
          realCommits: focus.realCommits,
          windowFrom: focus.from,
          windowTo: focus.to,
        },
      ),
    );

    if (investingArc?.firstMentionDate) {
      patch("Q3", (c) =>
        withFacts(c, {
          statedPositionEarly: investingArc.earlyPosition,
          statedPositionLate: investingArc.latePosition,
          statedMentionsFirstHalf: investingArc.mentionsFirstHalf,
          statedMentionsSecondHalf: investingArc.mentionsSecondHalf,
          note: "Stated risk appetite reverses across the window, so an answer that averages the two halves is wrong in a way the corpus can prove.",
        }),
      );
    }

    if (jobArc?.firstMentionDate) {
      patch("Q9", (c) =>
        withFacts(
          {
            ...c,
            expect: {
              kind: "judged",
              rubric:
                `Returns ${jobArc.firstMentionDate} (or the surrounding days) as the earliest indication, found in ` +
                `${jobArc.firstMentionSource}, and recognises the oblique framing — the first mention is a question ` +
                "about tenure, not a statement about leaving. Orders by time rather than relevance, and says the date " +
                "is the earliest *found* whenever coverage.method is prefiltered.",
            },
            notes:
              `The arc runs ${jobArc.mentions} mentions across four stages; the earliest carries no keyword a search ` +
              `for "quit" or "resign" would catch, which is design §3 Q9's stated difficulty. An answer citing the ` +
              "explicit later stage has found a real mention and still got the question wrong.",
          },
          {
            firstMentionDate: jobArc.firstMentionDate ?? "unknown",
            firstMentionSource: jobArc.firstMentionSource ?? "unknown",
            firstMentionStage: jobArc.firstMentionStage ?? "unknown",
            totalMentions: jobArc.mentions,
            earlyFraming: jobArc.earlyPosition,
          },
        ),
      );
    }

    if (investingArc?.firstMentionDate) {
      patch("Q10", (c) =>
        withFacts(
          {
            ...c,
            question: `What changed in how I think about ${investingArc.subject} over the last two years?`,
            expect: {
              kind: "judged",
              rubric:
                `Contrasts the early position (${investingArc.earlyPosition}) against the late one ` +
                `(${investingArc.latePosition}) and samples both halves with stated per-period coverage. ` +
                "A summary weighted to recent material, or one that reports only the late position, fails.",
            },
            notes:
              `${investingArc.mentionsFirstHalf} mentions in the first half against ` +
              `${investingArc.mentionsSecondHalf} in the second, so both ends are genuinely sampleable. ` +
              "The view reverses rather than drifts, which is what makes the contrast checkable.",
          },
          {
            subject: investingArc.subject,
            earlyPosition: investingArc.earlyPosition,
            latePosition: investingArc.latePosition,
            mentionsFirstHalf: investingArc.mentionsFirstHalf,
            mentionsSecondHalf: investingArc.mentionsSecondHalf,
          },
        ),
      );
    }

    if (abandoned.length > 0) {
      patch("Q15", (c) =>
        withFacts(
          {
            ...c,
            expect: {
              kind: "judged",
              rubric:
                `Names the abandoned intentions (${abandoned.map((i) => i.anchor).join(", ")}) and does not ` +
                `list the ones that were followed through (${kept.map((i) => i.anchor).join(", ")}). ` +
                "Reports coverage.stoppedBecause when the budget is exhausted rather than silently truncating.",
            },
            notes:
              `${abandoned.length} intentions stated repeatedly with zero follow-through evidence, against ` +
              `${kept.length} with calendar evidence. Listing a kept intention as abandoned is the more damaging ` +
              "error — the user would believe something about themselves that is not true.",
          },
          {
            abandoned: abandoned.map((i) => i.anchor).join(", "),
            kept: kept.map((i) => i.anchor).join(", "),
            abandonedCount: abandoned.length,
            keptCount: kept.length,
          },
        ),
      );
    }

    if (morning.conflict) {
      patch("Q16", (c) =>
        withFacts(
          {
            ...c,
            scopes: [...c.scopes, SCOPES.commits],
            expect: {
              kind: "judged",
              rubric:
                "Reports BOTH sides and names the disagreement: the user states repeatedly that they are not a " +
                `morning person, while ${(morning.shareBefore9 * 100).toFixed(0)}% of commits land before 09:00 ` +
                `local (median hour ${morning.medianCommitHour}). Picking one side without acknowledging the other fails, ` +
                "however well argued.",
            },
            notes:
              `${morning.statedClaims} stated claims against ${morning.commits} commits. The measured side must be ` +
              "read in LOCAL time — the corpus is at -08:00, so taking the UTC hour reports this user as a night " +
              "owl and inverts the answer.",
          },
          {
            statedClaims: morning.statedClaims,
            commits: morning.commits,
            commitsBefore9Local: morning.commitsBefore9,
            shareBefore9Local: Number(morning.shareBefore9.toFixed(3)),
            medianCommitHourLocal: morning.medianCommitHour,
            conflict: "stated and measured disagree",
          },
        ),
      );
    }

    if (person.factAnchors.length > 0) {
      patch("Q17", (c) =>
        withFacts(
          {
            ...c,
            expect: {
              kind: "set",
              contains: [...person.aliases.slice(0, 3), ...person.factAnchors],
              excludes: [
                "snguyen",
                "sarah.nguyen@partner.io",
                ...person.confusableFactAnchors,
              ],
            },
            notes:
              `Now graded on substance as well as alias resolution: ${person.factAnchors.length} distinct facts ` +
              `about Sarah Johnson (${person.factMentions} mentions), and the other Sarah has her own ` +
              `(${person.confusableFactAnchors.join(", ")}). A briefing containing those is visibly about the ` +
              "wrong person rather than merely thin.",
          },
          {
            factAnchors: person.factAnchors.join(", "),
            factMentions: person.factMentions,
            confusableFactAnchors: person.confusableFactAnchors.join(", "),
          },
        ),
      );
    }
  }

  if (hasNutrition) {
    patch("Q18", (c) =>
      withFacts(
        {
          ...c,
          scopes: [SCOPES.nutrition, SCOPES.ouraWorkout],
          expect: {
            kind: "numeric",
            value: Number(nutrition.meanKcalOnRunDays.toFixed(2)),
            tolerance: 5,
            denominator: nutrition.matchedDays,
          },
          notes:
            "Now answered against a real intake source. `oura_activity.total_calories` is energy " +
            `*expenditure* and returns ${nutrition.meanActivityCaloriesOnRunDays.toFixed(0)} kcal against an ` +
            `actual intake of ${nutrition.meanKcalOnRunDays.toFixed(0)} — a different question with a similar name. ` +
            `Logging is partial by design: ${nutrition.runDaysWithoutLog} qualifying run days have no nutrition ` +
            `record at all, so the honest answer states n=${nutrition.matchedDays}, not the number of run days. ` +
            "The metre/kilometre and manual/autodetected traps still apply to the join.",
        },
        {
          meanKcalOnRunDays: Number(nutrition.meanKcalOnRunDays.toFixed(2)),
          meanKcalOtherDays: Number(nutrition.meanKcalOtherDays.toFixed(2)),
          meanKcalCompleteDaysOnly: Number(
            nutrition.meanKcalOnRunDaysCompleteOnly.toFixed(2),
          ),
          expenditureProxyValue: Number(
            nutrition.meanActivityCaloriesOnRunDays.toFixed(2),
          ),
          matchedDays: nutrition.matchedDays,
          runDaysWithoutLog: nutrition.runDaysWithoutLog,
          daysLogged: nutrition.daysLogged,
          daysComplete: nutrition.daysComplete,
        },
      ),
    );
  }

  return cases.map((c) => byId.get(c.id) ?? c);
}
