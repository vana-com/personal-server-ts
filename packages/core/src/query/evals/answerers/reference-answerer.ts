/**
 * An answerer that computes every gradeable case correctly, by construction.
 *
 * It is not a query layer — it has the case list and calls the reference path
 * directly. Its job is to prove the harness itself is sound: if the reference
 * answerer does not score 100% on the non-judged cases, the bug is in the
 * grader or the fixture, not in the agent under test. It is also the control
 * arm for phase 2's determinism measurement, which needs a known-zero-variance
 * baseline to measure against.
 */

import type { FixtureSource } from "../fixtures/sink.js";
import {
  absenceReference,
  anomalyReference,
  conditionalReference,
  identityReference,
  needleReference,
  recurringReference,
  sleepTrap,
  tripReference,
} from "../reference/compute.js";
import { Q1_WINDOW_DAYS } from "../cases.js";
import type {
  EvalAnswerer,
  EvalQueryAnswer,
  EvalQueryRequest,
} from "../types.js";

const NO_COST = { toolCalls: 0, inputTokens: 0, outputTokens: 0, usd: 0 };

export function createReferenceAnswerer(source: FixtureSource): EvalAnswerer {
  const answer = async (
    request: EvalQueryRequest,
  ): Promise<EvalQueryAnswer> => {
    const q = request.question.toLowerCase();
    const base = {
      citations: request.grantedScopes.map((scope) => ({ scope })),
      determinism: "replayed" as const,
      cost: NO_COST,
    };

    if (q.includes("sleep on average")) {
      const trap = await sleepTrap(source, Q1_WINDOW_DAYS);
      return {
        ...base,
        value: Number(trap.correctHours.toFixed(4)),
        answer:
          `${trap.correctHours.toFixed(2)} hours per night on average, over ${trap.nights} of ` +
          `${trap.windowDays} nights with data. Main sleep periods only — naps excluded, ` +
          `\`rest\` and \`deleted\` periods dropped, rows with a null total_sleep_duration ` +
          `omitted rather than counted as zero. Total sleep time, not time in bed.`,
        coverage: {
          scopesScanned: ["oura.sleep"],
          recordsScanned: trap.naiveRows,
          scopesSkipped: [],
          complete: true,
        },
      };
    }

    if (q.includes("thai restaurant")) {
      const needle = await needleReference(source);
      return {
        ...base,
        answer: `${needle.answer}, recommended by Sarah Johnson (as "${needle.speakerAlias}") on ${needle.date}.`,
        coverage: {
          scopesScanned: request.grantedScopes,
          recordsScanned: needle.occurrences,
          scopesSkipped: [],
          complete: true,
          method: "full",
        },
      };
    }

    if (q.includes("distinct people")) {
      const identity = await identityReference(source);
      return {
        ...base,
        value: identity.distinctPeople,
        answer:
          `${identity.distinctPeople} distinct people across ${identity.rowsScanned} records ` +
          `(${identity.distinctAliases} raw handles before alias resolution).`,
        coverage: {
          scopesScanned: request.grantedScopes,
          recordsScanned: identity.rowsScanned,
          scopesSkipped: [],
          complete: true,
        },
      };
    }

    if (q.includes("recurring monthly expenses")) {
      const recurring = await recurringReference(source);
      return {
        ...base,
        answer:
          `Recurring: ${recurring.recurringMerchants.join(", ")}. ` +
          `Crept up: ${recurring.crept.map((c) => `${c.merchant} ${c.from}→${c.to}`).join(", ") || "none"}. ` +
          `Across ${recurring.transactions} transactions.`,
        coverage: {
          scopesScanned: ["bank.transactions"],
          recordsScanned: recurring.transactions,
          scopesSkipped: [],
          complete: true,
        },
      };
    }

    if (q.includes("conflicts with this contract")) {
      const absence = await absenceReference(source);
      return {
        ...base,
        answer:
          `No conflicting agreement found across ${absence.readable} readable documents. ` +
          `${absence.unreadable} scanned documents could not be text-extracted and were not searched, ` +
          `so this is not a complete answer. ${absence.nearMisses} documents mention exclusivity or ` +
          `non-compete terms but none is a binding agreement (draft, declined, or expired).`,
        citations: [],
        coverage: {
          scopesScanned: request.grantedScopes,
          recordsScanned: absence.readable,
          scopesSkipped: [],
          complete: false,
          unreadable: absence.unreadable,
          method: "full",
        },
      };
    }

    if (q.includes("resting heart rate")) {
      const anomaly = await anomalyReference(source);
      return {
        ...base,
        value: Number(anomaly.lastWeekBpm.toFixed(4)),
        answer:
          `Yes. Last week averaged ${anomaly.lastWeekBpm.toFixed(1)} bpm against a ` +
          `${anomaly.baselineBpm.toFixed(1)} bpm baseline over the rest of the history ` +
          `(${anomaly.zScore.toFixed(2)} standard deviations, sd ${anomaly.baselineStdDev.toFixed(2)}).`,
        coverage: {
          scopesScanned: request.grantedScopes,
          recordsScanned: 0,
          scopesSkipped: [],
          complete: true,
        },
      };
    }

    if (q.includes("japan trip")) {
      const trip = await tripReference(source);
      return {
        ...base,
        value: Number(trip.totalUsd.toFixed(2)),
        answer:
          `The Japan trip resolves to ${trip.startDay}–${trip.endDay} from the calendar. ` +
          `$${trip.totalUsd.toFixed(2)} total: $${trip.inWindowOnlyUsd.toFixed(2)} spent in-country ` +
          `across ${trip.jpyTransactions} JPY transactions, plus the $${trip.flightUsd.toFixed(2)} ` +
          `flight charged before departure.`,
        coverage: {
          scopesScanned: request.grantedScopes,
          recordsScanned: trip.jpyTransactions,
          scopesSkipped: [],
          complete: true,
        },
      };
    }

    if (q.includes("summarize everything i know about")) {
      return {
        ...base,
        answer:
          "Sarah Johnson appears as sarahj, sarah@work.com and Sarah 🌸 across Slack, email and " +
          "calendar. Distinct from Sarah Nguyen, whose records are excluded.",
        coverage: {
          scopesScanned: request.grantedScopes,
          recordsScanned: 0,
          scopesSkipped: [],
          complete: true,
        },
      };
    }

    if (q.includes("calories")) {
      const conditional = await conditionalReference(source);
      return {
        ...base,
        value: Number(conditional.meanCaloriesOnRunDays.toFixed(2)),
        answer:
          `${conditional.meanCaloriesOnRunDays.toFixed(0)} kcal on average across ` +
          `${conditional.matchedDays} days with a run over 10km (distance > 10000 metres) and a ` +
          `matching daily record (${conditional.unmatchedDays} run days had no matching record and ` +
          `are excluded). Workout rows were deduped from ${conditional.workoutRows} to ` +
          `${conditional.dedupedSessions} sessions across manual and autodetected sources. ` +
          `Other days average ${conditional.meanCaloriesOtherDays.toFixed(0)} kcal.`,
        coverage: {
          scopesScanned: request.grantedScopes,
          recordsScanned: conditional.matchedDays + conditional.unmatchedDays,
          scopesSkipped: [],
          complete: true,
        },
      };
    }

    // Judged cases fall through: the harness skips them without a judge, and a
    // fabricated answer here would make a skip look like a pass.
    return {
      ...base,
      answer:
        "Not answered by the reference answerer; this case requires a judge.",
      coverage: {
        scopesScanned: request.grantedScopes,
        recordsScanned: 0,
        scopesSkipped: [],
        complete: false,
      },
    };
  };

  return { name: "reference", answer };
}
