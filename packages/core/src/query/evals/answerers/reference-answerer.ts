/**
 * An answerer that computes every gradeable case correctly, by construction.
 *
 * It is not a query layer — it has the case list and calls the reference path
 * directly. Its job is to prove the harness itself is sound: if the reference
 * answerer does not score 100% on the non-judged cases, the bug is in the
 * grader or the fixture, not in the agent under test. It is also the control
 * arm for phase 2's determinism measurement, which needs a known-zero-variance
 * baseline to measure against.
 *
 * The three ambiguous cases (Q1, Q14, Q18) declare a `resolution`, because the
 * dual-rule runner grades them against the set the answer NAMES and an
 * undeclared set is a failure however right the number is. Each string states
 * the set the reference function beside it actually computes — read off the
 * computation, not off `readings.ts`. If one ever stops describing what the
 * reference does, the honest fix is to correct the string, never to pick the
 * label that makes the case pass.
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
import {
  nutritionReference,
  personBriefReference,
} from "../reference/semantic.js";
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
        // `sleepTrap(source, 31)` cuts at `lastDay - 30 days` and keeps
        // `day >= cutoff`, so the set really is the trailing 31 days ending on
        // the last day with data, inclusive.
        resolution:
          "the trailing 31 days ending on the last day with sleep data, that " +
          "last day included; main sleep periods only",
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
        // `tripReference` returns `inWindow + flight`, where `inWindow` sums
        // EVERY currency inside the calendar window (JPY at that date's rate)
        // and `flight` is the Delta charge that falls outside it.
        resolution:
          "every transaction dated inside the Japan trip window, all " +
          "currencies converted at each transaction's own rate, plus the " +
          "Delta flight booked before departure",
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
      // On a corpus with planted person facts the brief has to carry them, or
      // it is an alias list rather than a briefing. Degrades to the alias-only
      // answer when the corpus has no facts to report.
      const person = await personBriefReference(source);
      const facts = person.factAnchors.length
        ? ` Known facts: ${person.factAnchors.join(", ")}.`
        : "";
      return {
        ...base,
        answer:
          "Sarah Johnson appears as sarahj, sarah@work.com and Sarah 🌸 across Slack, email and " +
          "calendar. Distinct from Sarah Nguyen, whose records are excluded." +
          facts,
        coverage: {
          scopesScanned: request.grantedScopes,
          recordsScanned: person.factMentions,
          scopesSkipped: [],
          complete: true,
        },
      };
    }

    if (q.includes("calories")) {
      /*
       * Prefer the real intake source when the corpus has one.
       *
       * `oura_activity.total_calories` is energy *expenditure*; answering an
       * intake question from it is a different question with a similar name,
       * and on this corpus the two differ by ~350 kcal. The fallback keeps
       * older profiles answerable on the proxy they were built against.
       */
      const nutrition = await nutritionReference(source);
      if (nutrition.daysLogged > 0) {
        return {
          ...base,
          value: Number(nutrition.meanKcalOnRunDays.toFixed(2)),
          // `meanKcalOnRunDays` averages every qualifying run day that has a
          // log, whatever its `complete` flag says — the stricter
          // complete-logs-only figure is computed too, but it is not what
          // `value` carries.
          resolution:
            "all logged run days: every day with a deduped run over 10km " +
            "that also has a nutrition log",
          answer:
            `${nutrition.meanKcalOnRunDays.toFixed(0)} kcal on average across ` +
            `${nutrition.matchedDays} days with a run over 10km (distance > 10000 metres) and a ` +
            `nutrition record. ${nutrition.runDaysWithoutLog} qualifying run days had no log at ` +
            `all and are excluded, so n=${nutrition.matchedDays}. Restricting to days logged in ` +
            `full gives ${nutrition.meanKcalOnRunDaysCompleteOnly.toFixed(0)} kcal. Other logged ` +
            `days average ${nutrition.meanKcalOtherDays.toFixed(0)} kcal. Note the activity ` +
            `scope's ${nutrition.meanActivityCaloriesOnRunDays.toFixed(0)} kcal is expenditure, ` +
            `not intake.`,
          coverage: {
            scopesScanned: request.grantedScopes,
            recordsScanned: nutrition.matchedDays + nutrition.runDaysWithoutLog,
            scopesSkipped: [],
            complete: true,
          },
        };
      }

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
