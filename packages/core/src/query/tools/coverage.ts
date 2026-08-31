import type {
  CoverageCounters,
  CoverageMethod,
  StoppedBecause,
} from "./types.js";

/** Records, bytes and unreadable records attributed to one scope. */
export interface Tally {
  records: number;
  bytes: number;
  unreadable: number;
}

interface ScopeTally {
  /** Largest complete pass seen. A full pass covers the whole scope. */
  full: Tally | undefined;
  /** Sum of bounded reads. */
  partial: Tally;
  /** Scope size when the host knows it independently; a ceiling only. */
  knownSize: number | undefined;
}

const emptyTally = (): Tally => ({ records: 0, bytes: 0, unreadable: 0 });

const addTally = (a: Tally, b: Tally): Tally => ({
  records: a.records + b.records,
  bytes: a.bytes + b.bytes,
  unreadable: a.unreadable + b.unreadable,
});

const maxTally = (a: Tally, b: Tally): Tally => ({
  records: Math.max(a.records, b.records),
  bytes: Math.max(a.bytes, b.bytes),
  unreadable: Math.max(a.unreadable, b.unreadable),
});

/**
 * What one scope contributes, given everything read from it.
 *
 * A complete pass **subsumes** any bounded read of the same scope: you cannot
 * cover more than all of it, so the full-pass tally wins outright rather than
 * being added to. Without a full pass, bounded reads sum — two disjoint
 * windows really do cover more than one — but the total is capped at the
 * scope's known size so overlapping windows cannot over-claim.
 *
 * The rule is deliberately asymmetric: it may *under*-report coverage (two
 * disjoint windows over a scope of unknown size are counted honestly, but a
 * re-read of one window is not distinguished from a new one), and it may never
 * *over*-report it. Under-reporting weakens an absence answer; over-reporting
 * falsifies one.
 */
export function effectiveFor(t: ScopeTally): Tally {
  if (t.full) return t.full;
  if (t.knownSize === undefined) return t.partial;
  return {
    records: Math.min(t.partial.records, t.knownSize),
    bytes: t.partial.bytes,
    unreadable: Math.min(t.partial.unreadable, t.knownSize),
  };
}

/**
 * Merge two runs' `scopesPartiallyScanned` at the request level.
 *
 * **A scope is partially scanned for the request only if NO run exhausted it.**
 * The argument: `scopesPartiallyScanned` answers "could this scope have been
 * sampled rather than covered", and once any single run has streamed the scope
 * end to end, the request as a whole has seen every record in it. A bounded
 * read in some other turn — a script that windows first and then does a full
 * pass, which is ordinary code — adds no doubt about what was covered. This is
 * exactly the rule {@link CoverageLedger.completeScope} already applies within
 * one run, lifted unchanged to the request; having the two disagree would mean
 * a two-turn request reporting a scope as sampled that a one-turn request with
 * the same reads reported as covered.
 *
 * It is the *safe* direction as well as the honest one, because the direction
 * that could launder a sample is the other one: reporting a scope as fully
 * scanned when neither run exhausted it. That cannot happen here — a scope
 * leaves this list only on the strength of a run that actually reached
 * `completeScope`, which only a host loader run to exhaustion does.
 *
 * The old `complete` merge got a decision of exactly this shape backwards, so
 * `coverage-merge.test.ts` / `lite-tool-host.merge.test.ts` pin this one in
 * both directions.
 *
 * Shared rather than reimplemented per runtime: the Node and browser hosts
 * already carry parallel copies of the per-scope total merge, and a second
 * divergent copy of THIS rule is the one that would be dangerous.
 */
export function mergePartiallyScanned(
  prev: Pick<CoverageCounters, "scopesScanned" | "scopesPartiallyScanned">,
  next: Pick<CoverageCounters, "scopesScanned" | "scopesPartiallyScanned">,
): string[] {
  /**
   * Fail closed on a side that declares no list, in the direction that cannot
   * launder a sample.
   *
   * The field is required on {@link CoverageCounters}, and `decodeResultFrame`
   * checks only that `coverage` is an object, so this guards a violated type
   * contract the way `mergeScopeTotals` guards `perScope` — but the direction
   * is the whole point. Reading absence as "nothing was partial" would let a
   * frame that omits the field promote every scope it named to fully scanned,
   * which is the sampling claim this list exists to refuse. Reading it as
   * "everything it read might be partial" can only over-report doubt.
   */
  const partialOf = (
    side: Pick<CoverageCounters, "scopesScanned" | "scopesPartiallyScanned">,
  ): readonly string[] => side.scopesPartiallyScanned ?? side.scopesScanned;

  const exhausted = new Set<string>();
  for (const side of [prev, next]) {
    const partial = new Set(partialOf(side));
    for (const scope of side.scopesScanned) {
      if (!partial.has(scope)) exhausted.add(scope);
    }
  }
  return [...new Set([...partialOf(prev), ...partialOf(next)])]
    .filter((scope) => !exhausted.has(scope))
    .sort();
}

/**
 * Host-authored coverage counters (prompt contract §1).
 *
 * **The model may never assert coverage.** This ledger is incremented by the
 * runtime as reads happen, and the script has no reference to it: the
 * interpreter's realm never binds it, and the only values a script can send
 * outward are those it passes to `vana.result`, which carries no coverage
 * field. A script that scans 30 of 300 records cannot claim it scanned 300,
 * because it does not author the field.
 *
 * ## There is no summary `complete` flag, deliberately
 *
 * There was one, derived here: true only when every granted scope had been
 * streamed end to end or explicitly skipped, nothing was partial, nothing was
 * prefiltered, and nothing stopped the run. It was removed because it measured
 * the shape of the GRANT rather than the quality of the answer: on the owner
 * HTTP path the grant defaults to the whole data store
 * (`routes/query.ts`, `MAX_OWNER_SCOPES = 500`), so the flag was false on
 * nearly every real answer and `agent/loop.ts` appended "this answer is
 * incomplete" to all of them — which trains a reader to ignore the one caveat
 * that matters.
 *
 * It was NOT, as an earlier version of this comment said, structurally
 * incapable of firing. Every all-false tally behind that claim (43/43, and the
 * 78- and 132-run sweeps) predates `00acde9` "fix(query): ask each question
 * under its own grant" (2026-08-29), which fixed two harness bugs. Recorded
 * artifacts after it show `complete` firing 48/54, 45/54 and 35/54, and design
 * §19.16 carries those numbers. The removal stands on the grant-shape argument
 * above; it never stood on "it can never be true".
 *
 * Do not reintroduce a scalar summary (a ratio, a score, a flag) over the
 * counters without a consumer that can act on it differently from the parts.
 * The counters are shipped as they are and a consumer judges: `scopesScanned`
 * against the scopes it granted, `scopesPartiallyScanned`, `recordsScanned`,
 * `scopesSkipped`, `unreadable`, `method` and `stoppedBecause` each say
 * something specific and each is separately actionable.
 *
 * ## The anti-sampling half of it survives, as a list
 *
 * `complete`'s load-bearing conjunct was `#partiallyScanned.size === 0`: a
 * bounded read falsified it, so the model could not buy a completeness claim
 * by sampling. That was measured at 0 false completeness across 80 runs
 * (design §19.16) and is separately valuable from the flag it rode on —
 * but once `snapshot()` folded the partial and the fully-scanned sets into one
 * `scopesScanned` list, nothing in the shipped surface distinguished a scope
 * streamed end to end from one sampled through a window.
 *
 * So the parts are shipped: `scopesPartiallyScanned` names exactly the scopes
 * in `scopesScanned` that were read but not exhausted. A list, per the rule
 * above — not a scalar over the parts, and not `complete` under a new name: it
 * says nothing about scopes the question never needed, which is the failure
 * that removed the flag.
 */
export class CoverageLedger {
  readonly #fullyScanned = new Set<string>();
  readonly #partiallyScanned = new Set<string>();
  readonly #skipped = new Map<string, string>();
  readonly #perScope = new Map<string, ScopeTally>();
  #method: CoverageMethod = "full";
  #stopped: StoppedBecause | undefined;
  #enforcementNotes: string[] = [];

  #tally(scope: string): ScopeTally {
    let t = this.#perScope.get(scope);
    if (!t) {
      t = { partial: emptyTally(), full: undefined, knownSize: undefined };
      this.#perScope.set(scope, t);
    }
    return t;
  }

  /**
   * The size of a scope, when the host knows it independently of any read.
   *
   * Used only as a ceiling: it can cap an over-count from overlapping partial
   * reads, and it never raises a count. A wrong `itemCount` therefore cannot
   * inflate a denominator, only fail to trim one.
   */
  declareSize(scope: string, itemCount: number | undefined): void {
    if (typeof itemCount === "number" && Number.isFinite(itemCount)) {
      this.#tally(scope).knownSize = itemCount;
    }
  }

  /** A scope was streamed end to end. */
  completeScope(scope: string): void {
    this.#fullyScanned.add(scope);
    this.#partiallyScanned.delete(scope);
  }

  /** A scope was read but not exhaustively (a bounded read, or a prefilter). */
  partialScope(scope: string): void {
    if (!this.#fullyScanned.has(scope)) this.#partiallyScanned.add(scope);
  }

  /**
   * A complete pass over a scope: every record was streamed.
   *
   * Recorded as a *maximum*, not a sum. A script that reads a scope twice —
   * once to count, once to filter, which is ordinary code — covered the same
   * records both times. Summing produced the live Q8 failure where a
   * 340-document scope reported 680 scanned and 44 unreadable against 22
   * planted, and an inflated denominator makes an absence claim look better
   * founded than it is (design §4.3 point 1).
   */
  fullPass(scope: string, tally: Tally): void {
    const t = this.#tally(scope);
    t.full = t.full ? maxTally(t.full, tally) : tally;
  }

  /**
   * A bounded read covering part of a scope.
   *
   * Summed, because two windows at different cursors genuinely cover more
   * than one — but capped at the scope's true size in {@link effectiveFor},
   * so overlapping windows cannot push the count past what exists.
   */
  partialPass(scope: string, tally: Tally): void {
    const t = this.#tally(scope);
    t.partial = addTally(t.partial, tally);
  }

  skip(scope: string, reason: string): void {
    this.#skipped.set(scope, reason);
  }

  /**
   * Mark the run as having relied on a prefilter rather than a full pass.
   * Prompt §5 gap 2: Q9/Q15 must then say the date is the earliest *found*,
   * not the earliest that exists.
   */
  prefiltered(): void {
    this.#method = "prefiltered";
  }

  stop(reason: StoppedBecause): void {
    this.#stopped ??= reason;
  }

  /** Verbatim from `SandboxEnforcement.notes`; never summarised away. */
  noteEnforcement(notes: readonly string[]): void {
    this.#enforcementNotes = [...this.#enforcementNotes, ...notes];
  }

  snapshot(): CoverageCounters {
    const scanned = [...this.#fullyScanned, ...this.#partiallyScanned].sort();
    // Totals are derived per scope and then summed, never accumulated as
    // reads happen: that is what stops a re-read from counting twice.
    const perScope: Record<string, Tally> = {};
    let totals = emptyTally();
    for (const [scope, tally] of this.#perScope) {
      const effective = effectiveFor(tally);
      perScope[scope] = effective;
      totals = addTally(totals, effective);
    }
    return {
      scopesScanned: scanned,
      // Sorted, like `scopesScanned`, so the list is a function of which
      // scopes were sampled and not of the order the script touched them.
      // `completeScope` removes from this set, so a scope read both ways
      // reports as fully scanned — the ledger's rule, and the one the
      // cross-run merges lift to the request level.
      scopesPartiallyScanned: [...this.#partiallyScanned].sort(),
      recordsScanned: totals.records,
      bytesScanned: totals.bytes,
      unreadable: totals.unreadable,
      perScope,
      scopesSkipped: [...this.#skipped].map(([scope, reason]) => ({
        scope,
        reason,
      })),
      method: this.#method,
      ...(this.#stopped ? { stoppedBecause: this.#stopped } : {}),
      enforcementNotes: [...this.#enforcementNotes],
    };
  }
}
