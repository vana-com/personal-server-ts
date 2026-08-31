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
 * prefiltered, and nothing stopped the run. It was removed because that
 * conjunction is not a property real requests can satisfy. A grant is issued
 * per *consent*, not per question, so a 12-scope grant is ordinary while the
 * question in front of it legitimately needs two scopes; the other ten are
 * then never read and the flag is false. It measured the shape of the grant,
 * not the quality of the answer, and it was false on all 43 measured runs.
 *
 * A flag that is always false is not a safety property, it is noise, and worse
 * than noise here: `agent/loop.ts` appended "this answer is incomplete" to
 * *every* answer on the strength of it, which trains a reader to ignore the
 * one caveat that matters.
 *
 * What replaces it is nothing — by decision. The counters below are shipped as
 * they are and a consumer judges: `scopesScanned` against the scopes it
 * granted, `recordsScanned`, `scopesSkipped`, `unreadable`, `method` and
 * `stoppedBecause` each say something specific and each is separately
 * actionable. Do not reintroduce a scalar summary (a ratio, a score, a flag)
 * over them without a consumer that can act on it differently from the parts.
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
