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
 * `complete` is deliberately *derived*, never settable: true only when every
 * granted scope was streamed end to end and nothing stopped the run early.
 *
 * ## Why the derivation is unchanged despite 132 false runs
 *
 * It was reported as too strict to fire on a multi-scope grant, and therefore
 * as noise. Measured instead of assumed, that is wrong, and the flag stays as
 * it is. Every script from the 54-run `dogfood` N=3 benchmark was replayed
 * through this ledger offline, with no model calls:
 *
 * | conjunct                        | runs it made `complete` false |
 * | ------------------------------- | ----------------------------- |
 * | some granted scope never read   | 40 / 51                       |
 * | the run stopped (`error`)       | 30 / 51                       |
 * | a bounded read (`partialScope`) | 0 / 51                        |
 * | a scope skipped                 | 0 / 51                        |
 * | `method === "prefiltered"`      | 0 / 51                        |
 *
 * **`complete` was true on 10 of those 51 runs**, including on two- and
 * three-scope grants — so the derivation is satisfiable, and loosening it
 * would destroy the signal it currently carries. The 40 are honest: Q8's run
 * never read `email.messages` before answering an absence question over it,
 * and Q11's never read `oura.heartrate` before answering about heart rate.
 * Those are exactly the reads whose absence should falsify a coverage claim.
 *
 * The flag reads as always-false at the request level for two reasons outside
 * this file, both recorded in the phase report: the eval harness grants the
 * tool host all 18 corpus scopes rather than the case's two or three, so
 * `everyGrantedScopeAccountedFor` is unsatisfiable there; and the request-level
 * merge ANDs each run's flag, so one exploratory turn that reads nothing
 * poisons a request that later reads everything. Neither is a defect in this
 * derivation.
 */
export class CoverageLedger {
  readonly #granted: Set<string>;
  readonly #fullyScanned = new Set<string>();
  readonly #partiallyScanned = new Set<string>();
  readonly #skipped = new Map<string, string>();
  readonly #perScope = new Map<string, ScopeTally>();
  #method: CoverageMethod = "full";
  #stopped: StoppedBecause | undefined;
  #enforcementNotes: string[] = [];

  constructor(grantedScopes: readonly string[]) {
    this.#granted = new Set(grantedScopes);
  }

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
    const everyGrantedScopeAccountedFor =
      this.#granted.size > 0 &&
      [...this.#granted].every(
        (s) => this.#fullyScanned.has(s) || this.#skipped.has(s),
      );
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
      complete:
        everyGrantedScopeAccountedFor &&
        this.#skipped.size === 0 &&
        this.#partiallyScanned.size === 0 &&
        this.#method === "full" &&
        this.#stopped === undefined,
      method: this.#method,
      ...(this.#stopped ? { stoppedBecause: this.#stopped } : {}),
      enforcementNotes: [...this.#enforcementNotes],
    };
  }
}
