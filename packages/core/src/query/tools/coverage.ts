import type {
  CoverageCounters,
  CoverageMethod,
  StoppedBecause,
} from "./types.js";

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
 */
export class CoverageLedger {
  readonly #granted: Set<string>;
  readonly #fullyScanned = new Set<string>();
  readonly #partiallyScanned = new Set<string>();
  readonly #skipped = new Map<string, string>();
  #records = 0;
  #bytes = 0;
  #method: CoverageMethod = "full";
  #stopped: StoppedBecause | undefined;
  #enforcementNotes: string[] = [];

  constructor(grantedScopes: readonly string[]) {
    this.#granted = new Set(grantedScopes);
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

  recordsRead(n: number): void {
    this.#records += n;
  }

  bytesRead(n: number): void {
    this.#bytes += n;
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
    const everyGrantedScopeAccountedFor =
      this.#granted.size > 0 &&
      [...this.#granted].every(
        (s) => this.#fullyScanned.has(s) || this.#skipped.has(s),
      );
    return {
      scopesScanned: scanned,
      recordsScanned: this.#records,
      bytesScanned: this.#bytes,
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
