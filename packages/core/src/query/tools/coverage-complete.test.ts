import { describe, expect, it } from "vitest";

import { CoverageLedger } from "./coverage.js";

/**
 * `coverage.complete` had been false in 132 consecutive live runs, and the
 * standing conclusion was that its derivation could not fire on a multi-scope
 * grant — a flag that is always false being noise rather than a safety
 * property.
 *
 * Replaying every script from the 54-run `dogfood` benchmark through this
 * ledger says otherwise: it fires on 10 of 51, multi-scope grants included,
 * and each of the 40 it refuses is a run that genuinely never read a granted
 * scope. The derivation is therefore kept, and these are the cases that stop
 * it being loosened later on the strength of the same wrong inference.
 *
 * The two reasons the flag nevertheless read as always-false at the request
 * level are outside this file — the eval harness over-granted, and the
 * request-level merge ANDed each run's flag — and both are now fixed, in
 * `scripts/query-eval-harness.ts` and `server/query/sandbox-tool-host.ts`
 * respectively. The per-run derivation asserted here is what makes the merge's
 * disjunction sound, so these cases are load-bearing for that fix too:
 * `coverage-merge.test.ts` relies on one `complete: true` run meaning the
 * whole grant was streamed.
 */
const tally = (records: number) => ({
  records,
  bytes: records * 100,
  unreadable: 0,
});

describe("coverage.complete fires", () => {
  it("on a single-scope grant read end to end", () => {
    const ledger = new CoverageLedger(["bank.transactions"]);
    ledger.fullPass("bank.transactions", tally(900));
    ledger.completeScope("bank.transactions");
    expect(ledger.snapshot().complete).toBe(true);
  });

  it("on a multi-scope grant with every scope read end to end", () => {
    // The shape the standing conclusion said could never be true. Q18's live
    // runs are exactly this: `nutrition.log` and `oura.workout`, both streamed.
    const scopes = ["nutrition.log", "oura.workout"];
    const ledger = new CoverageLedger(scopes);
    for (const s of scopes) {
      ledger.fullPass(s, tally(400));
      ledger.completeScope(s);
    }
    expect(ledger.snapshot().complete).toBe(true);
  });

  it("after a scope is re-read, since a second full pass covers no less", () => {
    // Reading a scope twice — once to count, once to filter — is ordinary
    // code, and must not be mistaken for partial coverage.
    const ledger = new CoverageLedger(["oura.sleep"]);
    ledger.fullPass("oura.sleep", tally(1276));
    ledger.completeScope("oura.sleep");
    ledger.fullPass("oura.sleep", tally(1276));
    ledger.completeScope("oura.sleep");
    const snap = ledger.snapshot();
    expect(snap.complete).toBe(true);
    expect(snap.recordsScanned).toBe(1276);
  });

  it("when a bounded read is later superseded by a full pass", () => {
    const ledger = new CoverageLedger(["email.messages"]);
    ledger.partialPass("email.messages", tally(50));
    ledger.partialScope("email.messages");
    expect(ledger.snapshot().complete).toBe(false);
    ledger.fullPass("email.messages", tally(2600));
    ledger.completeScope("email.messages");
    expect(ledger.snapshot().complete).toBe(true);
  });
});

describe("coverage.complete stays false", () => {
  it("when a granted scope was never touched", () => {
    // Q8's live run: `documents.files` streamed, `email.messages` never read,
    // and the question is whether anything conflicts with a contract. The
    // absence claim is not founded and the flag must say so.
    const ledger = new CoverageLedger(["documents.files", "email.messages"]);
    ledger.fullPass("documents.files", tally(340));
    ledger.completeScope("documents.files");
    expect(ledger.snapshot().complete).toBe(false);
  });

  it("when a granted scope was only read within bounds", () => {
    const ledger = new CoverageLedger(["oura.sleep", "oura.heartrate"]);
    ledger.fullPass("oura.sleep", tally(1276));
    ledger.completeScope("oura.sleep");
    ledger.partialPass("oura.heartrate", tally(200));
    ledger.partialScope("oura.heartrate");
    expect(ledger.snapshot().complete).toBe(false);
  });

  it("when a scope was skipped, however good the reason", () => {
    const ledger = new CoverageLedger(["documents.files", "email.messages"]);
    for (const s of ["documents.files", "email.messages"]) {
      ledger.fullPass(s, tally(340));
      ledger.completeScope(s);
    }
    ledger.skip("email.messages", "no text layer");
    expect(ledger.snapshot().complete).toBe(false);
  });

  it("when the answer rests on a ranked prefilter rather than a pass", () => {
    // Prompt §5 gap 2: Q9/Q15 must say "the earliest found", not "the
    // earliest", and a complete flag would contradict that in metadata.
    const ledger = new CoverageLedger(["notes.entries"]);
    ledger.fullPass("notes.entries", tally(2200));
    ledger.completeScope("notes.entries");
    ledger.prefiltered();
    expect(ledger.snapshot().complete).toBe(false);
  });

  it("when the run stopped early, even after every scope was read", () => {
    const ledger = new CoverageLedger(["bank.transactions"]);
    ledger.fullPass("bank.transactions", tally(1800));
    ledger.completeScope("bank.transactions");
    ledger.stop("budget");
    expect(ledger.snapshot().complete).toBe(false);
  });

  it("when nothing was granted at all", () => {
    // Q12 is granted no scopes. "Complete" over an empty grant would be a
    // vacuous truth attached to an answer that read nothing.
    expect(new CoverageLedger([]).snapshot().complete).toBe(false);
  });
});
