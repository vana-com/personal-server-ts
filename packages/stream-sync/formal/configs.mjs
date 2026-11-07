// The one source of every TLC config in cfg/. `node formal/check.mjs --write`
// regenerates cfg/*.cfg from this table; `node formal/check.mjs` fails when
// they differ; `node formal/check.mjs --run NAME...` runs TLC and checks the
// result against `expect`.
//
// A config is a bound profile plus the guards it turns off. `expect` is
// "pass", or the one property that must be violated. A control that fails
// some other way (parse error, another property, an unfinished run) does not
// count as failing as required.

const set = (xs) => `{${xs.join(", ")}}`;

/**
 * The design (revision 4.1 with the three-outcome base rule and Q9, and
 * run intake v2 as reduced by the owner's decisions): every guard on.
 */
export const DESIGN = {
  GenInNames: "TRUE",
  ClearOnGenChange: "TRUE",
  ExclusiveHeads: "TRUE",
  OneConnectionRead: "TRUE",
  SeedOnlyGen1: "TRUE",
  CheckpointAfterAll: "TRUE",
  ReReadAfterCtl: "TRUE",
  NoRebind: "TRUE",
  NeedListing: "TRUE",
  LegacyHonoursDelete: "TRUE",
  OneWay: "TRUE",
  NeedsFull: "TRUE",
  ImportPastPending: "TRUE",
  SeedWhateverBase: "TRUE",
  AckImmutable: "TRUE",
  ReadinessSame: "TRUE",
  StaleGenStops: "TRUE",
  NoOpNeedsFull: "TRUE",
  NullBasePublishes: "TRUE",
  NeedsFullForcesFull: "TRUE",
  PublishCoveredOnly: "TRUE",
  WriterIssuesStart: "TRUE",
  // F2's fix, adopted: retry_pending keeps no cursor of a stream with
  // spooled records (traces/retry-spooled-cursor.txt).
  RetryQuietOnly: "TRUE",
  FullMerges: "TRUE",
  // Proposed fix, not in the ruled contract, so FALSE here: a checkpoint
  // that only retry_pending ends saved keeps the next run full
  // (traces/retry-token-incremental.txt).  The Fix-* rows turn it on.
  RetryCkptStaysFull: "FALSE",
};

/**
 * Bound profiles. Devices, Readers, Acct, PK and Streams are TLC model
 * values. d1 is the Desktop. The counters bound each kind of event.
 */
const base = {
  Devices: set(["d1", "d2"]),
  Desktop: "d1",
  // No reader PS: reads are checked on every reachable current registry
  // state, which covers every snapshot a reader can hold (README.md).
  Readers: "{}",
  Acct: set(["A", "B"]),
  PK: set(["x1", "x2"]),
  Streams: set(["s1", "s2", "s3"]),
  IdLess: "FALSE",
  OtherKey: "{}",
  LegacyFrom: "s1",
  // Streams declared incremental: false (run intake v2 3.0).
  FullStreams: "{}",
  MaxRuns: 3,
  // One run of the bound may end retry_pending; failed or cancelled runs
  // (abortRun) only in the intake slice.
  MaxRetry: 1,
  MaxAbort: 0,
  MaxReruns: 0,
  MaxDeletes: 1,
  MaxLost: 1,
  MaxSessions: 1,
  // A settlement failure changes nothing the design reads while
  // AckImmutable holds; only C15 turns it on.
  MaxSettleFail: 0,
  MaxFail: 1,
  MaxVer: 6,
  // Leave and the old stream DELETE (limitation L11) only in the Q9 profiles.
  MaxLeave: 0,
  MaxOldDelete: 0,
  // Device imports feed only S12 (second key) and L2.
  Views: "FALSE",
  // A bound, not a guard: FALSE makes every "ok" run cover every stream.
  PartialCover: "TRUE",
};

export const PROFILES = {
  // Section 4 small profile: two accounts, three streams, two keys of
  // records, MaxRuns 3, MaxVer 6, one owner key.
  small: { ...base },
  // Small plus a second owner key on d2 (S12).
  key: { ...base, OtherKey: set(["d2"]), Views: "TRUE" },
  // Small with settlement failures (C15).
  settle: { ...base, MaxSettleFail: 1 },
  // Small with more of each event.
  full: {
    ...base,
    MaxDeletes: 2,
    MaxLost: 2,
    MaxSessions: 2,
  },
  // The identity-less connector: one connection "".
  idless: { ...base, IdLess: "TRUE" },
  // The V4 counterexample shape: one account, two streams, one delete.
  split: {
    ...base,
    Acct: set(["A"]),
    PK: set(["x1"]),
    Streams: set(["s1", "s2"]),
    MaxRuns: 2,
    MaxLost: 0,
    MaxSessions: 0,
    MaxFail: 0,
  },
  // One account, two record keys, one stream, three runs: a late
  // old-generation head under later runs of the current generation.
  late: {
    ...base,
    Acct: set(["A"]),
    Streams: set(["s1"]),
    MaxLost: 0,
    MaxSessions: 0,
    MaxFail: 0,
  },
  // Scenario witnesses: one account, one key, two streams.
  lean: {
    ...base,
    Acct: set(["A"]),
    PK: set(["x1"]),
    Streams: set(["s1", "s2"]),
  },
  // Two deletes and reconnects.
  twice: {
    ...base,
    Acct: set(["A"]),
    PK: set(["x1"]),
    Streams: set(["s1"]),
    MaxRuns: 4,
    MaxDeletes: 2,
    MaxLost: 0,
    MaxSessions: 0,
    MaxFail: 0,
  },
  // Liveness: one account, one stream, a delete, reruns, a lagging reader
  // and imports.  No lost replies or failed entries: with them, or with two
  // streams, the run does not finish within the time bound.
  live: {
    ...base,
    Acct: set(["A"]),
    PK: set(["x1"]),
    Streams: set(["s1"]),
    MaxRuns: 2,
    MaxReruns: 2,
    MaxLost: 0,
    MaxSessions: 0,
    MaxFail: 0,
    Views: "TRUE",
    Readers: set(["r1"]),
  },
  // Live with one failed entry (C13: a failed entry must not block import).
  "live-fail": {
    ...base,
    Acct: set(["A"]),
    PK: set(["x1"]),
    Streams: set(["s1"]),
    MaxRuns: 2,
    MaxReruns: 2,
    MaxLost: 0,
    MaxSessions: 0,
    MaxFail: 1,
    Views: "TRUE",
    Readers: set(["r1"]),
  },
  // A reader PS that lags the registry (C18).
  lag: { ...base, Readers: set(["r1"]) },

  // Exhaustive slices of the small profile: each keeps one dimension of
  // it and cuts the rest, so that breadth-first search finishes.
  // One account, key and stream, three runs, one of each fault.
  "slice-faults": {
    ...base,
    Acct: set(["A"]),
    PK: set(["x1"]),
    Streams: set(["s1"]),
  },
  // Two accounts, one key, one stream, three runs, no faults.
  "slice-accounts": {
    ...base,
    PK: set(["x1"]),
    Streams: set(["s1"]),
    MaxLost: 0,
    MaxSessions: 0,
    MaxFail: 0,
  },
  // One device, two accounts, four runs: a device that holds needsFull
  // for one account and a checkpoint for the other starts a run (a
  // control and a witness only).
  "slice-accounts4": {
    ...base,
    Devices: set(["d1"]),
    PK: set(["x1"]),
    Streams: set(["s1"]),
    MaxRuns: 4,
    MaxDeletes: 0,
    MaxLost: 0,
    MaxSessions: 0,
    MaxFail: 0,
  },
  // A second owner key on d2, with imports.
  "slice-key": {
    ...base,
    Acct: set(["A"]),
    PK: set(["x1"]),
    Streams: set(["s1"]),
    MaxLost: 0,
    MaxSessions: 0,
    MaxFail: 0,
    OtherKey: set(["d2"]),
    Views: "TRUE",
  },
  // Ruling Q9 (a no-op onto a complete:false base): an old stream DELETE,
  // a device that leaves, four runs on one account, key and stream.
  "slice-q9": {
    ...base,
    Acct: set(["A"]),
    PK: set(["x1"]),
    Streams: set(["s1"]),
    MaxRuns: 4,
    MaxDeletes: 0,
    MaxLost: 0,
    MaxSessions: 0,
    MaxFail: 0,
    MaxLeave: 1,
    MaxOldDelete: 1,
  },
  // Liveness with Q9: an old stream DELETE and a device that leaves.
  // Three reruns: under Q9 a device that stays may need a no-op rerun
  // (which sets needsFull) and then a full one, and the device that
  // leaves may spend one first.
  // Liveness with two streams and partial coverage on one device.  No
  // complete:false head is reachable here (the state count is the same
  // with NeedsFull off), so L3 is vacuous on this profile; it checks L1
  // and L4 under partial coverage.
  "live-cover": {
    ...base,
    Devices: set(["d1"]),
    Acct: set(["A"]),
    IdLess: "TRUE",
    PK: set(["x1"]),
    Streams: set(["s1", "s2"]),
    MaxRuns: 3,
    MaxReruns: 2,
    MaxDeletes: 0,
    MaxRetry: 0,
    MaxLost: 0,
    MaxSessions: 0,
    MaxFail: 0,
  },
  "live-leave": {
    ...base,
    Acct: set(["A"]),
    PK: set(["x1"]),
    Streams: set(["s1"]),
    MaxRuns: 3,
    MaxReruns: 3,
    MaxDeletes: 0,
    MaxLost: 0,
    MaxSessions: 0,
    MaxFail: 0,
    MaxLeave: 1,
    MaxOldDelete: 1,
  },
  // Settlement failure and a lagging reader on the late slice.
  "slice-settle": { ...base, Acct: set(["A"]), Streams: set(["s1"]), MaxLost: 0, MaxSessions: 0, MaxFail: 0, MaxSettleFail: 1 },
  "slice-lag": { ...base, Acct: set(["A"]), Streams: set(["s1"]), MaxLost: 0, MaxSessions: 0, MaxFail: 0, Readers: set(["r1"]) },
  // Run intake v2: two streams, one declared incremental: false, partial
  // coverage, a retry_pending run and an aborted run, one delete.
  // Run intake v2 on the identity-less name every connector uses:
  // partial coverage, a stream declared incremental: false, retry_pending
  // and abort.  Two devices with two runs, then one device with four runs
  // (checkpoint merges across runs).  Three runs on two devices do not
  // finish within the hour.
  "slice-intake": {
    ...base,
    Acct: set(["A"]),
    IdLess: "TRUE",
    PK: set(["x1"]),
    Streams: set(["s1", "s2"]),
    FullStreams: set(["s2"]),
    MaxRuns: 2,
    MaxLost: 0,
    MaxSessions: 0,
    MaxFail: 0,
    MaxAbort: 1,
  },
  "slice-intake1": {
    ...base,
    Devices: set(["d1"]),
    Acct: set(["A"]),
    IdLess: "TRUE",
    PK: set(["x1"]),
    Streams: set(["s1", "s2"]),
    FullStreams: set(["s2"]),
    MaxRuns: 4,
    MaxLost: 0,
    MaxSessions: 0,
    MaxFail: 0,
    MaxAbort: 1,
  },
  // The identity-less connector, two accounts.
  "slice-idless": {
    ...base,
    IdLess: "TRUE",
    PK: set(["x1"]),
    Streams: set(["s1"]),
    MaxLost: 0,
    MaxSessions: 0,
    MaxFail: 0,
  },
};

export const SAFETY = [
  "TypeOK",
  "S1_NoLostCommit",
  "S2a_DeleteHolds",
  "S3_CleanGeneration",
  "S4_NoAccountMix",
  "S5_CleanupSafety",
  "S6_ExactOnce",
  "S7_CheckpointSafety",
  "S8_AckImmutable",
  "S9_OneWay",
  "S10_ReadinessMatchesRead",
  "S11_SeedCoverage",
  "S12_KeyIsolation",
  "NeverInconsistent",
  "NoHeadAboveControl",
  "HeadGenMonotone",
  "IncompleteOwned",
  "NeedsFullRunIsFull",
  "CoveredOnly",
  "IssuedStart",
  "NoFalseDelete",
  "LaterWriteSurvives",
];

export const LIVENESS = [
  "L1_EventualDelete",
  "L2_Convergence",
  "L3_NoStuckIncomplete",
  "L4_Resume",
];

/** Simulation bounds for the profiles that breadth-first search cannot finish. */
const SIM = { traces: 200000, depth: 60, seed: 1 };
// The cut for slices that do not finish within an hour with the intake
// choices: every "ok" run covers every stream and no run ends
// retry_pending.  Partial coverage and retry_pending are checked on
// "split", "slice-key", "slice-q9", "slice-idless", "slice-intake",
// "slice-intake1" and in the controls on "late".
const CUT = { PartialCover: "FALSE", MaxRetry: 0 };

/**
 * name, what it shows, profile, changed constants, expected result, kind,
 * and optional simulation bounds.
 * A safety positive checks every safety property. A liveness positive
 * checks every liveness property. A control checks TypeOK and `expect`, so
 * that TLC's first violation is that one.
 */
export const CONFIGS = [
  // --- positives ---
  // Section 4 profiles: too large for breadth-first search on this host.
  ["Small", "the design, small profile", "small", {}, "pass", "safety", SIM],
  ["Key", "the design, key profile (a second owner key)", "key", {}, "pass", "safety", SIM],
  ["Full", "the design, full profile", "full", {}, "pass", "safety", SIM],
  ["IdLess", "the design, an identity-less connector", "idless", {}, "pass", "safety", SIM],
  // Exhaustive slices of the small profile.
  // slice-faults with every intake choice does not finish within the
  // hour: lost replies, and a restart with a failed entry, are two slices.
  ["Slice-faults", "the design: lost replies (cut)", "slice-faults", { ...CUT, MaxSessions: 0, MaxFail: 0 }, "pass"],
  ["Slice-faults2", "the design: a restart and a failed entry (cut)", "slice-faults", { ...CUT, MaxLost: 0 }, "pass"],
  ["Slice-accounts", "the design: two accounts", "slice-accounts", CUT, "pass"],
  ["Slice-key", "the design: a second owner key with imports", "slice-key", {}, "pass"],
  ["Slice-idless", "the design: an identity-less connector, two accounts", "slice-idless", {}, "pass"],
  // Four runs with two deletes do not finish within the hour with the
  // intake choices; three runs still allow run, delete, run, delete, run.
  ["Slice-twice", "the design: two deletes and reconnects (cut, three runs)", "twice", { ...CUT, MaxRuns: 3 }, "pass"],
  ["Slice-q9", "the design: an old stream DELETE, a device that leaves, no-ops", "slice-q9", {}, "pass"],
  ["Slice-intake", "the design, identity-less: partial coverage, a stream declared incremental: false, retry_pending and abort; two devices", "slice-intake", {}, "pass"],
  ["Slice-intake1", "the design, identity-less: the same on one device with four runs", "slice-intake1", {}, "pass"],
  ["Live", "liveness of the design", "live", CUT, "pass", "liveness"],
  // With the reader PS it does not finish within the hour; reader lag
  // matters only to C18, and Live keeps the reader.
  ["Live-fail", "liveness of the design with a failed entry (cut, no reader PS)", "live-fail", { ...CUT, Readers: "{}" }, "pass", "liveness"],
  // One stream, so PartialCover only drops runs that cover nothing; one
  // retry_pending end stays, the positive counterpart of C19L.
  ["Live-leave", "liveness of the design with an old stream DELETE, a device that leaves and a retry_pending end", "live-leave", { PartialCover: "FALSE" }, "pass", "liveness"],
  ["Live-cover", "liveness with two streams and partial coverage, one device, identity-less", "live-cover", {}, "pass", "liveness"],
  // --- the proposed fix RetryCkptStaysFull (traces/retry-token-incremental.txt) ---
  ["Fix-live-leave", "Live-leave with the proposed fix", "live-leave", { PartialCover: "FALSE", RetryCkptStaysFull: "TRUE" }, "pass", "liveness"],
  ["Fix-idless", "the identity-less slice with the proposed fix", "slice-idless", { RetryCkptStaysFull: "TRUE" }, "pass"],
  ["Fix-split", "two streams, partial coverage and retry_pending with the proposed fix", "split", { RetryCkptStaysFull: "TRUE" }, "pass"],

  // --- regression: the revision 4 counterexample (traces/split-run.txt) ---
  [
    "CE-split-run",
    "a user-connect run commits one stream, a delete lands, its next stream sees deleted",
    "split",
    {},
    "pass",
  ],

  // --- regression: the revision 4.1 counterexample (traces/late-head.txt) ---
  [
    "CE-late-head",
    "an old-generation run resumes after a delete and reconnect elsewhere; the stream row has a newer generation",
    "late",
    CUT,
    "pass",
  ],
  [
    "C-late-head-old-rule",
    "the two-outcome base rule: a newer-generation row gives an empty base (only S1 checked)",
    "late",
    { StaleGenStops: "FALSE" },
    "S1_NoLostCommit",
  ],

  // --- section 4 negative controls: each removes one guard ---
  ["C01-no-gen-in-names", "part names without the generation", "late", { GenInNames: "FALSE" }, "S5_CleanupSafety"],
  // C02 is not a failing control.  With the guard off, every safety
  // invariant still holds on three profiles with a generation change
  // (README.md, "C02 and C12"); the rows record that.
  ["C02-key", "checkpoints and entries kept on a generation change", "slice-key", { ClearOnGenChange: "FALSE" }, "pass"],
  ["C02-split", "the same, two streams", "split", { ClearOnGenChange: "FALSE" }, "pass"],
  ["C02-idless", "the same, identity-less", "slice-idless", { ClearOnGenChange: "FALSE" }, "pass"],
  ["C03-non-exclusive", "an occupied head version is replaced", "late", { ExclusiveHeads: "FALSE" }, "S1_NoLostCommit"],
  ["C04-reader-unions", "a plain-name read unions the connections", "slice-accounts", { OneConnectionRead: "FALSE" }, "S4_NoAccountMix"],
  ["C05-seed-any-gen", "the Desktop seeds at any generation", "late", { SeedOnlyGen1: "FALSE" }, "S3_CleanGeneration"],
  ["C06-early-checkpoint", "the checkpoint is saved at the first stream commit", "split", { CheckpointAfterAll: "FALSE" }, "S7_CheckpointSafety"],
  ["C07-no-reread-after-create", "publish after a create or reconnect reply without a re-read", "late", { ReReadAfterCtl: "FALSE" }, "S3_CleanGeneration"],
  ["C08-rebind-old-spool", "a userConnect spool reconnects whatever its start", "late", { NoRebind: "FALSE" }, "S3_CleanGeneration"],
  ["C09-no-listing-needed", "start = null is read as absent", "slice-faults", { NeedListing: "FALSE" }, "S3_CleanGeneration"],
  ["C10-legacy-ignores-delete", "the legacy fallback ignores a deleted connection", "late", { LegacyHonoursDelete: "FALSE" }, "S2a_DeleteHolds"],
  ["C11-collectedat-competition", "a newer legacy file beats a live complete view", "late", { OneWay: "FALSE" }, "S9_OneWay"],
  ["C12-no-needsfull", "complete:false does not force a full run", "slice-q9", { NeedsFull: "FALSE" }, "IncompleteOwned"],
  ["C13-pending-blocks-import", "a pending or failed entry blocks import", "live-fail", { ImportPastPending: "FALSE" }, "L2_Convergence", "liveness"],
  ["C14-seed-only-empty-base", "the Desktop seeds only into an empty base", "late", { SeedWhateverBase: "FALSE" }, "S11_SeedCoverage"],
  ["C15-failed-row-replaceable", "a row that failed settlement can be replaced", "slice-settle", { AckImmutable: "FALSE" }, "S8_AckImmutable"],
  ["C16-readiness-live-only", "readiness uses live, reads use live and complete", "slice-q9", { ReadinessSame: "FALSE" }, "S10_ReadinessMatchesRead"],
  ["C19-no-q9", "a no-op onto a complete:false base sets no needsFull", "slice-q9", { NoOpNeedsFull: "FALSE" }, "IncompleteOwned"],
  // Is needsFull needed for liveness once RetryCkptStaysFull holds?  A
  // complete:false publish also clears the checkpoint, so only a
  // retry_pending save before the next run could make it incremental, and
  // the fix keeps that run full.  Expected to pass (README.md, C02 and C12).
  ["C12L-fix", "complete:false sets no needsFull, with the proposed fix", "live-leave", { PartialCover: "FALSE", RetryCkptStaysFull: "TRUE", NeedsFull: "FALSE" }, "pass", "liveness"],
  ["C19L-no-q9", "the same, against liveness L3", "live-leave", { NoOpNeedsFull: "FALSE" }, "L3_NoStuckIncomplete", "liveness"],
  ["C20-null-base-noop", "an incremental run onto an empty base with an empty spool is a no-op", "slice-q9", { NullBasePublishes: "FALSE" }, "IncompleteOwned"],
  ["C21-needsfull-not-full", "a device with needsFull and a checkpoint runs incrementally", "slice-accounts4", { NeedsFullForcesFull: "FALSE" }, "NeedsFullRunIsFull"],
  ["C18-immediate-delete", "the design against an immediate delete property", "slice-lag", {}, "S2_Immediate"],

  // --- run intake v2 negative controls ---
  ["C-publish-uncovered", "a stream the run did not cover is published", "late", { PublishCoveredOnly: "FALSE" }, "CoveredOnly"],
  ["C-producer-state", "START takes a state the producer chose", "late", { WriterIssuesStart: "FALSE" }, "IssuedStart"],
  ["C-retry-saves-spooled", "retry_pending saves the cursor of a stream whose records it drops (v2 2.3 as written)", "late", { RetryQuietOnly: "FALSE" }, "S7_CheckpointSafety"],
  ["C-full-replaces", "a stream-full run replaces its base instead of merging", "late", { FullMerges: "FALSE", FullStreams: "{s1}" }, "NoFalseDelete"],

  // --- section 4 scenarios: each must be reachable (NotX violated) ---
  ["W-trace-a", "trace A: a lost create lands and is deleted before its resend", "lean", {}, "NotTraceA", "witness"],
  ["W-trace-b", "trace B: a userConnect entry meets a delete and reconnect", "lean", {}, "NotTraceB", "witness"],
  ["W-offline-vs-5", "a run started at active(1) is pending against active(5)", "twice", {}, "NotOfflineVs5", "witness"],
  ["W-late-old-head", "an old-generation head lands after control left its generation", "lean", {}, "NotLateOldHead", "witness"],
  ["W-twice", "delete and reconnect twice", "twice", {}, "NotTwice", "witness"],
  ["W-first-write-in-delete", "a stream's first head is in flight across a delete", "lean", {}, "NotFirstWriteDuringDelete", "witness"],
  ["W-phone-first-seed", "a phone publishes first, the Desktop seed merges later", "late", {}, "NotPhoneFirstThenSeed", "witness"],
  ["W-zero-emission-seed", "the seed alone publishes a stream", "slice-accounts", {}, "NotZeroEmissionSeed", "witness"],
  ["W-settle-after-ack", "a row fails settlement after its ack", "slice-settle", {}, "NotSettleAfterAck", "witness"],
  ["W-switch-reused-ckpt", "an account switch with a reused checkpoint", "slice-accounts", {}, "NotSwitchReusedCkpt", "witness"],
  ["W-needsfull-with-ckpt", "a device holds needsFull and a checkpoint at once", "slice-accounts4", {}, "NotNeedsFullWithCkpt", "witness"],
  ["W-failed-entry", "a failed entry while newer heads arrive", "lean", {}, "NotFailedEntryNewerHeads", "witness"],
].map(([name, why, profile, changes, expect, kind = "safety", simulate]) => ({
  name,
  why,
  profile,
  changes,
  expect,
  kind,
  simulate,
}));

export function configText(config) {
  const constants = {
    ...PROFILES[config.profile],
    ...DESIGN,
    ...config.changes,
  };
  const changed = Object.keys(config.changes);
  const liveness = config.kind === "liveness";
  const checks = liveness
    ? config.expect === "pass"
      ? [
          "INVARIANT TypeOK",
          // L2 is about imports: a profile without views does not check it.
          ...LIVENESS.filter((p) => constants.Views === "TRUE" || p !== "L2_Convergence").map(
            (p) => `PROPERTY ${p}`,
          ),
        ]
      : ["INVARIANT TypeOK", `PROPERTY ${config.expect}`]
    : config.expect === "pass"
      ? SAFETY.map((p) => `INVARIANT ${p}`)
      : ["INVARIANT TypeOK", `INVARIANT ${config.expect}`];
  return [
    `\\* ${config.name}: ${config.why}.`,
    `\\* Generated from formal/configs.mjs. Profile: ${config.profile}. Changed: ${changed.join(", ") || "nothing"}.`,
    `\\* Expected: ${config.expect === "pass" ? "no violation" : `${config.expect} violated`}.`,
    ...(config.simulate
      ? [
          `\\* Mode: simulation, not proof: ${config.simulate.traces} random behaviours of depth <= ${config.simulate.depth}, seed ${config.simulate.seed}.`,
        ]
      : []),
    "SPECIFICATION Spec",
    "CONSTANTS",
    ...Object.entries(constants).map(([k, v]) => `  ${k} = ${v}`),
    // Safety configs bound every chain; liveness configs bound by counters
    // only (a state constraint would cut behaviours short).
    ...(liveness ? [] : ["CONSTRAINT VerBound"]),
    ...(liveness ? [] : ["SYMMETRY Symmetry"]),
    ...checks,
    "",
  ].join("\n");
}
