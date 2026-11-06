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

/** The design (revision 4.1): every guard on. */
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
  RawSeedChecksId: "TRUE",
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
  RawHasId: "TRUE",
  MaxRuns: 3,
  MaxReruns: 0,
  MaxDeletes: 1,
  MaxLost: 1,
  MaxSessions: 1,
  // A settlement failure changes nothing the design reads while
  // AckImmutable holds; only C15 turns it on.
  MaxSettleFail: 0,
  MaxFail: 1,
  MaxVer: 6,
  // Device imports feed only S12 (second key) and L2.
  Views: "FALSE",
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
  // Liveness: one account, two streams, finite events, reruns allowed.
  live: {
    ...base,
    Acct: set(["A"]),
    PK: set(["x1"]),
    Streams: set(["s1", "s2"]),
    MaxRuns: 2,
    MaxReruns: 2,
    MaxLost: 1,
    MaxSessions: 0,
    MaxFail: 1,
    Views: "TRUE",
    Readers: set(["r1"]),
  },
  // A reader PS that lags the registry (C18).
  lag: { ...base, Readers: set(["r1"]) },
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
];

export const LIVENESS = [
  "L1_EventualDelete",
  "L2_Convergence",
  "L3_NoStuckIncomplete",
  "L4_Resume",
];

/**
 * name, what it shows, profile, changed constants, expected result, kind.
 * A safety positive checks every safety property. A liveness positive
 * checks every liveness property. A control checks TypeOK and `expect`, so
 * that TLC's first violation is that one.
 */
export const CONFIGS = [
  // --- positives ---
  ["Small", "the design, small profile", "small", {}, "pass"],
  ["Key", "the design, key profile (a second owner key)", "key", {}, "pass"],
  ["Full", "the design, full profile, symmetry on Acct and PK", "full", {}, "pass"],
  ["IdLess", "the design, an identity-less connector", "idless", {}, "pass"],
  ["Live", "liveness of the design", "live", {}, "pass", "liveness"],

  // --- regression: the revision 4 counterexample (traces/split-run.txt) ---
  [
    "CE-split-run",
    "a user-connect run commits one stream, a delete lands, its next stream sees deleted",
    "split",
    {},
    "pass",
  ],

  // --- counterexample to revision 4.1 (traces/late-head.txt) ---
  [
    "CE-late-head",
    "the design: an old-generation head lands above a newer generation's head, the next incremental run of that generation drops records",
    "late",
    {},
    "S1_NoLostCommit",
  ],

  // --- section 4 negative controls: each removes one guard ---
  ["C01-no-gen-in-names", "part names without the generation", "small", { GenInNames: "FALSE" }, "S5_CleanupSafety"],
  ["C02-no-clear-on-gen-change", "checkpoints and entries kept on a generation change", "small", { ClearOnGenChange: "FALSE" }, "S3_CleanGeneration"],
  ["C03-non-exclusive", "an occupied head version is replaced", "small", { ExclusiveHeads: "FALSE" }, "S1_NoLostCommit"],
  ["C04-reader-unions", "a plain-name read unions the connections", "small", { OneConnectionRead: "FALSE" }, "S4_NoAccountMix"],
  ["C05-seed-any-gen", "the Desktop seeds at any generation", "small", { SeedOnlyGen1: "FALSE" }, "S3_CleanGeneration"],
  ["C06-early-checkpoint", "the checkpoint is saved at the first stream commit", "small", { CheckpointAfterAll: "FALSE" }, "S7_CheckpointSafety"],
  ["C07-no-reread-after-create", "publish after a create or reconnect reply without a re-read", "small", { ReReadAfterCtl: "FALSE" }, "S3_CleanGeneration"],
  ["C08-rebind-old-spool", "a userConnect spool reconnects whatever its start", "small", { NoRebind: "FALSE" }, "S3_CleanGeneration"],
  ["C09-no-listing-needed", "start = null is read as absent", "small", { NeedListing: "FALSE" }, "S3_CleanGeneration"],
  ["C10-legacy-ignores-delete", "the legacy fallback ignores a deleted connection", "small", { LegacyHonoursDelete: "FALSE" }, "S2a_DeleteHolds"],
  ["C11-collectedat-competition", "a newer legacy file beats a live complete view", "small", { OneWay: "FALSE" }, "S9_OneWay"],
  ["C12-no-needsfull", "complete:false does not force a full run", "live", { NeedsFull: "FALSE" }, "L3_NoStuckIncomplete", "liveness"],
  ["C13-pending-blocks-import", "a pending or failed entry blocks import", "live", { ImportPastPending: "FALSE" }, "L2_Convergence", "liveness"],
  ["C14-seed-only-empty-base", "the Desktop seeds only into an empty base", "small", { SeedWhateverBase: "FALSE" }, "S11_SeedCoverage"],
  ["C15-failed-row-replaceable", "a row that failed settlement can be replaced", "settle", { AckImmutable: "FALSE" }, "S8_AckImmutable"],
  ["C16-readiness-live-only", "readiness uses live, reads use live and complete", "small", { ReadinessSame: "FALSE" }, "S10_ReadinessMatchesRead"],
  ["C17-raw-seed-ignores-id", "the raw seed ignores the recorded identity", "small", { RawSeedChecksId: "FALSE" }, "S4_NoAccountMix"],
  ["C18-immediate-delete", "the design against an immediate delete property", "lag", {}, "S2_Immediate"],

  // --- section 4 scenarios: each must be reachable (NotX violated) ---
  ["W-trace-a", "trace A: a lost create lands and is deleted before its resend", "lean", {}, "NotTraceA", "witness"],
  ["W-trace-b", "trace B: a userConnect entry meets a delete and reconnect", "lean", {}, "NotTraceB", "witness"],
  ["W-offline-vs-5", "a run started at active(1) is pending against active(5)", "twice", {}, "NotOfflineVs5", "witness"],
  ["W-late-old-head", "an old-generation head lands above a current one", "lean", {}, "NotLateOldHead", "witness"],
  ["W-twice", "delete and reconnect twice", "twice", {}, "NotTwice", "witness"],
  ["W-first-write-in-delete", "a stream's first head is in flight across a delete", "lean", {}, "NotFirstWriteDuringDelete", "witness"],
  ["W-phone-first-seed", "a phone publishes first, the Desktop seed merges later", "lean", {}, "NotPhoneFirstThenSeed", "witness"],
  ["W-zero-emission-seed", "the seed alone publishes a stream", "lean", {}, "NotZeroEmissionSeed", "witness"],
  ["W-settle-after-ack", "a row fails settlement after its ack", "settle", {}, "NotSettleAfterAck", "witness"],
  ["W-switch-reused-ckpt", "an account switch with a reused checkpoint", "small", {}, "NotSwitchReusedCkpt", "witness"],
  ["W-failed-entry", "a failed entry while newer heads arrive", "lean", {}, "NotFailedEntryNewerHeads", "witness"],
].map(([name, why, profile, changes, expect, kind = "safety"]) => ({
  name,
  why,
  profile,
  changes,
  expect,
  kind,
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
      ? ["INVARIANT TypeOK", ...LIVENESS.map((p) => `PROPERTY ${p}`)]
      : ["INVARIANT TypeOK", `PROPERTY ${config.expect}`]
    : config.expect === "pass"
      ? SAFETY.map((p) => `INVARIANT ${p}`)
      : ["INVARIANT TypeOK", `INVARIANT ${config.expect}`];
  return [
    `\\* ${config.name}: ${config.why}.`,
    `\\* Generated from formal/configs.mjs. Profile: ${config.profile}. Changed: ${changed.join(", ") || "nothing"}.`,
    `\\* Expected: ${config.expect === "pass" ? "no violation" : `${config.expect} violated`}.`,
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
