// The one source of every TLC config in cfg/. `node formal/check.mjs --write-configs`
// regenerates cfg/*.cfg from this table; `node formal/check.mjs` fails when
// they differ.
//
// A config is a bound profile plus the guards it turns off. `expect` is
// "pass", or the one property that must be violated. A control that fails
// some other way (parse error, another property, an unfinished run) does not
// count as failing as required.

const set = (xs) => `{${xs.join(", ")}}`;

/** The design: every guard on. Empty parts on (the harder environment). */
export const DESIGN = {
  GenInNames: "TRUE",
  ClearOnGenChange: "TRUE",
  Exclusive: "TRUE",
  OneConnectionRead: "TRUE",
  SeedOnlyGen1: "TRUE",
  CheckpointAfterAll: "TRUE",
  EmptyParts: "TRUE",
};

/** Bound profiles. Devices, NS and Streams are TLC model values. */
export const PROFILES = {
  // Small: one connection, two streams, one key. One delete, one reconnect,
  // one lost reply, no crash.
  small: {
    Devices: set(["d1", "d2"]),
    Desktop: "d1",
    NS: set(["n1"]),
    Streams: set(["s1", "s2"]),
    Keys: set([1]),
    MaxRuns: 3,
    MaxDeletes: 1,
    MaxConnects: 1,
    MaxLost: 1,
    MaxCrashes: 0,
  },
  // Full: two connections (accounts) of the connector, three streams, two
  // deletes and two reconnects, one lost reply, one crash.
  full: {
    Devices: set(["d1", "d2"]),
    Desktop: "d1",
    NS: set(["n1", "n2"]),
    Streams: set(["s1", "s2", "s3"]),
    Keys: set([1]),
    MaxRuns: 3,
    MaxDeletes: 2,
    MaxConnects: 2,
    MaxLost: 1,
    MaxCrashes: 1,
  },
  // Two connections, small otherwise: the reader control needs two live
  // connections of one stream.
  twoNs: {
    Devices: set(["d1", "d2"]),
    Desktop: "d1",
    NS: set(["n1", "n2"]),
    Streams: set(["s1"]),
    Keys: set([1]),
    MaxRuns: 2,
    MaxDeletes: 0,
    MaxConnects: 0,
    MaxLost: 0,
    MaxCrashes: 0,
  },
};

export const SAFETY = [
  "TypeOK",
  "S1_NoLostCommit",
  "S2_DeleteHolds",
  "S3_ReconnectClean",
  "S4_NoAccountMix",
  "S5_CleanupSafe",
  "S6_ExactResend",
  "S7_CheckpointSafe",
  "X1_CompleteHonest",
  "NeverInconsistent",
];

/**
 * name, what it shows, profile, changed constants, expected result, kind.
 * Positives check every safety property (or L1). A control checks TypeOK and
 * `expect`, so that TLC's first violation is that one.
 */
export const CONFIGS = [
  // --- positives ---
  ["Small", "the design, small profile", "small", {}, "pass"],
  ["Full", "the design, full profile", "full", {}, "pass"],
  [
    "L1-Small",
    "convergence of the design, small profile",
    "small",
    {},
    "pass",
    "liveness",
  ],

  // --- counterexample to the design (traces/split-run.txt) ---
  [
    "CE-split-run",
    "the design: a user-connect run commits one stream, a delete lands, its next stream reconnects",
    "small",
    {},
    "S7_CheckpointSafe",
  ],

  // --- controls from section 4: each removes one guard ---
  [
    "C1-no-gen-in-names",
    "part names without the generation; cleanup of an old generation",
    "small",
    { GenInNames: "FALSE" },
    "S5_CleanupSafe",
  ],
  [
    "C2-no-clear-on-gen-change",
    "checkpoints and entries kept on a generation change",
    "small",
    { ClearOnGenChange: "FALSE" },
    "S3_ReconnectClean",
  ],
  [
    "C3-non-exclusive",
    "an occupied registry version is replaced",
    "small",
    { Exclusive: "FALSE" },
    "S1_NoLostCommit",
  ],
  [
    "C4-reader-unions",
    "a plain-name read unions the connections",
    "twoNs",
    { OneConnectionRead: "FALSE" },
    "S4_NoAccountMix",
  ],
  [
    "C5-seed-any-gen",
    "the Desktop seeds at any generation with an empty base",
    "small",
    { SeedOnlyGen1: "FALSE" },
    "S3_ReconnectClean",
  ],
  [
    "C6-early-checkpoint",
    "the checkpoint is saved at the first stream commit",
    "small",
    { CheckpointAfterAll: "FALSE" },
    "S7_CheckpointSafe",
  ],
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
  const checks =
    config.kind === "liveness"
      ? ["INVARIANT TypeOK", "PROPERTY L1_Convergence"]
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
    ...checks,
    "",
  ].join("\n");
}
