#!/usr/bin/env node
// Generate the conformance corpus from the TLA+ model.
//
//   TLA2TOOLS=/path/to/tla2tools.jar node conformance/generate.mjs \
//     --formal <dir with StreamSync.tla and configs.mjs> \
//     --model-ref <git commit of that dir> \
//     --scratch <empty work dir> [--seeds 60] [--out conformance/corpus/corpus.ndjson.gz]
//
// Each simulated trace is one TLC run: `-simulate` with a fixed seed and one
// worker, and the invariant SimEnd, which fails at the end of a behaviour so
// that `-dumpTrace json` writes it. Fixed traces are breadth-first runs to a
// witness invariant (shortest trace). TLC runs one at a time under
// `nice -n 19` with at most 4 workers; each run's state directory is deleted
// after it.
//
// The corpus is gzipped NDJSON (gzip without a timestamp, so the bytes are
// deterministic): line 1 is metadata, every other line is one trace.
// A trace stores its first state in full and every later state as the
// top-level fields that changed.
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { gzipSync } from "node:zlib";

const here = dirname(fileURLToPath(import.meta.url));
const args = new Map();
for (let i = 2; i < process.argv.length; i += 2) {
  args.set(process.argv[i].replace(/^--/, ""), process.argv[i + 1]);
}
const formal = resolve(args.get("formal") ?? join(here, "..", "formal"));
const modelRef = args.get("model-ref") ?? "unknown";
const scratch = resolve(args.get("scratch") ?? "");
const seeds = Number(args.get("seeds") ?? 60);
const out = resolve(
  args.get("out") ?? join(here, "corpus", "corpus.ndjson.gz"),
);
const jar = process.env.TLA2TOOLS;
if (!jar || !args.get("scratch")) {
  console.error("set TLA2TOOLS and pass --scratch <dir>");
  process.exit(2);
}
mkdirSync(scratch, { recursive: true });

const { DESIGN, PROFILES } = await import(
  pathToFileURL(join(formal, "configs.mjs")).href
);
const modelText = readFileSync(join(formal, "StreamSync.tla"), "utf8");
const sha256 = (text) => createHash("sha256").update(text).digest("hex");
copyFileSync(join(formal, "StreamSync.tla"), join(scratch, "StreamSync.tla"));
const WRAPPERS = ["StreamSyncConformance.tla", "StreamSyncConformanceR3.tla"];
for (const module of WRAPPERS) {
  copyFileSync(join(here, module), join(scratch, module));
}

// Simulation profiles: the model's own bound profiles, so they follow the
// model. The run counter is raised so that more runs reach publish and
// checkpoint; MaxVer still bounds every chain.
// Profiles the model does not have (older revisions) are skipped.
const SIM = [
  ["late", { MaxRuns: 5 }],
  ["split", { MaxRuns: 4 }],
  ["lean", { MaxRuns: 5 }],
  ["key", { MaxRuns: 4 }],
  ["idless", { MaxRuns: 4 }],
  ["small", { MaxRuns: 4 }],
  ["twice", { MaxRuns: 6 }],
  ["slice-q9", { MaxRuns: 5 }],
].filter(([p]) => p in PROFILES);

// Fixed traces: [id, profile, invariant, changes, module]. Breadth-first, so
// each is the shortest trace to its state.
// A witness whose breadth-first search does not finish in this time is left
// out and named in the corpus as timed out.
const FIXED_TIMEOUT_MS = Number(args.get("fixed-timeout") ?? 180) * 1000;
const FIXED = [
  ["late-head", "late", "NotLateBasePoint", {}],
  ["split-run", "split", "NotSplitRunPoint", {}],
  ["CE-late-head", "late", "S1_NoLostCommit", {}],
  ["W-trace-a", "lean", "NotTraceA", {}],
  ["W-trace-b", "lean", "NotTraceB", {}],
  ["W-late-old-head", "lean", "NotLateOldHead", {}],
  ["W-first-write-in-delete", "lean", "NotFirstWriteDuringDelete", {}],
  ["W-phone-first-seed", "lean", "NotPhoneFirstThenSeed", {}],
  ["W-zero-emission-seed", "lean", "NotZeroEmissionSeed", {}],
  ["W-failed-entry", "lean", "NotFailedEntryNewerHeads", {}],
  ["W-twice", "twice", "NotTwice", {}],
  [
    "stale-generation",
    "late",
    "NotStaleGenPoint",
    {},
    "StreamSyncConformanceR3",
  ],
  ["q9-noop", "slice-q9", "NotQ9NoopPoint", {}, "StreamSyncConformanceR3"],
  [
    "incomplete-plan-lost-to-409",
    "lean",
    "NotSkipAllCompletePoint",
    {},
    "StreamSyncConformanceR3",
  ],
].filter(
  ([, p, , , module]) =>
    p in PROFILES && (module === undefined || "NoOpNeedsFull" in DESIGN),
);

function cfgText(profile, changes, invariant, simulate) {
  const constants = { ...PROFILES[profile], ...DESIGN, ...changes };
  return [
    "SPECIFICATION Spec",
    "CONSTANTS",
    ...Object.entries(constants).map(([k, v]) => `  ${k} = ${v}`),
    "CONSTRAINT VerBound",
    ...(simulate ? [] : ["SYMMETRY Symmetry"]),
    `INVARIANT ${invariant}`,
    "ALIAS TraceAlias",
    "",
  ].join("\n");
}

let runNo = 0;
function tlc(cfg, flags, timeoutMs = 0, module = "StreamSyncConformance") {
  runNo += 1;
  const cfgFile = join(scratch, `run-${runNo}.cfg`);
  const dump = join(scratch, `run-${runNo}.json`);
  const meta = join(scratch, `meta-${runNo}`);
  writeFileSync(cfgFile, cfg);
  const argv = [
    "-n",
    "19",
    "java",
    "-Xmx2g",
    "-XX:+UseParallelGC",
    "-cp",
    jar,
    "tlc2.TLC",
    ...flags,
    "-deadlock",
    "-noGenerateSpecTE",
    "-cleanup",
    "-metadir",
    meta,
    "-dumpTrace",
    "json",
    dump,
    "-config",
    cfgFile,
    join(scratch, `${module}.tla`),
  ];
  const run = spawnSync("nice", argv, {
    cwd: scratch,
    encoding: "utf8",
    maxBuffer: 1 << 30,
    timeout: timeoutMs,
  });
  rmSync(meta, { recursive: true, force: true });
  rmSync(cfgFile, { force: true });
  const text = `${run.stdout}${run.stderr}`;
  if (run.signal || run.error?.code === "ETIMEDOUT") return { timedOut: true };
  if (!existsSync(dump)) {
    if (
      !text.includes("No error has been found") &&
      !/traces generated/.test(text)
    ) {
      throw new Error(`TLC failed:\n${text.split("\n").slice(-30).join("\n")}`);
    }
    return null;
  }
  const json = JSON.parse(readFileSync(dump, "utf8"));
  rmSync(dump, { force: true });
  return json.counterexample;
}

function compact(ce) {
  const states = ce.state.map(([, st]) => st);
  const steps = ce.action.map(([, act]) => {
    const step = { a: act.name };
    if (act.context && Object.keys(act.context).length > 0)
      step.p = act.context;
    return step;
  });
  const delta = [states[0]];
  for (let i = 1; i < states.length; i += 1) {
    const d = {};
    for (const [k, v] of Object.entries(states[i])) {
      if (JSON.stringify(v) !== JSON.stringify(states[i - 1][k])) d[k] = v;
    }
    delta.push(d);
  }
  return { steps, states: delta };
}

const traces = [];
const seen = new Set();
const commands = [];

for (const [id, profile, invariant, changes, module] of FIXED) {
  const flags = ["-workers", "4"];
  commands.push({ id, profile, invariant, flags: flags.join(" ") });
  const started = Date.now();
  const ce = tlc(
    cfgText(profile, changes, invariant, false),
    flags,
    FIXED_TIMEOUT_MS,
    module,
  );
  const secs = Math.round((Date.now() - started) / 1000);
  if (ce?.timedOut) {
    console.log(`fixed ${id}: no trace within ${secs} s, left out`);
    traces.push({ id, kind: "fixed", profile, invariant, timedOut: secs });
    continue;
  }
  if (!ce) {
    console.log(`fixed ${id}: no trace (${invariant} holds), ${secs} s`);
    traces.push({ id, kind: "fixed", profile, invariant, holds: true });
    continue;
  }
  const t = compact(ce);
  console.log(`fixed ${id}: ${t.steps.length} steps, ${secs} s`);
  traces.push({ id, kind: "fixed", profile, invariant, ...t });
}

for (const [profile, changes] of SIM) {
  let got = 0;
  for (let seed = 1; seed <= seeds; seed += 1) {
    const flags = [
      "-workers",
      "1",
      "-simulate",
      "num=400",
      "-depth",
      "80",
      "-seed",
      String(seed),
    ];
    const ce = tlc(cfgText(profile, changes, "SimEnd", true), flags);
    if (!ce) continue;
    const t = compact(ce);
    const key = sha256(
      JSON.stringify(t.steps) + JSON.stringify(t.states.at(-1)),
    );
    if (seen.has(key)) continue;
    seen.add(key);
    got += 1;
    traces.push({ id: `${profile}-${seed}`, kind: "sim", profile, seed, ...t });
  }
  commands.push({
    profile,
    changes,
    flags: `-workers 1 -simulate num=400 -depth 80 -seed 1..${seeds}`,
  });
  console.log(`sim ${profile}: ${got} traces`);
}

const meta = {
  kind: "meta",
  model: {
    ref: modelRef,
    streamSyncSha256: sha256(modelText),
    configsSha256: sha256(readFileSync(join(formal, "configs.mjs"), "utf8")),
    // SHA-256 of the wrapper modules, concatenated in WRAPPERS order.
    wrapperSha256: sha256(
      WRAPPERS.map((m) => readFileSync(join(here, m), "utf8")).join(""),
    ),
    staleGeneration: /\bPlanStale\b/.test(modelText),
    design: DESIGN,
  },
  tlc: "tla2tools.jar, java -cp tla2tools.jar tlc2.TLC",
  command: `TLA2TOOLS=<jar> node conformance/generate.mjs --formal <formal dir at ${modelRef}> --model-ref ${modelRef} --scratch <dir> --seeds ${seeds}`,
  profiles: Object.fromEntries(
    [...new Set([...SIM.map(([p]) => p), ...FIXED.map(([, p]) => p)])].map(
      (p) => [
        p,
        { ...PROFILES[p], ...(SIM.find(([q]) => q === p)?.[1] ?? {}) },
      ],
    ),
  ),
  runs: commands,
};
mkdirSync(dirname(out), { recursive: true });
const text = [meta, ...traces].map((x) => JSON.stringify(x)).join("\n") + "\n";
writeFileSync(out, out.endsWith(".gz") ? gzipSync(text, { level: 9 }) : text);
console.log(`wrote ${traces.length} traces to ${out}`);
