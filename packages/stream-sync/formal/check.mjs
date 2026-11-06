#!/usr/bin/env node
// Runner for the formal model.
//
//   node formal/check.mjs              fail if cfg/ differs from configs.mjs
//   node formal/check.mjs --write      regenerate cfg/ from configs.mjs
//   node formal/check.mjs --list       print every config and its expectation
//   node formal/check.mjs --run NAME…  run TLC on each config and compare the
//                                      result with its expectation
//
// A config with `simulate` runs TLC in simulation mode (random behaviours
// with a fixed seed and depth). Its "pass" is evidence, not proof.
//
// --run needs TLA2TOOLS (path to tla2tools.jar, TLC 1.8 or later). Optional:
// WORKERS (default 4), HEAP (default 4g). TLC state files go to a fresh
// directory under the OS temp directory and are deleted after each run.
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { CONFIGS, configText } from "./configs.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const cfgDir = join(here, "cfg");
const args = process.argv.slice(2);

function expected() {
  return new Map(CONFIGS.map((c) => [`${c.name}.cfg`, configText(c)]));
}

if (args[0] === "--write") {
  for (const [file, text] of expected()) writeFileSync(join(cfgDir, file), text);
  for (const file of readdirSync(cfgDir)) {
    if (!expected().has(file)) rmSync(join(cfgDir, file));
  }
  console.log(`wrote ${expected().size} configs`);
} else if (args[0] === "--list") {
  for (const c of CONFIGS) {
    console.log(`${c.name}\t${c.profile}\t${c.expect === "pass" ? "pass" : `violates ${c.expect}`}`);
  }
} else if (args[0] === "--run") {
  const jar = process.env.TLA2TOOLS;
  if (!jar) {
    console.error("set TLA2TOOLS to the path of tla2tools.jar");
    process.exit(2);
  }
  let bad = 0;
  for (const name of args.slice(1)) {
    const config = CONFIGS.find((c) => c.name === name);
    if (!config) {
      console.error(`no config ${name}`);
      process.exit(2);
    }
    const meta = mkdtempSync(join(tmpdir(), "stream-sync-tlc-"));
    const started = Date.now();
    const run = spawnSync(
      "java",
      [
        `-Xmx${process.env.HEAP ?? "4g"}`,
        "-XX:+UseParallelGC",
        "-cp",
        jar,
        "tlc2.TLC",
        "-workers",
        process.env.WORKERS ?? "4",
        "-deadlock",
        "-noGenerateSpecTE",
        ...(config.simulate
          ? [
              "-simulate",
              `num=${config.simulate.traces}`,
              "-depth",
              String(config.simulate.depth),
              "-seed",
              String(config.simulate.seed),
            ]
          : []),
        "-metadir",
        meta,
        "-config",
        join(cfgDir, `${name}.cfg`),
        join(here, "StreamSync.tla"),
      ],
      { encoding: "utf8", maxBuffer: 1 << 30 },
    );
    rmSync(meta, { recursive: true, force: true });
    const out = `${run.stdout}${run.stderr}`;
    const violated =
      out.match(/Invariant (\w+) is violated/)?.[1] ??
      (out.includes("Temporal properties were violated") ? config.expect : undefined);
    const passed = out.includes("No error has been found");
    const states = out.match(/([\d,]+) distinct states found/g)?.at(-1) ?? "?";
    const depth = out.match(/depth of the complete state graph search is (\d+)/)?.[1] ?? "?";
    const got = passed ? "pass" : violated ? `violates ${violated}` : "error";
    const want = config.expect === "pass" ? "pass" : `violates ${config.expect}`;
    const ok = got === want;
    if (!ok) bad++;
    console.log(
      `${ok ? "ok  " : "FAIL"} ${name}: ${got} (want ${want}); ${states}; depth ${depth}; ${Math.round((Date.now() - started) / 1000)} s`,
    );
    if (!ok) console.log(out.split("\n").slice(-40).join("\n"));
  }
  process.exit(bad ? 1 : 0);
} else {
  let stale = 0;
  for (const [file, text] of expected()) {
    let have = "";
    try {
      have = readFileSync(join(cfgDir, file), "utf8");
    } catch {}
    if (have !== text) {
      console.error(`stale: cfg/${file}`);
      stale++;
    }
  }
  for (const file of readdirSync(cfgDir)) {
    if (!expected().has(file)) {
      console.error(`not in configs.mjs: cfg/${file}`);
      stale++;
    }
  }
  if (stale) {
    console.error("run: node formal/check.mjs --write");
    process.exit(1);
  }
  console.log(`${expected().size} configs match configs.mjs`);
}
