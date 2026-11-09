/**
 * One scenario per process (lane P3). Run as:
 *   node --expose-gc --import tsx stream-sync-heap-child.ts '<json options>'
 * Prints one JSON line: the RunReport (no record bodies).
 */
import { rmSync } from "node:fs";
import { runScenario, type RunOptions } from "./stream-sync-heap-node.js";
import type { ScenarioSpec } from "./stream-sync-heap-scenarios.js";

interface ChildInput extends RunOptions {
  readonly spec: ScenarioSpec;
}

const input = JSON.parse(process.argv[2] ?? "{}") as ChildInput;
const { spec, ...options } = input;
const report = await runScenario(spec, options);
rmSync(options.dir, { recursive: true, force: true });
process.stdout.write(`${JSON.stringify(report)}\n`);
