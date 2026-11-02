/**
 * The 22 minimized seeds from the nightly oracle run on PR #486 (head
 * 1c5a3b1b). Each failed before the fixes in this branch and replays clean
 * now, through every port with a fresh replay of the accepted history.
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { runCommands } from "./runner.test-utils.js";

const seeds = JSON.parse(
  readFileSync(new URL("seed-regressions.json", import.meta.url), "utf8"),
) as Record<string, Parameters<typeof runCommands>[0]>;

describe("minimized nightly seeds", () => {
  for (const [seed, commands] of Object.entries(seeds))
    it(`seed ${seed}`, async () => {
      expect(await runCommands(commands, { freshReplay: true })).toEqual([]);
    }, 120_000);
});
