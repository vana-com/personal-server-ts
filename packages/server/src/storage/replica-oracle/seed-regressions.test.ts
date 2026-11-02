/**
 * Minimized nightly seeds, originally collected on PR #486 (head 1c5a3b1b).
 * Reset-gap blob reads and cross-connection pending-byte delivery add coverage
 * for the later nightly failures. The latter also withdraws its carrier;
 * another vector supplies a retained Node record from another connection.
 * Replay through every port, including a fresh replay of accepted history.
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
