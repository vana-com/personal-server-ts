import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { runVector, type Vector } from "./vector-runner.js";

const dir = join(dirname(fileURLToPath(import.meta.url)), "vectors");
const files = readdirSync(dir)
  .filter((name) => name.endsWith(".json"))
  .sort();

describe("account-mode vectors against the real module", () => {
  it("ships vectors 1 to 12 plus the new-owner, first-launch and Off-save vectors", () => {
    expect(files).toHaveLength(17);
  });

  for (const file of files) {
    const vector = JSON.parse(readFileSync(join(dir, file), "utf8")) as Vector;
    it(`vector ${vector.id}`, async () => {
      expect(await runVector(vector)).toEqual([]);
    });
  }
});
