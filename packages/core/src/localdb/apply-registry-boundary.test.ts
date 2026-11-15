import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, it } from "vitest";

// Apply must read the registry itself: its answers reflect reads taken after
// the call began. A caller that wraps the registry and hands apply a listing
// taken earlier breaks that, so no localdb source may override the listing.
it("no localdb source overrides the registry's stream listing", () => {
  const dir = dirname(fileURLToPath(import.meta.url));
  const offenders = readdirSync(dir)
    .filter((name) => name.endsWith(".ts") && !name.endsWith(".test.ts"))
    .filter((name) =>
      /\blistStreamRows\s*:/.test(readFileSync(join(dir, name), "utf8")),
    );
  expect(offenders).toEqual([]);
});
