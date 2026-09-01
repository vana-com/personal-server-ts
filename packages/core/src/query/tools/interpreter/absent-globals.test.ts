import { describe, expect, it } from "vitest";

import { runConfinedScript } from "./index.js";
import { DELIBERATELY_ABSENT } from "./realm.js";

/**
 * Globals we withhold on purpose say so, and name the substitute.
 *
 * The model gets exactly one repair attempt. Spending it working out that
 * `Intl` is absent by design rather than by accident wastes the only correction
 * the contract allows.
 */
async function reason(src: string): Promise<string> {
  try {
    await runConfinedScript(src, { note: () => {} }, { maxSteps: 50_000 });
    return "NO ERROR";
  } catch (e) {
    return (e as Error).message;
  }
}

describe("deliberately absent globals explain themselves", () => {
  it("names Intl and tells the script what to do instead", async () => {
    const msg = await reason(`return Intl.NumberFormat().format(1234.5)`);
    expect(msg).toContain("Intl");
    expect(msg).toMatch(/locale/i);
    expect(msg).toMatch(/toFixed/);
  });

  it("still refuses Intl — it is not merely undocumented", async () => {
    // Intl is excluded on measured grounds: the same script formatting the
    // same values yields "1,234.5"/"1969-12-31" on one host and
    // "1.234,5"/"1.1.1970" on another, purely from ambient locale and
    // timezone. Scripts here bucket and join on dates, so that would inject
    // invisible nondeterminism into exactly the numbers being measured.
    for (const src of [
      `return Intl.DateTimeFormat().format(new Date(0))`,
      `const f = Intl; return typeof f`,
    ]) {
      expect(await reason(src)).toContain("not defined");
    }
  });

  it("keeps the guidance actionable for every entry", async () => {
    for (const [name, guidance] of DELIBERATELY_ABSENT) {
      const msg = await reason(`return ${name}`);
      expect(msg, `${name} should explain itself`).toContain(guidance);
    }
  });

  it("leaves ordinary unknown identifiers with the plain message", async () => {
    const msg = await reason(`return someTypoedHelper()`);
    expect(msg).toBe("someTypoedHelper is not defined");
  });

  it("does not accidentally expose a deliberately absent global", async () => {
    for (const name of DELIBERATELY_ABSENT.keys()) {
      expect(await reason(`return typeof ${name}`)).toContain("not defined");
    }
  });
});
