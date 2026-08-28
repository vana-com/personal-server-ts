import { describe, expect, it } from "vitest";
import { ConfinementError, runConfinedScript } from "./index.js";

/**
 * The security contract for the language layer (design §19.7).
 *
 * A measured fact motivates every case here: a script run as plain
 * `node script.js` inside the OS sandbox still holds `require`, `process`,
 * `eval` and the `Function` constructor, so it can read granted files without
 * touching the counters and print a forged coverage line. OS enforcement
 * bounds the process; only this layer bounds the *script*. A new escape is a
 * P0 exactly as a sandbox bypass is.
 */

const noVana = {};

async function run(src: string, vana: unknown = noVana) {
  return runConfinedScript(src, vana);
}

/** Asserts the script was *denied*, not merely unsuccessful. */
async function expectDenied(src: string, vana: unknown = noVana) {
  await expect(run(src, vana)).rejects.toThrow(ConfinementError);
}

describe("confined realm: ambient authority is unreachable", () => {
  it("has no require", async () => {
    await expectDenied(`const fs = require("fs");`);
  });

  it("has no process", async () => {
    await expectDenied(`process.exit(0);`);
  });

  it("has no eval", async () => {
    await expectDenied(`eval("1+1");`);
  });

  it("has no Function constructor by name", async () => {
    await expectDenied(`Function("return 1")();`);
  });

  it("has no globalThis", async () => {
    await expectDenied(`globalThis.foo = 1;`);
  });

  it("has no fetch", async () => {
    await expectDenied(`fetch("https://example.com");`);
  });

  it("has no dynamic import", async () => {
    await expectDenied(`import("node:fs");`);
  });

  it("cannot bind a forbidden name to smuggle it in", async () => {
    await expectDenied(`const process = 1;`);
  });
});

describe("confined realm: the constructor bridge is severed", () => {
  // The canonical escape: every value reaches `Function` through its
  // constructor, and `Function` compiles code in the HOST realm.
  it("blocks .constructor on a function", async () => {
    await expectDenied(`(function(){}).constructor("return process")();`);
  });

  it("blocks .constructor on an object literal", async () => {
    await expectDenied(`({}).constructor;`);
  });

  it("blocks .constructor on a string", async () => {
    await expectDenied(`"".constructor;`);
  });

  it("blocks computed constructor access", async () => {
    await expectDenied(`const k = "constructor"; ({})[k];`);
  });

  it("blocks constructor reached through an array element", async () => {
    await expectDenied(`[1,2,3].map(function(x){ return x; }).constructor;`);
  });

  it("blocks __proto__ read", async () => {
    await expectDenied(`({}).__proto__;`);
  });

  it("blocks prototype read", async () => {
    await expectDenied(`Array.prototype;`);
  });

  it("blocks assignment to __proto__", async () => {
    await expectDenied(`const o = {}; o.__proto__ = {};`);
  });

  it("blocks an object literal declaring __proto__", async () => {
    await expectDenied(`const o = { __proto__: null };`);
  });

  it("blocks constructor access inside a catch block", async () => {
    // A script must not be able to swallow a confinement denial and retry.
    await expectDenied(`try { ({}).constructor; } catch (e) { }`);
  });
});

describe("confined realm: unsupported syntax fails closed", () => {
  it("rejects class declarations", async () => {
    await expectDenied(`class Foo {}`);
  });

  it("rejects with", async () => {
    // `with` is a parse error under acorn's strict-ish default; either way the
    // script must not run.
    await expect(run(`with({}){}`)).rejects.toThrow(ConfinementError);
  });

  it("rejects new on an arbitrary callee", async () => {
    await expectDenied(`new Error.constructor("x");`);
  });

  it("rejects delete", async () => {
    await expectDenied(`const o = {a:1}; delete o.a;`);
  });

  it("reports a parse failure as a confinement error, not a crash", async () => {
    await expect(run(`const = ;`)).rejects.toThrow(ConfinementError);
  });
});

describe("confined realm: legitimate scripts still work", () => {
  it("runs arithmetic and array work", async () => {
    const vana = { out: (v: unknown) => v };
    const r = await runConfinedScript(
      `
      const xs = [1,2,3,4,5];
      const evens = xs.filter((x) => x % 2 === 0);
      const total = evens.reduce((a, b) => a + b, 0);
      return total;
      `,
      vana,
    );
    expect(r).toBe(6);
  });

  it("supports destructuring, template literals and objects", async () => {
    const r = await runConfinedScript(
      `
      const rows = [{day:"a", mins: 60}, {day:"b", mins: 120}];
      let out = "";
      for (const { day, mins } of rows) { out += \`\${day}:\${mins};\`; }
      return out;
      `,
      noVana,
    );
    expect(r).toBe("a:60;b:120;");
  });

  it("awaits host-supplied async functions", async () => {
    const vana = { readAll: async () => [1, 2, 3] };
    const r = await runConfinedScript(
      `const rows = await vana.readAll("s"); return rows.length;`,
      vana,
    );
    expect(r).toBe(3);
  });

  it("supports try/catch for ordinary script errors", async () => {
    const r = await runConfinedScript(
      `try { throw new Error("boom"); } catch (e) { return "caught"; }`,
      noVana,
    );
    expect(r).toBe("caught");
  });

  it("supports function declarations and recursion", async () => {
    const r = await runConfinedScript(
      `function fib(n){ return n < 2 ? n : fib(n-1) + fib(n-2); } return fib(10);`,
      noVana,
    );
    expect(r).toBe(55);
  });

  it("routes console.log to the host, not to stdout", async () => {
    const seen: string[] = [];
    await runConfinedScript(`console.log("hello", 42);`, noVana, {
      onConsole: (m) => seen.push(m),
    });
    expect(seen).toEqual(["hello 42"]);
  });
});

describe("confined realm: runaway scripts are bounded", () => {
  it("stops an infinite loop at the step budget", async () => {
    await expect(
      runConfinedScript(`while (true) { }`, noVana, { maxSteps: 10_000 }),
    ).rejects.toThrow(/evaluation steps/);
  });
});
