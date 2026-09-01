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

describe("confined realm: reflection cannot walk around the key guard", () => {
  /**
   * The key guard in `readMember` only sees the *string* a script writes. The
   * reflection API returns the same objects without ever being asked for a
   * guarded name: `getOwnPropertyDescriptor(proto, "constructor").value` hands
   * back `Function` under the key `value`, and `getPrototypeOf` hands back a
   * prototype without anyone typing `prototype`. Measured before the fix:
   * these reached the real host `process`, `fs.readFileSync` and
   * `process.stdout.write`, which is a forged-coverage primitive.
   *
   * These cases are about the *route*, so each asserts denial rather than a
   * particular value — a route that returns `undefined` would still be a
   * silent partial escape.
   */
  it("blocks getPrototypeOf", async () => {
    await expectDenied(`return Object.getPrototypeOf({});`);
  });

  it("blocks the descriptor bridge to Function", async () => {
    await expectDenied(
      `const proto = Object.getPrototypeOf(Math.max);
       const d = Object.getOwnPropertyDescriptor(proto, "constructor");
       return d.value("return process")();`,
    );
  });

  it("blocks the Object.values(descriptor) variant of the same bridge", async () => {
    await expectDenied(
      `const proto = Object.getPrototypeOf(Math.max);
       const d = Object.getOwnPropertyDescriptor(proto, "constructor");
       return Object.values(d)[0]("return process")();`,
    );
  });

  it("blocks the Object.entries(descriptor) variant", async () => {
    await expectDenied(
      `const proto = Object.getPrototypeOf(Math.max);
       const d = Object.getOwnPropertyDescriptor(proto, "constructor");
       return Object.entries(d)[0][1]("return process")();`,
    );
  });

  it("blocks getOwnPropertyDescriptors", async () => {
    await expectDenied(
      `return Object.getOwnPropertyDescriptors(Object.getPrototypeOf(Math.max));`,
    );
  });

  it("blocks getOwnPropertyNames", async () => {
    await expectDenied(`return Object.getOwnPropertyNames(Object);`);
  });

  it("blocks setPrototypeOf", async () => {
    await expectDenied(
      `const o = {}; Object.setPrototypeOf(o, { pwned: 7 }); return o.pwned;`,
    );
  });

  it("blocks Object.create", async () => {
    await expectDenied(`return Object.create({ inherited: 5 }).inherited;`);
  });

  it("blocks defineProperty", async () => {
    await expectDenied(
      `Object.defineProperty({}, "x", { value: 1 }); return 1;`,
    );
  });

  it("does not let a script mutate the host's Array.prototype", async () => {
    // The second variant needs no `Function` at all: the runner's own ledger
    // and its `JSON.stringify` path run on the same `Array.prototype` the
    // script would be redefining. The probe below writes a novel key rather
    // than `map` only so that a *failing* run leaves the test process
    // diagnosable — redefining `map` succeeded before the fix and took the
    // test runner's own serializer down with it.
    await expectDenied(
      `const ap = Object.getPrototypeOf([]);
       Object.defineProperty(ap, "__pwned__", { value: 42, configurable: true });
       return 1;`,
    );
    expect(
      (Array.prototype as unknown as Record<string, unknown>).__pwned__,
    ).toBeUndefined();
    expect([1, 2].map((x) => x)).toEqual([1, 2]);
  });

  it("blocks reflection reached through every other bound intrinsic", async () => {
    // The escape is a property of handing out live host objects, not of
    // `Object` specifically. Whatever else the realm binds must not become a
    // second doorway to the same prototypes.
    const roots = [
      `Array.from([1])`,
      `"x"`,
      `(5)`,
      `Promise.resolve(1)`,
      `new Map()`,
      `new Set()`,
      `new Date()`,
      `/x/`,
      `new Error("e")`,
      `JSON`,
      `Math`,
    ];
    for (const root of roots) {
      await expectDenied(`return Object.getPrototypeOf(${root});`);
    }
  });

  it("does not let one script poison the realm for the next", async () => {
    // The shims are process-wide singletons, so a mutable one would carry a
    // redefinition across runs — the same shape of bug as prototype pollution,
    // one level up.
    await expect(
      run(`Array.isArray = function(){ return true }; return 1;`),
    ).rejects.toThrow(TypeError);
    const r = await runConfinedScript(
      `return Array.isArray("not an array");`,
      noVana,
    );
    expect(r).toBe(false);
  });

  it("keeps the intrinsics themselves out of reach as values", async () => {
    // Even naming a host constructor as a value is a foothold: it is the thing
    // every descriptor route was trying to obtain.
    await expectDenied(`return Object.getPrototypeOf(Object);`);
  });
});

describe("confined realm: the Object statics real scripts use still work", () => {
  // §19.16 and the real-data benchmark show model-authored code reaching for
  // these constantly. Removing them would be a regression, not a hardening.
  it("supports keys, values, entries, assign and fromEntries", async () => {
    const r = await runConfinedScript(
      `const o = { a: 1, b: 2 };
       const merged = Object.assign({}, o, { c: 3 });
       const round = Object.fromEntries(
         Object.entries(merged).map(([k, v]) => [k, v * 2]),
       );
       return [
         Object.keys(o).join(","),
         Object.values(o).join(","),
         Object.keys(merged).length,
         JSON.stringify(round),
       ].join("|");`,
      noVana,
    );
    expect(r).toBe(`a,b|1,2|3|{"a":2,"b":4,"c":6}`);
  });

  it("groups records the way a real script does", async () => {
    const r = await runConfinedScript(
      `const rows = [
         { day: "mon", mins: 30 },
         { day: "tue", mins: 45 },
         { day: "mon", mins: 15 },
       ];
       const byDay = {};
       for (const row of rows) {
         byDay[row.day] = (byDay[row.day] || 0) + row.mins;
       }
       return Object.entries(byDay)
         .sort((a, b) => b[1] - a[1])
         .map(([day, mins]) => day + "=" + mins)
         .join(",");`,
      noVana,
    );
    expect(r).toBe("mon=45,tue=45");
  });

  it("supports Object.freeze and Object.is", async () => {
    const r = await runConfinedScript(
      `const o = Object.freeze({ a: 1 });
       return Object.is(o.a, 1) && Object.keys(o).length === 1;`,
      noVana,
    );
    expect(r).toBe(true);
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
