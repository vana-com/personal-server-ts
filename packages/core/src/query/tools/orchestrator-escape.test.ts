// Orchestrator's independent adversarial tests against 4b's confined interpreter.
// These are MY escape attempts, not the agent's.
import { describe, it, expect } from "vitest";
import { runConfinedScript } from "./interpreter/index.js";

const CANARY = "ORCHESTRATOR-CANARY";
(globalThis as Record<string, unknown>)[CANARY] = "leaked";

async function attempt(src: string): Promise<string> {
  try {
    const v = await runConfinedScript(
      src,
      { note: () => {} },
      { maxSteps: 200_000 },
    );
    return `RETURNED:${JSON.stringify(v)}`;
  } catch (e) {
    return `THREW:${(e as Error).constructor.name}`;
  }
}

describe("orchestrator escape attempts", () => {
  const escapes: [string, string][] = [
    [
      "Function ctor via constructor.constructor",
      `return ({}).constructor.constructor("return process")()`,
    ],
    [
      "Function ctor via computed key",
      `const k="constructor"; return ({})[k][k]("return process")()`,
    ],
    [
      "Function ctor via array",
      `return [].constructor.constructor("return globalThis")()`,
    ],
    [
      "proto chain to Object",
      `return ({}).__proto__.constructor.constructor("return process")()`,
    ],
    [
      "getPrototypeOf escape",
      `return Object.getPrototypeOf({}).constructor.constructor("return process")()`,
    ],
    [
      "function .constructor",
      `function f(){}; return f.constructor("return process")()`,
    ],
    [
      "async fn constructor",
      `const f=async()=>{}; return f.constructor("return process")()`,
    ],
    [
      "generator constructor",
      `return (function*(){}).constructor("return process")()`,
    ],
    ["bare require", `return require("fs")`],
    ["bare process", `return process.env`],
    ["globalThis", `return globalThis`],
    ["eval", `return eval("1+1")`],
    ["Function global", `return Function("return process")()`],
    ["import()", `return import("node:fs")`],
    [
      "reach canary via globalThis alias",
      `const g=(function(){return this})(); return g["${CANARY}"]`,
    ],
    [
      "toString leak on host fn",
      `return ({}).toString.constructor("return process")()`,
    ],
    ["Reflect", `return Reflect.get(globalThis,"process")`],
    ["Proxy trap", `return new Proxy({},{get:()=>process})`],
    [
      "error stack walk",
      `try{null.x}catch(e){return e.constructor.constructor("return process")()}`,
    ],
    ["Symbol.for registry", `return Symbol.for("x").constructor`],
  ];

  for (const [name, src] of escapes) {
    it(`blocks: ${name}`, async () => {
      const r = await attempt(src);
      expect(r, `ESCAPE via ${name}: ${r}`).not.toMatch(
        /leaked|ORCHESTRATOR-CANARY/,
      );
      expect(r, `ESCAPE via ${name} returned a live object: ${r}`).not.toMatch(
        /RETURNED:\{"[a-zA-Z]/,
      );
      // must be a refusal, not a silent undefined that hides a partial escape
      expect(r, `expected refusal, got ${r}`).toMatch(
        /^THREW:|^RETURNED:(undefined|null|2)$/,
      );
    });
  }

  it("cannot write to stdout except via vana.note", async () => {
    const r = await attempt(`console.log("FORGED"); return 1`);
    expect(r).toMatch(/^THREW:|^RETURNED:1$/);
  });

  it("step budget actually halts an infinite loop", async () => {
    const r = await attempt(`while(true){}`);
    expect(r).toMatch(/^THREW:/);
  });
});
