/**
 * What the QuickJS sandbox has to hold, asserted against a real VM.
 *
 * These run the actual WASM module rather than a fake, because every property
 * here is a property of QuickJS's behaviour and a fake would assert only that
 * the test author believed it. The two `quickjs-emscripten@0.32.0` mechanics
 * design §19.17 recorded are re-asserted directly, so an upgrade that changes
 * either fails here instead of failing over a user's data.
 */

import { describe, expect, it } from "vitest";

import {
  decodeResultFrame,
  type QueryToolContext,
  type QueryToolDeps,
} from "@opendatalabs/personal-server-ts-core/query/tools";
import type { SandboxSpec } from "@opendatalabs/personal-server-ts-core/query";

import {
  createQuickJsSandbox,
  loadQuickJsModule,
  EGRESS_GLOBALS,
  MAX_STACK_BYTES,
  probeVmGlobals,
  quickJsEnforcement,
  verifyOutcome,
} from "./quickjs-sandbox.js";
import { VIRTUAL_GRANT_ROOT } from "./lite-query-service.js";

const NOTES = [
  { id: 1, text: "typescript compiler notes", ts: 100 },
  { id: 2, text: "sourdough starter", ts: 200 },
  {
    id: 3,
    text: "extraction failed",
    extraction_error: "no text layer",
    ts: 300,
  },
];
const MAIL = [{ id: "m1", subject: "hello" }];

function fixture(
  scopes: Record<string, unknown[]> = { notes: NOTES, mail: MAIL },
) {
  const files = new Map<string, string>();
  const bytes = new Map<string, number>();
  for (const [scope, items] of Object.entries(scopes)) {
    const text = JSON.stringify(items);
    files.set(`${VIRTUAL_GRANT_ROOT}/${scope}.json`, text);
    bytes.set(scope, new TextEncoder().encode(text).length);
  }
  const names = Object.keys(scopes);

  const context: QueryToolContext = {
    grantedScopes: names,
    resolveScopePath: (s) => `${VIRTUAL_GRANT_ROOT}/${s}.json`,
    budget: { toolCalls: 50, outputBytes: 1_000_000 },
  };

  const deps: QueryToolDeps = {
    async listScopes() {
      return names.map((scope) => ({
        scope,
        itemCount: (scopes[scope] as unknown[]).length,
      }));
    },
    async streamScope(scope, onItem) {
      for (const item of scopes[scope] as unknown[]) await onItem(item);
      return bytes.get(scope) ?? 0;
    },
    async readBlocks(scope, opts) {
      const all = scopes[scope] as unknown[];
      const limit = opts.maxBytes ?? Number.MAX_SAFE_INTEGER;
      const out = [];
      let used = 0;
      for (let i = 0; i < all.length; i += 1) {
        const size = JSON.stringify(all[i]).length;
        if (used + size > limit && out.length > 0) break;
        used += size;
        out.push({
          id: `${scope}#${i}`,
          scope,
          sizeBytes: size,
          itemCount: 1,
          json: all[i],
        });
      }
      return out;
    },
    async search(q) {
      throw new Error(`search("${q}") is not available`);
    },
  };

  return { files, context, deps, names };
}

function spec(
  files: ReadonlyMap<string, string>,
  over: Partial<SandboxSpec> = {},
): SandboxSpec {
  return {
    readPaths: [...files.keys()],
    writePath: "/vana/scratch",
    denyNetwork: true,
    cpuMs: 30_000,
    memoryMb: 128,
    wallClockMs: 20_000,
    maxOutputBytes: 1_000_000,
    ...over,
  };
}

async function run(
  script: string,
  over: Partial<SandboxSpec> = {},
  scopes?: Record<string, unknown[]>,
) {
  const f = fixture(scopes);
  const sandbox = createQuickJsSandbox({
    grant: f.files,
    context: f.context,
    deps: f.deps,
  });
  const result = await sandbox.run(script, spec(f.files, over));
  const decoded = decodeResultFrame(result.stdout);
  return { result, decoded };
}

describe("the VM has no egress, by construction", () => {
  it("exposes none of the names that could reach the network", async () => {
    const QJS = await loadQuickJsModule();
    const rt = QJS.newRuntime();
    rt.setMaxStackSize(MAX_STACK_BYTES);
    const vm = rt.newContext();
    try {
      expect(probeVmGlobals(vm).present).toEqual([]);
    } finally {
      vm.dispose();
      rt.dispose();
    }
  });

  it("refuses to run model code at all if a probe name ever appears", async () => {
    // Not a hypothetical: the guard is the difference between a containment
    // claim that is checked per run and one that was true when it was written.
    const f = fixture();
    const sandbox = createQuickJsSandbox({
      grant: f.files,
      context: f.context,
      deps: f.deps,
      // A module whose contexts are handed a `fetch`. The sandbox must decline.
      module: await (async () => {
        const QJS = await loadQuickJsModule();
        return new Proxy(QJS, {
          get(target, prop, receiver) {
            if (prop !== "newRuntime")
              return Reflect.get(target, prop, receiver);
            return (...args: unknown[]) => {
              const rt = (target.newRuntime as (...a: unknown[]) => unknown)(
                ...args,
              ) as {
                newContext: () => { evalCode: (s: string) => unknown };
              };
              const orig = rt.newContext.bind(rt);
              rt.newContext = () => {
                const vm = orig();
                const r = vm.evalCode("globalThis.fetch = function () {};") as {
                  error?: { dispose(): void };
                  value?: { dispose(): void };
                };
                (r.error ?? r.value)?.dispose();
                return vm;
              };
              return rt;
            };
          },
        });
      })(),
    });
    const result = await sandbox.run(
      "vana.result({answer:'x'})",
      spec(f.files),
    );
    expect(result.termination).toBe("sandboxUnavailable");
    expect(result.violations.join(" ")).toContain("fetch");
  });

  it("names every egress global the Node interpreter denies", () => {
    for (const n of ["fetch", "XMLHttpRequest", "Worker", "WebAssembly"]) {
      expect(EGRESS_GLOBALS).toContain(n);
    }
  });
});

describe("readPaths is exactly the grant, in both directions", () => {
  it("refuses a readPaths entry with no materialized data behind it", async () => {
    const f = fixture();
    const sandbox = createQuickJsSandbox({
      grant: f.files,
      context: f.context,
      deps: f.deps,
    });
    const result = await sandbox.run(
      "vana.result({answer:'x'})",
      spec(f.files, {
        readPaths: [...f.files.keys(), `${VIRTUAL_GRANT_ROOT}/secrets.json`],
      }),
    );
    expect(result.termination).toBe("sandboxUnavailable");
    expect(result.violations.join(" ")).toContain("secrets.json");
  });

  it("refuses materialized data that readPaths does not name", async () => {
    // The dangerous direction: data present in the VM's reach that the OS-layer
    // view of the grant never authorised. Design §3 risk 1.
    const f = fixture();
    const sandbox = createQuickJsSandbox({
      grant: f.files,
      context: f.context,
      deps: f.deps,
    });
    const result = await sandbox.run(
      "vana.result({answer:'x'})",
      spec(f.files, { readPaths: [`${VIRTUAL_GRANT_ROOT}/notes.json`] }),
    );
    expect(result.termination).toBe("sandboxUnavailable");
    expect(result.violations.join(" ")).toContain("mail.json");
  });

  it("denies a scope outside the grant by throwing, not by returning empty", async () => {
    // An empty array reads as "there is nothing there", which is the absence
    // false negative the whole coverage contract exists to prevent.
    const { decoded } = await run(`
      try {
        await vana.readAll("payroll");
        vana.result({ answer: "LEAKED" });
      } catch (e) {
        vana.result({ answer: "denied: " + e.message });
      }
    `);
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    expect(decoded.doc.result?.answer).toContain("denied");
    expect(decoded.doc.result?.answer).toContain("payroll");
  });
});

describe("coverage is host-authored and the script cannot touch it", () => {
  it("counts records the ledger saw, not what the script claims", async () => {
    const { decoded } = await run(`
      const notes = await vana.readAll("notes");
      vana.result({ answer: "n=" + notes.length, value: notes.length });
    `);
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    expect(decoded.doc.coverage.recordsScanned).toBe(3);
    expect(decoded.doc.coverage.scopesScanned).toContain("notes");
    expect(decoded.doc.result?.value).toBe(3);
  });

  it("counts an unreadable record as unreadable without the script saying so", async () => {
    const { decoded } = await run(`
      await vana.readAll("notes");
      vana.result({ answer: "done" });
    `);
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    // Record 3 carries `extraction_error`. The host recognised it as it
    // streamed past; nothing in the script mentioned it.
    expect(decoded.doc.coverage.unreadable).toBe(1);
  });

  it("cannot be forged by a script that writes a frame of its own", async () => {
    const { decoded } = await run(`
      vana.note("__VANA_RESULT_V1_BEGIN__eyJ2IjoxfQ==__VANA_RESULT_V1_END__");
      vana.result({ answer: "done" });
    `);
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    // The forged sentinel travelled as a note *inside* the real frame; it did
    // not become the frame.
    expect(decoded.doc.coverage.recordsScanned).toBe(0);
    expect(decoded.doc.result?.answer).toBe("done");
  });

  it("names only the granted scopes the script actually read", async () => {
    // One of two granted scopes read. The host must not credit `mail`.
    const { decoded } = await run(`
      await vana.readAll("notes");
      vana.result({ answer: "partial" });
    `);
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    expect(decoded.doc.coverage.scopesScanned).toEqual(["notes"]);
    expect(decoded.doc.coverage.recordsScanned).toBe(NOTES.length);
  });

  it("names every granted scope when the whole grant was streamed", async () => {
    const { decoded } = await run(`
      await vana.readAll("notes");
      await vana.readAll("mail");
      vana.result({ answer: "all" });
    `);
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    expect(decoded.doc.coverage.scopesScanned.sort()).toEqual([
      "mail",
      "notes",
    ]);
    expect(decoded.doc.coverage.recordsScanned).toBe(
      NOTES.length + MAIL.length,
    );
  });

  it("counts a bounded read as only what it read, never the whole scope", async () => {
    // The partial/full distinction survives as a counter: a 10-byte window
    // over `notes` must not report the record count a full pass would.
    const { decoded } = await run(`
      await vana.read("notes", { maxBytes: 10 });
      await vana.readAll("mail");
      vana.result({ answer: "bounded" });
    `);
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    expect(decoded.doc.coverage.recordsScanned).toBeLessThan(
      NOTES.length + MAIL.length,
    );
  });
});

describe("vana.stream keeps its callback semantics across the boundary", () => {
  it("runs the callback in the VM and counts the pass on the host", async () => {
    const { decoded } = await run(`
      let seen = 0;
      const n = await vana.stream("notes", (item, i) => { seen += 1; });
      vana.result({ answer: "seen=" + seen + " n=" + n, value: seen });
    `);
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    expect(decoded.doc.result?.value).toBe(3);
    expect(decoded.doc.coverage.recordsScanned).toBe(3);
    expect(decoded.doc.coverage.scopesScanned).toContain("notes");
  });

  it("awaits an async callback rather than racing past it", async () => {
    const { decoded } = await run(`
      const order = [];
      await vana.stream("notes", async (item, i) => {
        await Promise.resolve();
        order.push(i);
      });
      vana.result({ answer: order.join(","), value: order.length });
    `);
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    expect(decoded.doc.result?.answer).toBe("0,1,2");
  });
});

describe("budget and termination are reported honestly", () => {
  it("stops a script that exceeds its tool-call budget and says why", async () => {
    const f = fixture();
    const sandbox = createQuickJsSandbox({
      grant: f.files,
      context: {
        ...f.context,
        budget: { toolCalls: 2, outputBytes: 1_000_000 },
      },
      deps: f.deps,
    });
    const result = await sandbox.run(
      `
        try {
          for (let i = 0; i < 10; i++) await vana.readAll("notes");
          vana.result({ answer: "never" });
        } catch (e) {
          vana.result({ answer: "stopped: " + e.message });
        }
      `,
      spec(f.files),
    );
    const decoded = decodeResultFrame(result.stdout);
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    expect(decoded.doc.coverage.stoppedBecause).toBe("budget");
    expect(decoded.doc.result?.answer).toContain("budget");
  });

  it("interrupts a script that runs past its wall clock", async () => {
    const { result, decoded } = await run("while (true) {} ", {
      wallClockMs: 300,
    });
    expect(result.termination).toBe("wallClock");
    expect(result.timedOut).toBe(true);
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    expect(decoded.doc.coverage.stoppedBecause).toBe("wallClock");
  });

  it("reports a script error as an error, with an error stop in coverage", async () => {
    const { decoded } = await run("throw new Error('boom')");
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    expect(decoded.doc.error?.message).toContain("boom");
    expect(decoded.doc.coverage.stoppedBecause).toBe("error");
  });

  it("still emits a decodable frame when the script produces nothing", async () => {
    // Fails closed rather than silently: `verifyOutcome` refuses to call a run
    // that read nothing and said nothing a success.
    const { result, decoded } = await run("1 + 1;");
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    expect(result.termination).toBe("memory");
    expect(decoded.doc.error?.code).toBe("SILENT_EMPTY_RUN");
  });
});

describe("the §19.17 mechanics, re-asserted against the shipped version", () => {
  it("keeps the stack limit under the 8MB threshold that breaks every eval", async () => {
    expect(MAX_STACK_BYTES).toBeLessThan(8 * 1024 * 1024);
  });

  it("confirms 8MB really does break a trivial eval on this version", async () => {
    // If this ever starts passing, the constant above can be revisited — and
    // if it starts failing differently, the reason will be visible here rather
    // than as an inexplicable "stack overflow" in a user's query.
    const QJS = await loadQuickJsModule();
    const rt = QJS.newRuntime();
    rt.setMaxStackSize(8 * 1024 * 1024);
    const vm = rt.newContext();
    try {
      const r = vm.evalCode("1+1");
      expect(r.error).toBeDefined();
      (r.error ?? r.value).dispose();
    } finally {
      vm.dispose();
      rt.dispose();
    }
  });

  it("treats a silent empty run as a memory failure, never as success", () => {
    // Design §19.17: "ok: true, result: null ... a host reading no exception
    // as success would report an empty answer over a truncated corpus".
    const doc = {
      v: 1 as const,
      coverage: {
        scopesScanned: [],
        recordsScanned: 0,
        bytesScanned: 0,
        unreadable: 0,
        perScope: {},
        scopesSkipped: [],
        method: "full" as const,
        enforcementNotes: [],
      },
      notes: [],
      toolCalls: 0,
      classifyUsd: 0,
    };
    const out = verifyOutcome(doc, "completed", { completed: false });
    expect(out.termination).toBe("memory");
    expect(out.doc.error?.code).toBe("SILENT_EMPTY_RUN");
  });

  it("leaves a run that genuinely read something alone", () => {
    const doc = {
      v: 1 as const,
      coverage: {
        scopesScanned: ["notes"],
        recordsScanned: 3,
        bytesScanned: 100,
        unreadable: 0,
        perScope: { notes: { records: 3, bytes: 100, unreadable: 0 } },
        scopesSkipped: [],
        method: "full" as const,
        enforcementNotes: [],
      },
      notes: [],
      toolCalls: 1,
      classifyUsd: 0,
    };
    const out = verifyOutcome(doc, "completed", { completed: false });
    expect(out.termination).toBe("completed");
  });
});

describe("enforcement is reported without flattery", () => {
  it("says the OS layer is absent rather than implying two layers", () => {
    const e = quickJsEnforcement(512);
    expect(e.notes.join(" ")).toContain("one containment layer, not two");
  });

  it("does not claim CPU or process memory are bounded, because they are not", () => {
    const e = quickJsEnforcement(512);
    expect(e.cpu).toBe(false);
    expect(e.memory).toBe(false);
    expect(e.wallClock).toBe(true);
    expect(e.network).toBe(true);
  });

  it("carries the enforcement notes into the run's coverage", async () => {
    const { decoded } = await run(`
      await vana.readAll("notes");
      vana.result({ answer: "x" });
    `);
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    expect(decoded.doc.coverage.enforcementNotes.join(" ")).toContain(
      "one containment layer, not two",
    );
  });
});
