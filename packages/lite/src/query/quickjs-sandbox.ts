/**
 * PS-Lite's implementation of the query-layer {@link Sandbox}, on QuickJS-WASM.
 *
 * The Node path (`packages/server/src/query/node-sandbox.ts`) nests two
 * layers: an OS sandbox around a Node process, and inside it a hand-written
 * AST interpreter, because a Node process handed model code can `require('fs')`
 * straight past the injected API. Design §19.7 requires both because neither
 * suffices alone.
 *
 * **Lite cannot have the OS layer at all** (design §4's table marks it
 * "impossible" on a browser runtime), so the layer that replaces it has to
 * carry the containment by itself. QuickJS-WASM does, and it does it
 * structurally rather than by enumeration: the VM is a separate heap reached
 * only through host functions we inject by hand. Nothing else crosses.
 * Measured, not assumed — see {@link probeVmGlobals} and the
 * `quickjs-sandbox.egress.test.ts` suite: `fetch`, `XMLHttpRequest`, `Worker`,
 * `WebAssembly`, `require`, `process`, `importScripts` and `eval`-to-network
 * are all absent from the VM because they were never created there, not
 * because a name list rejects them.
 *
 * ## Why the model's code runs natively here, and not under the interpreter
 *
 * It would be tempting to keep the Node arrangement and run the confined
 * interpreter *inside* QuickJS, for three layers instead of two. Design
 * §19.17's measurements rule it out: the interpreter costs 20.9x native and
 * QuickJS costs 9.3x, so nesting them is ~195x — roughly 8 seconds for a
 * single script over the `dogfood` corpus, against 42 ms native. That is not a
 * safety margin, it is an unusable product.
 *
 * Running model code natively on QuickJS is sound *because* QuickJS is not
 * Node. The interpreter exists to deny `require`/`process`/`globalThis` inside
 * a realm that has them. This VM has none of them to deny. What the
 * interpreter provides by enumeration, the VM boundary provides by
 * construction.
 *
 * ## The coverage ledger never enters the VM
 *
 * `createVanaApi` (host-authored, `packages/core`) stays on the *host* side of
 * the boundary, exactly as prompt contract §1 requires. The VM gets a `vana`
 * prelude that does nothing but marshal calls across; every counter is
 * incremented in a heap the model's code cannot address. The Node path has to
 * encode the ledger into a base64 frame to get it out of a subprocess it does
 * not share memory with; here the ledger is simply already on the right side.
 * The frame is still emitted, because `decodeResultFrame` fails closed and the
 * rest of the stack reads that contract.
 *
 * ## Two `quickjs-emscripten@0.32.0` mechanics that bite
 *
 * Both are recorded in design §19.17 and both are re-asserted by tests here,
 * because neither is documented upstream:
 *
 * - `setMaxStackSize` at 8 MB or more makes **every** `evalCode` fail with a
 *   spurious `stack overflow`, including `1+1`. {@link MAX_STACK_BYTES} is 1 MB.
 * - A host function that *returns* `vm.newError(...)` does **not** throw
 *   inside the VM; it returns the error object as an ordinary value. Every
 *   denial here uses the `{ error }` result form. A run of this file's
 *   predecessor spike read a path outside its grant and printed `LEAK`
 *   because of exactly this.
 *
 * And the failure §19.17 says must never be trusted: at a memory limit too
 * small for the corpus, a QuickJS run can end with **no exception raised and a
 * null result**. A host that reads "no error" as success reports an empty
 * answer over a truncated corpus — the silent-wrongness failure this whole
 * layer exists to prevent. {@link verifyOutcome} therefore checks the result
 * frame positively and treats "no error, no frame" as a memory termination,
 * never as a completed run.
 */

import { newQuickJSWASMModuleFromVariant } from "quickjs-emscripten-core";
import singleFileBrowserReleaseSync from "@jitl/quickjs-singlefile-browser-release-sync";
import type {
  QuickJSContext,
  QuickJSHandle,
  QuickJSRuntime,
  QuickJSWASMModule,
} from "quickjs-emscripten-core";

import {
  boundRunDocument,
  createVanaApi,
  encodeResultFrame,
  QueryToolError,
  ScriptCompleted,
  type CoverageCounters,
  type QueryToolContext,
  type QueryToolDeps,
  type RunDocument,
  type ScriptResult,
} from "@opendatalabs/personal-server-ts-core/query/tools";
import type {
  Sandbox,
  SandboxEnforcement,
  SandboxResult,
  SandboxSpec,
  SandboxTermination,
} from "@opendatalabs/personal-server-ts-core/query";

/**
 * The VM's own stack ceiling.
 *
 * Design §19.17: at 8 MB and above the requested limit exceeds the WASM stack
 * region and QuickJS answers *every* eval with `SyntaxError: stack overflow`.
 * 1 MB is comfortably inside the working range (0–4 MB measured good) and
 * still deep enough for the recursive walks a model writes over nested JSON.
 */
export const MAX_STACK_BYTES = 1024 * 1024;

/** Ceiling on one `vana.note` line, so a chatty script cannot exhaust the heap. */
const MAX_NOTE_CHARS = 4000;

export interface QuickJsSandboxOptions {
  /**
   * The materialized grant: virtual path -> the scope's records as JSON text.
   *
   * This map is the *entire* universe the run can reach. There is no
   * filesystem behind it and no fallback lookup: a path absent from this map
   * does not resolve to an empty result, it throws inside the VM. That is the
   * browser's equivalent of the Node path's per-request scratch directory —
   * containment by there being nothing else to read, not by a policy that
   * could be computed wrong (design §3 risk 1).
   */
  readonly grant: ReadonlyMap<string, string>;
  /** Per-run `vana` context: granted scopes, budget, caller. */
  readonly context: QueryToolContext;
  /** Per-run data access. In Lite these are served from memory. */
  readonly deps: QueryToolDeps;
  /** Test seam: inject a pre-loaded module rather than loading the WASM. */
  readonly module?: QuickJSWASMModule;
}

let sharedModule: Promise<QuickJSWASMModule> | undefined;

/**
 * Load the QuickJS WASM module once per page.
 *
 * Two choices are baked in here, and both were forced by a measured failure
 * rather than chosen from the docs.
 *
 * **Single-file, not wasmfile.** Design §19.17 noted that
 * `@jitl/quickjs-wasmfile-release-sync` "ships `emscripten-module.wasm` as a
 * separate **503,134-byte** file, so its load is a real fetch that a strict
 * policy would have to allow or pre-empt". Measured here in a real headless
 * Chrome, that is not merely a policy question: the default variant aborts
 * with `both async and sync fetching of the wasm failed` unless the embedding
 * page happens to serve that file at the URL Emscripten computes from
 * `import.meta.url`. Every one of the first benchmark runs failed exactly that
 * way — reported honestly as `sandboxUnavailable`, but reported as a failure.
 * `@jitl/quickjs-singlefile-browser-release-sync` inlines the module as
 * base64, so the bundle is self-contained: no second fetch, nothing for a
 * `connect-src` policy to allow, and nothing for a WebView's local origin —
 * which on iOS cannot emit a response header at all — to have to serve. It
 * costs bundle size and buys a deployment that cannot half-work.
 *
 * **Sync, not asyncify.** The asyncify variant would let host functions be
 * `async` and remove the settle pump in `run`, but measured here it returned
 * no result at all and then aborted the WASM module on dispose. The sync
 * variant is also the one §19.17's throughput numbers describe, so keeping it
 * keeps those numbers applicable.
 */
export async function loadQuickJsModule(): Promise<QuickJSWASMModule> {
  sharedModule ??= newQuickJSWASMModuleFromVariant(
    singleFileBrowserReleaseSync,
  );
  return sharedModule;
}

/**
 * What a QuickJS VM actually enforces, stated without flattery.
 *
 * Every `false` here is a fact the answer will carry: `SandboxEnforcement`
 * exists so a caller can degrade deliberately and *say* it degraded rather
 * than silently running unconfined (plan §4.3).
 */
export function quickJsEnforcement(memoryMb: number): SandboxEnforcement {
  return {
    // There is no filesystem. Reads resolve against the injected grant map
    // and nothing else exists to reach, so this is stronger than an allowlist
    // over a real filesystem rather than weaker.
    filesystemRead: true,
    // No write surface of any kind is created in the VM, so `writePath` is
    // unused. Reported true because the guarantee ("writes cannot leave the
    // scratch") holds vacuously, and noted below so nobody reads it as
    // "a scratch directory was policed".
    filesystemWrite: true,
    // No network binding is created. Verified per run by `probeVmGlobals`.
    network: true,
    // QuickJS's interrupt handler measures wall clock, not CPU time, and WASM
    // gives the host no CPU accounting. A CPU-bound run is caught by the wall
    // clock or not at all.
    cpu: false,
    // `setMemoryLimit` bounds the VM heap. It does NOT bound the host page's
    // memory, which is what `SandboxEnforcement.memory` asks about, so this is
    // false even though the number that matters most is enforced.
    memory: false,
    // The VM cannot create a process, a thread or a Worker; those globals do
    // not exist in it.
    processCount: true,
    wallClock: true,
    notes: [
      "PS-Lite/QuickJS: one containment layer, not two. The Node path backs " +
        "its language boundary with an OS sandbox; a browser runtime has no " +
        "OS layer available, so the VM boundary is the only one.",
      `VM heap bounded at ${memoryMb}MB by QuickJS setMemoryLimit; the ` +
        `host page's own memory is not bounded.`,
      "CPU time is not bounded; only wall clock is, via the QuickJS interrupt " +
        "handler.",
      "No write surface exists in the VM, so writePath is unused.",
    ],
  };
}

/** The result of asking the VM, at runtime, what globals it actually has. */
export interface VmGlobalProbe {
  /** Names that exist in the VM. Expected to be empty. */
  present: string[];
}

/**
 * Names whose presence in the VM would be an egress or escape path.
 *
 * The Node interpreter denies these by enumeration
 * (`interpreter/realm.ts:38-56`) because its realm has them. This VM never
 * creates them, so the list is used as an *assertion* rather than as a
 * filter — if any of them is ever present, something upstream changed and the
 * containment claim is void.
 */
export const EGRESS_GLOBALS = [
  "fetch",
  "XMLHttpRequest",
  "WebSocket",
  "Worker",
  "SharedWorker",
  "importScripts",
  "WebAssembly",
  "RTCPeerConnection",
  "EventSource",
  "navigator",
  "process",
  "require",
  "Deno",
  "sendBeacon",
  "postMessage",
  "indexedDB",
  "localStorage",
  "caches",
  "open",
] as const;

/**
 * Ask the VM which of {@link EGRESS_GLOBALS} it has.
 *
 * Run per sandbox construction rather than once, so a future change that
 * injects something reaches this before it reaches a user's data.
 */
export function probeVmGlobals(vm: QuickJSContext): VmGlobalProbe {
  const expr = `JSON.stringify(${JSON.stringify([...EGRESS_GLOBALS])}.filter(function (n) { return typeof globalThis[n] !== "undefined"; }))`;
  const res = vm.evalCode(expr);
  if (res.error) {
    res.error.dispose();
    // Fail closed: an unreadable probe is not a passing probe.
    return { present: ["<probe failed>"] };
  }
  const raw = vm.getString(res.value);
  res.value.dispose();
  return { present: JSON.parse(raw) as string[] };
}

/**
 * The `vana` object as it exists *inside* the VM.
 *
 * It holds no data and no counters. Every method marshals to the host and
 * returns a promise the host settles, so the ledger stays in a heap the
 * model's code cannot address. `stream` iterates in the VM over records the
 * host already counted as a full pass, which keeps `vana.stream`'s callback
 * semantics without letting VM code drive the ledger.
 *
 * Frozen so a script cannot replace a method with one that reports different
 * numbers to code running after it.
 */
const VANA_PRELUDE = `
(function () {
  var pending = Object.create(null);
  var nextId = 1;
  globalThis.__vana_settle = function (id, ok, json) {
    var p = pending[id];
    if (!p) return;
    delete pending[id];
    var v = json === undefined ? undefined : JSON.parse(json);
    if (ok) p.resolve(v); else {
      var e = new Error(v && v.message ? v.message : "query tool error");
      if (v && v.code) e.code = v.code;
      p.reject(e);
    }
  };
  function call(method, args) {
    var id = nextId++;
    return new Promise(function (resolve, reject) {
      pending[id] = { resolve: resolve, reject: reject };
      __vana_enqueue(id, method, JSON.stringify(args === undefined ? [] : args));
    });
  }
  var vana = {
    scopes: function () { return call("scopes", []); },
    readAll: function (s) { return call("readAll", [s]); },
    read: function (s, o) { return call("read", [s, o]); },
    search: function (q, o) { return call("search", [q, o]); },
    classify: function (i, ins, o) { return call("classify", [i, ins, o]); },
    introspect: function () { return call("introspect", []); },
    note: function (m) { __vana_note(String(m)); },
    result: function (p) { __vana_result(JSON.stringify(p)); },
    stream: function (scope, onItem) {
      return call("streamRecords", [scope]).then(function (items) {
        var i = 0;
        function step() {
          if (i >= items.length) return items.length;
          var r = onItem(items[i], i);
          i++;
          return (r && typeof r.then === "function") ? r.then(step) : step();
        }
        return step();
      });
    },
  };
  Object.freeze(vana);
  Object.defineProperty(globalThis, "vana", { value: vana, writable: false, configurable: false });
  globalThis.console = Object.freeze({
    log: function () {
      var parts = [];
      for (var i = 0; i < arguments.length; i++) {
        var a = arguments[i];
        parts.push(typeof a === "string" ? a : JSON.stringify(a));
      }
      __vana_note(parts.join(" "));
    },
  });
})();
`;

/** One marshalled call waiting for the host to settle it. */
interface PendingCall {
  id: number;
  method: string;
  args: unknown[];
}

interface RunAccounting {
  notes: string[];
  result?: ScriptResult;
  error?: { code: string; message: string };
  completed: boolean;
}

/**
 * Create a QuickJS-backed {@link Sandbox} bound to one request's grant.
 *
 * The grant is fixed at construction, mirroring `createNodeSandbox({dataRoot})`:
 * one sandbox serves one request, and the data it can reach was decided before
 * any model code existed.
 */
export function createQuickJsSandbox(options: QuickJsSandboxOptions): Sandbox {
  const { grant, context, deps } = options;

  const capabilities = async (): Promise<
    | { available: true; enforcement: SandboxEnforcement }
    | { available: false; reason: string }
  > => {
    try {
      await (options.module
        ? Promise.resolve(options.module)
        : loadQuickJsModule());
    } catch (err) {
      return {
        available: false,
        reason: `QuickJS WASM module failed to load: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
    return {
      available: true,
      enforcement: quickJsEnforcement(0),
    };
  };

  return {
    capabilities,

    async run(script: string, spec: SandboxSpec): Promise<SandboxResult> {
      const started = Date.now();
      const enforcement = quickJsEnforcement(spec.memoryMb);
      const violations: string[] = [];

      /*
       * Both layers must agree, exactly as they do on Node.
       *
       * `readPaths` is the grant as the caller computed it; `grant` is the
       * data actually materialized. A path in one and not the other means the
       * two views of the grant have drifted, and drift in this direction is
       * design §3 risk 1 — "data under a grant is one bad readPaths
       * computation away from exposure". Refuse rather than run under the
       * more permissive of the two.
       */
      const declared = new Set(spec.readPaths);
      for (const p of declared) {
        if (!grant.has(p)) {
          return failed(
            started,
            enforcement,
            "sandboxUnavailable",
            `readPaths names "${p}", which was not materialized into this run's grant`,
          );
        }
      }
      for (const p of grant.keys()) {
        if (!declared.has(p)) {
          return failed(
            started,
            enforcement,
            "sandboxUnavailable",
            `the materialized grant holds "${p}", which readPaths does not name`,
          );
        }
      }

      let module: QuickJSWASMModule;
      try {
        module = options.module ?? (await loadQuickJsModule());
      } catch (err) {
        return failed(
          started,
          enforcement,
          "sandboxUnavailable",
          `QuickJS WASM module failed to load: ${err instanceof Error ? err.message : String(err)}`,
        );
      }

      const { api, state } = createVanaApi(context, deps);
      const acc: RunAccounting = { notes: [], completed: false };

      let rt: QuickJSRuntime | undefined;
      let vm: QuickJSContext | undefined;
      let termination: SandboxTermination = "completed";

      try {
        rt = module.newRuntime();
        rt.setMemoryLimit(spec.memoryMb * 1024 * 1024);
        rt.setMaxStackSize(MAX_STACK_BYTES);
        const deadline = started + spec.wallClockMs;
        rt.setInterruptHandler(() => Date.now() > deadline);
        vm = rt.newContext();

        const probe = probeVmGlobals(vm);
        if (probe.present.length > 0) {
          // Never run model code in a VM whose containment claim just failed.
          return failed(
            started,
            enforcement,
            "sandboxUnavailable",
            `the QuickJS VM unexpectedly exposes ${probe.present.join(", ")}; refusing to run`,
          );
        }

        const queue: PendingCall[] = [];
        const disposables: QuickJSHandle[] = [];

        const enqueue = vm.newFunction(
          "__vana_enqueue",
          (idH, methodH, argsH) => {
            queue.push({
              id: vm!.getNumber(idH),
              method: vm!.getString(methodH),
              args: JSON.parse(vm!.getString(argsH)) as unknown[],
            });
          },
        );
        vm.setProp(vm.global, "__vana_enqueue", enqueue);
        disposables.push(enqueue);

        const note = vm.newFunction("__vana_note", (mH) => {
          const line = vm!.getString(mH).slice(0, MAX_NOTE_CHARS);
          api.note(line);
        });
        vm.setProp(vm.global, "__vana_note", note);
        disposables.push(note);

        const resultFn = vm.newFunction("__vana_result", (pH) => {
          const payload = JSON.parse(vm!.getString(pH)) as ScriptResult;
          try {
            api.result(payload);
          } catch (err) {
            if (err instanceof ScriptCompleted) {
              acc.completed = true;
              // `vana.result` terminates the script (prompt §3). The `{error}`
              // form is the ONLY way to throw out of a host function — a
              // returned error object is just a value, and a script that saw
              // one would carry on past its own result.
              return { error: vm!.newString("__vana_script_completed__") };
            }
            if (err instanceof QueryToolError) {
              acc.error = { code: err.code, message: err.message };
              return { error: vm!.newString(err.message) };
            }
            throw err;
          }
          return vm!.undefined;
        });
        vm.setProp(vm.global, "__vana_result", resultFn);
        disposables.push(resultFn);

        for (const h of disposables) h.dispose();
        disposables.length = 0;

        const pre = vm.evalCode(VANA_PRELUDE);
        if (pre.error) {
          const msg = vm.dump(pre.error) as unknown;
          pre.error.dispose();
          throw new Error(`vana prelude failed: ${JSON.stringify(msg)}`);
        }
        pre.value.dispose();

        /*
         * The model's code is wrapped, never concatenated into a template it
         * could break out of: `JSON.stringify` is not used because the wrapper
         * needs the code as *code*, but the wrapper is a bare async IIFE with
         * no surrounding expression to escape. Top-level `await` is what the
         * prompt teaches (`agent/prompt.ts:42-54`) and a plain QuickJS script
         * has no top-level await, so the IIFE supplies it.
         */
        const wrapped = `(async () => {\n${script}\n})().then(function(){}, function(e){ globalThis.__vana_uncaught = (e && e.message) ? e.message : String(e); });`;
        const evalRes = vm.evalCode(wrapped);
        if (evalRes.error) {
          const dumped = vm.dump(evalRes.error) as { message?: string };
          evalRes.error.dispose();
          const message = dumped?.message ?? "script failed";
          if (message === "interrupted") termination = "wallClock";
          else if (message === "out of memory") termination = "memory";
          else acc.error = { code: "SCRIPT_ERROR", message };
        } else {
          evalRes.value.dispose();
        }

        /*
         * The settle pump.
         *
         * QuickJS's sync variant cannot suspend a host function on a promise,
         * so the bridge is explicit: drain the VM's microtasks, take whatever
         * `vana` calls the script queued, settle them against the *host's*
         * async API, hand the values back, repeat. The loop ends when the VM
         * has nothing left to run and nothing left to wait for.
         */
        while (termination === "completed" && !acc.completed) {
          const jobs = rt.executePendingJobs();
          if (jobs.error) {
            const dumped = vm.dump(jobs.error) as { message?: string };
            jobs.error.dispose();
            const message = dumped?.message ?? "pending job failed";
            if (message === "interrupted") termination = "wallClock";
            else if (message === "out of memory") termination = "memory";
            else acc.error ??= { code: "SCRIPT_ERROR", message };
            break;
          }
          jobs.dispose();

          if (Date.now() > deadline) {
            termination = "wallClock";
            break;
          }
          if (queue.length === 0) break;

          const batch = queue.splice(0, queue.length);
          for (const call of batch) {
            let ok = true;
            let payload: unknown;
            try {
              payload = await dispatch(api, call);
            } catch (err) {
              ok = false;
              if (err instanceof ScriptCompleted) {
                acc.completed = true;
                break;
              }
              payload =
                err instanceof QueryToolError
                  ? { code: err.code, message: err.message }
                  : {
                      code: "SCRIPT_ERROR",
                      message: err instanceof Error ? err.message : String(err),
                    };
            }
            settle(vm, call.id, ok, payload);
          }
        }

        // An uncaught rejection inside the script's own async body lands here
        // rather than on `evalCode`, because the IIFE attaches a handler.
        const uncaught = vm.getProp(vm.global, "__vana_uncaught");
        if (vm.typeof(uncaught) === "string") {
          const message = vm.getString(uncaught);
          if (message !== "__vana_script_completed__") {
            acc.error ??= { code: "SCRIPT_ERROR", message };
          } else {
            acc.completed = true;
          }
        }
        uncaught.dispose();
      } catch (err) {
        acc.error = {
          code: "SANDBOX_ERROR",
          message: err instanceof Error ? err.message : String(err),
        };
        termination = "error";
      } finally {
        /*
         * Disposal order matters and disposing out of order takes the process
         * with it: design §19.17 recorded that freeing a runtime that still
         * owns a handle aborts the WASM module with
         * `Assertion failed: list_empty(&rt->gc_obj_list)`. Context before
         * runtime, and every handle already released above.
         */
        try {
          vm?.dispose();
        } catch {
          /* a VM aborted mid-run cannot always be disposed; the runtime free
             below still reclaims the WASM memory. */
        }
        try {
          rt?.dispose();
        } catch {
          /* see above */
        }
      }

      const s = state();
      const coverage = finalizeCoverage(
        s.coverage.snapshot(),
        termination,
        acc,
      );

      const doc: RunDocument = {
        v: 1,
        coverage: {
          ...coverage,
          enforcementNotes: [
            ...coverage.enforcementNotes,
            ...enforcement.notes,
          ],
        },
        notes: s.notes,
        toolCalls: s.toolCalls,
        classifyUsd: s.classifyUsd,
        ...(s.result ? { result: s.result } : {}),
        ...(acc.error ? { error: acc.error } : {}),
      };

      /*
       * §19.17's silent failure, guarded explicitly.
       *
       * "At a 16 MB limit the FFI arm returned ok: true, result: null — the
       * allocation failure raised no error, settled no promise, and left the
       * host with no signal that anything had gone wrong. A Lite sandbox that
       * treated 'no exception' as success would hand the model an empty result
       * over a truncated corpus."
       *
       * So success is asserted positively rather than inferred from silence: a
       * run that neither completed, nor errored, nor hit a budget, and which
       * read nothing, did not succeed — whatever the absence of an exception
       * suggests.
       */
      const verified = verifyOutcome(doc, termination, acc);

      const frame = encodeResultFrame(
        boundRunDocument(verified.doc, Math.floor(spec.maxOutputBytes / 2)),
      );

      return {
        stdout: frame,
        stderr: "",
        exitCode: verified.termination === "completed" ? 0 : 1,
        timedOut:
          verified.termination === "wallClock" ||
          verified.termination === "cpu",
        truncated: false,
        durationMs: Date.now() - started,
        termination: verified.termination,
        enforcement,
        violations: [...violations, ...verified.violations],
      };
    },
  };
}

/**
 * Positively verify that a run that reported nothing actually did nothing
 * wrong, rather than inferring success from the absence of an exception.
 *
 * See design §19.17's `ok: true, result: null` finding. The three signals that
 * a run genuinely happened are: it called `vana.result`, or it raised an
 * error, or it read something. A run with none of those, and no budget stop to
 * explain itself, is treated as a memory termination and says so — an honest
 * "we cannot vouch for this run" rather than an empty answer over a corpus
 * that may have been truncated.
 */
export function verifyOutcome(
  doc: RunDocument,
  termination: SandboxTermination,
  acc: { completed: boolean; error?: { code: string; message: string } },
): {
  doc: RunDocument;
  termination: SandboxTermination;
  violations: string[];
} {
  if (termination !== "completed") return { doc, termination, violations: [] };
  if (acc.completed || acc.error) return { doc, termination, violations: [] };
  if (
    doc.coverage.recordsScanned > 0 ||
    doc.coverage.scopesScanned.length > 0
  ) {
    return { doc, termination, violations: [] };
  }
  if (doc.coverage.stoppedBecause !== undefined) {
    return { doc, termination, violations: [] };
  }
  const message =
    "the run produced no result, raised no error and read no records; " +
    "QuickJS can end this way on an allocation failure that raises nothing " +
    "(design §19.17), so the run is reported as failed rather than empty";
  return {
    termination: "memory",
    violations: [message],
    doc: {
      ...doc,
      coverage: {
        ...doc.coverage,
        stoppedBecause: "memory",
      },
      error: doc.error ?? { code: "SILENT_EMPTY_RUN", message },
    },
  };
}

/**
 * Fold a non-`completed` termination into the coverage the ledger produced.
 *
 * The ledger knows what was read; only the host knows why the reading stopped.
 * Strictly one-directional, like `applyGrantCoverage` on the Node side: it can
 * only add a reason the reading was bounded, never withdraw one. It never
 * touches a counter, so it cannot make a run look like it read more than it
 * did.
 */
function finalizeCoverage(
  coverage: CoverageCounters,
  termination: SandboxTermination,
  acc: RunAccounting,
): CoverageCounters {
  if (termination === "wallClock") {
    return { ...coverage, stoppedBecause: "wallClock" };
  }
  if (termination === "memory") {
    return { ...coverage, stoppedBecause: "memory" };
  }
  if (termination === "error") {
    return { ...coverage, stoppedBecause: "error" };
  }
  if (acc.error && acc.error.code !== "BUDGET_EXHAUSTED") {
    return { ...coverage, stoppedBecause: "error" };
  }
  return coverage;
}

/** Hand one settled host value back into the VM. */
function settle(
  vm: QuickJSContext,
  id: number,
  ok: boolean,
  payload: unknown,
): void {
  const json = payload === undefined ? undefined : JSON.stringify(payload);
  const idH = vm.newNumber(id);
  const okH = ok ? vm.true : vm.false;
  const jsonH = json === undefined ? vm.undefined : vm.newString(json);
  const fn = vm.getProp(vm.global, "__vana_settle");
  const res = vm.callFunction(fn, vm.undefined, idH, okH, jsonH);
  if (res.error) res.error.dispose();
  else res.value.dispose();
  fn.dispose();
  idH.dispose();
  if (json !== undefined) jsonH.dispose();
}

/**
 * Route one marshalled call to the host-side `vana` API.
 *
 * Every branch goes through the same `createVanaApi` instance the Node runner
 * uses, so grant binding, budget spend and the coverage ledger behave
 * identically on both runtimes. `streamRecords` is the one method with no
 * direct counterpart: `vana.stream`'s callback lives in the VM, so the host
 * runs the full pass (which is what the ledger records) and returns the
 * records for the VM to iterate.
 */
async function dispatch(
  api: ReturnType<typeof createVanaApi>["api"],
  call: PendingCall,
): Promise<unknown> {
  const [a, b, c] = call.args;
  switch (call.method) {
    case "scopes":
      return api.scopes();
    case "readAll":
      return api.readAll(a as string);
    case "read":
      return api.read(a as string, b as Parameters<typeof api.read>[1]);
    case "search":
      return api.search(a as string, b as Parameters<typeof api.search>[1]);
    case "classify":
      return api.classify(
        a as unknown[],
        b as string,
        c as Parameters<typeof api.classify>[2],
      );
    case "introspect":
      return api.introspect();
    case "streamRecords": {
      const items: unknown[] = [];
      await api.stream(a as string, (item) => {
        items.push(item);
      });
      return items;
    }
    default:
      throw new QueryToolError(
        "CAPABILITY_UNAVAILABLE",
        `unknown vana method "${call.method}"`,
      );
  }
}

/** A run that never started, reported so the caller can see why. */
function failed(
  started: number,
  enforcement: SandboxEnforcement,
  termination: SandboxTermination,
  message: string,
): SandboxResult {
  const doc: RunDocument = {
    v: 1,
    coverage: {
      scopesScanned: [],
      recordsScanned: 0,
      bytesScanned: 0,
      unreadable: 0,
      perScope: {},
      scopesSkipped: [],
      method: "full",
      stoppedBecause: termination === "wallClock" ? "wallClock" : "error",
      enforcementNotes: enforcement.notes,
    },
    notes: [],
    toolCalls: 0,
    classifyUsd: 0,
    error: { code: "SANDBOX_UNAVAILABLE", message },
  };
  return {
    stdout: encodeResultFrame(doc),
    stderr: message,
    exitCode: 1,
    timedOut: false,
    truncated: false,
    durationMs: Date.now() - started,
    termination,
    enforcement,
    violations: [message],
  };
}
