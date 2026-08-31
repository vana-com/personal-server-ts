/**
 * The mobile WASM device probe: one page load, four fields, no model call.
 *
 * Design §19.18 records QuickJS-on-WASM as **measured working** on desktop
 * Chrome and desktop Safari and **UNVERIFIED** on iOS WKWebView and Android
 * WebView, and says exactly what would settle it:
 *
 * > build `.bench/probe.ts` into `apps/mobile-shell/assets/ps/`, load it in
 * > the Flutter shell on one real iOS device and one real Android device, and
 * > read the four fields it already emits — `moduleLoad`,
 * > `egressGlobalsPresent`, `mechanics`, `opfs.writable`.
 *
 * `.bench/` was a scratch directory and did not survive; this is that probe,
 * in the package the fields belong to, so it is type-checked and tested
 * alongside the sandbox whose behaviour it asserts. The field names are the
 * ones §19.18 named, unchanged, because a paste-back report is only useful if
 * it answers the question in the words the question was asked in.
 *
 * ### What it does not do
 *
 * It runs no model, reads no user data and writes nothing outside one
 * throwaway OPFS file it deletes. It is a capability measurement, and a
 * failure of any field is a result rather than an error — every branch below
 * records *why* instead of throwing, because a probe that dies on the first
 * missing capability answers one field and leaves three unknown.
 *
 * ### Why these four
 *
 * - `moduleLoad` — the single-file variant inlines the engine as base64
 *   (`loadQuickJsModule`), so this is the whole "does WASM instantiate here"
 *   question with no fetch, no MIME type and no CSP in it. On iOS it is also
 *   the Lockdown Mode question, which disables WebAssembly outright.
 * - `egressGlobalsPresent` — the containment claim. §19.18: "Not denied:
 *   absent, because QuickJS never created them." Expected `[]`; anything else
 *   voids the claim on that engine.
 * - `mechanics` — the three version-specific behaviours the sandbox is built
 *   on. They are asserted against Node's WASM build by
 *   `quickjs-sandbox.test.ts`; a WebView's WASM is not that build, so they are
 *   re-asked on the device rather than assumed.
 * - `opfs.writable` — §19.17 recorded the mobile host defaulting to IndexedDB
 *   because "WKWebView can advertise OPFS while failing its first real write",
 *   and `isOpfsAvailable()` only feature-detects `getDirectory`. So presence is
 *   the wrong question; this performs the real `createWritable()` write that
 *   the OPFS store performs.
 */

import type {
  QuickJSContext,
  QuickJSRuntime,
  QuickJSWASMModule,
} from "quickjs-emscripten-core";

import {
  loadQuickJsModule,
  MAX_STACK_BYTES,
  probeVmGlobals,
} from "./quickjs-sandbox.js";

/** Stable identifier of the report shape, so a pasted-back block is unambiguous. */
export const DEVICE_PROBE_NAME = "vana-quickjs-device-probe";

/** Bumped whenever a field is added, removed or changes meaning. */
export const DEVICE_PROBE_VERSION = 2;

/** §19.18 field 1. */
export interface ModuleLoadField {
  /** Did the WASM engine instantiate at all? */
  ok: boolean;
  /** Wall clock for the first instantiation, ms. `null` when it failed. */
  ms: number | null;
  /** Present only on failure. */
  error?: string;
}

/** §19.18 field 3. */
export interface MechanicsField {
  /**
   * §19.17: `setMaxStackSize` at 8 MB makes *every* `evalCode` fail, including
   * `1+1`. `MAX_STACK_BYTES` is chosen to sit under that threshold, so a
   * device where this comes back `false` has a different WASM stack region and
   * the constant needs re-measuring there.
   */
  stackLimitAt8MbFailsEval: boolean | null;
  /**
   * §19.17's silent-wrongness trap: at a limit too small, a QuickJS run can
   * end with no exception and a null result. This asks for the *raising*
   * behaviour directly — an allocation past the limit must surface an error,
   * not an empty success.
   */
  memoryLimitRaisesRatherThanNull: boolean | null;
  /**
   * §19.18's third mechanic: a host function that *returns* `vm.newError(...)`
   * hands the error back as an ordinary value rather than throwing. The
   * grant-denial path depends on knowing this, and the first spike printed
   * `LEAK` because it did not.
   */
  hostErrorReturnValueDoesNotThrow: boolean | null;
  /** The stack ceiling this build ships, for the record. */
  maxStackBytes: number;
  /** Why any field above is `null`. Empty when all three were measured. */
  errors: string[];
}

/** §19.18 field 4 — the report reads `opfs.writable`. */
export interface OpfsField {
  /** What `isOpfsAvailable()` in `storage.ts` feature-detects, and no more. */
  getDirectoryPresent: boolean;
  /** Whether the method the OPFS store actually writes through exists. */
  createWritablePresent: boolean;
  /**
   * **The field §19.18 names.** A real `createWritable()` write completed.
   * This is the one that separates "advertises OPFS" from "OPFS works".
   */
  writable: boolean;
  /** The bytes written came back byte-identical. */
  roundTripOk: boolean;
  error?: string;
}

export interface DeviceProbeReport {
  probe: typeof DEVICE_PROBE_NAME;
  version: number;
  at: string;
  /** Storage partitions by origin; a report from the wrong one means nothing. */
  origin: string;
  userAgent: string;
  /** No `crypto.subtle` without one, and PS-Lite cannot boot. Context, not a verdict. */
  secureContext: boolean;
  /** §19.18 field 1. */
  moduleLoad: ModuleLoadField;
  /** §19.18 field 2. Expected `[]`. `null` when the module never loaded. */
  egressGlobalsPresent: string[] | null;
  /** §19.18 field 3. `null` when the module never loaded. */
  mechanics: MechanicsField | null;
  /** §19.18 field 4, read as `opfs.writable`. */
  opfs: OpfsField;
  /**
   * One line a human can read without decoding the rest. It states what was
   * measured; it never claims support that was not measured here.
   */
  verdict: string;
}

const message = (err: unknown): string =>
  err instanceof Error ? err.message : String(err);

/**
 * Ask the VM which of `EGRESS_GLOBALS` it has.
 *
 * A bare context rather than a configured sandbox: the question is what the
 * *engine* creates on this platform, and a sandbox would answer for the
 * injection code as well.
 */
function measureEgressGlobals(module: QuickJSWASMModule): string[] {
  const rt = module.newRuntime();
  rt.setMaxStackSize(MAX_STACK_BYTES);
  const vm = rt.newContext();
  try {
    return probeVmGlobals(vm).present;
  } finally {
    vm.dispose();
    rt.dispose();
  }
}

/** Runs `body` against a fresh runtime/context pair and always disposes both. */
function withVm<T>(
  module: QuickJSWASMModule,
  configure: (rt: QuickJSRuntime) => void,
  body: (vm: QuickJSContext) => T,
): T {
  const rt = module.newRuntime();
  configure(rt);
  const vm = rt.newContext();
  try {
    return body(vm);
  } finally {
    vm.dispose();
    rt.dispose();
  }
}

function measureMechanics(module: QuickJSWASMModule): MechanicsField {
  const out: MechanicsField = {
    stackLimitAt8MbFailsEval: null,
    memoryLimitRaisesRatherThanNull: null,
    hostErrorReturnValueDoesNotThrow: null,
    maxStackBytes: MAX_STACK_BYTES,
    errors: [],
  };

  try {
    out.stackLimitAt8MbFailsEval = withVm(
      module,
      (rt) => rt.setMaxStackSize(8 * 1024 * 1024),
      (vm) => {
        const r = vm.evalCode("1+1");
        const failed = r.error !== undefined;
        (r.error ?? r.value).dispose();
        return failed;
      },
    );
  } catch (err) {
    out.errors.push(`stackLimitAt8MbFailsEval: ${message(err)}`);
  }

  try {
    out.memoryLimitRaisesRatherThanNull = withVm(
      module,
      (rt) => {
        rt.setMemoryLimit(1024 * 1024);
        rt.setMaxStackSize(MAX_STACK_BYTES);
      },
      (vm) => {
        // Allocate well past the limit. The property under test is that the
        // engine *surfaces* the failure rather than completing with nothing —
        // §19.17's `ok: true, result: null`, which read as success.
        const r = vm.evalCode(
          "var a = []; for (var i = 0; i < 400000; i++) { a.push('x'.repeat(64)); } a.length",
        );
        const raised = r.error !== undefined;
        (r.error ?? r.value).dispose();
        return raised;
      },
    );
  } catch (err) {
    // An out-of-memory that takes the whole runtime down is still "raised
    // rather than silently null", and is the safe direction. Record it as such
    // and say so, rather than losing the reading.
    out.memoryLimitRaisesRatherThanNull = true;
    out.errors.push(
      `memoryLimitRaisesRatherThanNull: raised at the host boundary: ${message(err)}`,
    );
  }

  try {
    out.hostErrorReturnValueDoesNotThrow = withVm(
      module,
      (rt) => rt.setMaxStackSize(MAX_STACK_BYTES),
      (vm) => {
        const fn = vm.newFunction("__probe_error", () =>
          vm.newError("returned, not thrown"),
        );
        vm.setProp(vm.global, "__probe_error", fn);
        fn.dispose();
        const r = vm.evalCode(
          "(function () { try { var v = __probe_error(); return v instanceof Error ? 'returned' : 'other'; } catch (e) { return 'threw'; } })()",
        );
        if (r.error) {
          r.error.dispose();
          return null;
        }
        const verdict = vm.getString(r.value);
        r.value.dispose();
        return verdict === "returned";
      },
    );
  } catch (err) {
    out.errors.push(`hostErrorReturnValueDoesNotThrow: ${message(err)}`);
  }

  return out;
}

/**
 * The real write, not the feature detect.
 *
 * Mirrors what `assets/probe/probe.js` does for the shell's own W1 report, and
 * what `packages/lite/src/storage.ts` does at runtime: `getFileHandle` with
 * `create`, `createWritable`, write, close, read back, compare, delete.
 */
async function measureOpfs(): Promise<OpfsField> {
  const out: OpfsField = {
    getDirectoryPresent: false,
    createWritablePresent: false,
    writable: false,
    roundTripOk: false,
  };

  const storage = (
    globalThis as { navigator?: { storage?: { getDirectory?: unknown } } }
  ).navigator?.storage;
  out.getDirectoryPresent = typeof storage?.getDirectory === "function";
  if (!out.getDirectoryPresent) {
    out.error = "navigator.storage.getDirectory is absent";
    return out;
  }

  const name = `vana-wasm-probe-${Date.now()}.txt`;
  const payload = `${DEVICE_PROBE_NAME}:${DEVICE_PROBE_VERSION}`;
  try {
    const root = await (
      storage as { getDirectory: () => Promise<FileSystemDirectoryHandle> }
    ).getDirectory();
    const handle = await root.getFileHandle(name, { create: true });
    out.createWritablePresent = typeof handle.createWritable === "function";
    if (!out.createWritablePresent) {
      out.error = "FileSystemFileHandle.createWritable is absent";
      return out;
    }
    const writable = await handle.createWritable();
    await writable.write(payload);
    await writable.close();
    out.writable = true;

    const back = await (await handle.getFile()).text();
    out.roundTripOk = back === payload;
    if (!out.roundTripOk) {
      out.error = `read back ${JSON.stringify(back)}, expected ${JSON.stringify(payload)}`;
    }
    await root.removeEntry(name).catch(() => undefined);
  } catch (err) {
    // WebKit's generic `UnknownError` is the shape §19.17 recorded on the one
    // device run that called `navigator.storage.persist()`. Keep the message
    // verbatim; it is the only distinguishing detail that failure has.
    out.error = message(err);
  }
  return out;
}

function summarise(report: DeviceProbeReport): string {
  if (!report.moduleLoad.ok) {
    return `FAIL: QuickJS/WASM did not load here (${report.moduleLoad.error ?? "no reason reported"}). The query layer cannot run on this surface.`;
  }
  const problems: string[] = [];
  if (report.egressGlobalsPresent?.length) {
    problems.push(
      `egress globals present: ${report.egressGlobalsPresent.join(", ")}`,
    );
  }
  const m = report.mechanics;
  if (m) {
    if (m.stackLimitAt8MbFailsEval === false) {
      problems.push("8MB stack limit does NOT fail eval here (§19.17 differs)");
    }
    if (m.memoryLimitRaisesRatherThanNull === false) {
      problems.push("memory limit returned null instead of raising");
    }
    if (m.hostErrorReturnValueDoesNotThrow === false) {
      problems.push("a returned vm.newError threw instead of returning");
    }
    for (const e of m.errors) problems.push(e);
  }
  if (!report.opfs.writable) {
    problems.push(
      `OPFS is not writable here (${report.opfs.error ?? "no reason reported"}) — PS-Lite must stay on the IndexedDB file store on this surface`,
    );
  }
  return problems.length === 0
    ? `PASS on this surface: engine loaded in ${report.moduleLoad.ms}ms, no egress globals, all three mechanics hold, OPFS writable. This is one device; it says nothing about any other.`
    : `PARTIAL: engine loaded in ${report.moduleLoad.ms}ms. Unresolved: ${problems.join("; ")}`;
}

/**
 * Run the probe and return the four §19.18 fields.
 *
 * Never throws: every failure is a recorded field. A caller on a device has no
 * debugger, so an exception costs the whole run.
 */
export async function runDeviceProbe(): Promise<DeviceProbeReport> {
  const nav = (globalThis as { navigator?: { userAgent?: string } }).navigator;
  const report: DeviceProbeReport = {
    probe: DEVICE_PROBE_NAME,
    version: DEVICE_PROBE_VERSION,
    at: new Date().toISOString(),
    origin:
      (globalThis as { location?: { origin?: string } }).location?.origin ??
      "(no location)",
    userAgent: nav?.userAgent ?? "(no navigator)",
    secureContext:
      (globalThis as { isSecureContext?: boolean }).isSecureContext === true,
    moduleLoad: { ok: false, ms: null },
    egressGlobalsPresent: null,
    mechanics: null,
    opfs: {
      getDirectoryPresent: false,
      createWritablePresent: false,
      writable: false,
      roundTripOk: false,
    },
    verdict: "",
  };

  let module: QuickJSWASMModule | undefined;
  const started = Date.now();
  try {
    module = await loadQuickJsModule();
    report.moduleLoad = { ok: true, ms: Date.now() - started };
  } catch (err) {
    report.moduleLoad = { ok: false, ms: null, error: message(err) };
  }

  if (module) {
    try {
      report.egressGlobalsPresent = measureEgressGlobals(module);
    } catch (err) {
      // Fail closed, exactly as `probeVmGlobals` does: an unreadable probe is
      // not a passing probe.
      report.egressGlobalsPresent = [`<probe failed: ${message(err)}>`];
    }
    report.mechanics = measureMechanics(module);
  }

  // Independent of the engine: OPFS is measured even when WASM is unavailable,
  // because "which of the two failed" is the whole value of the report.
  report.opfs = await measureOpfs();

  report.verdict = summarise(report);
  return report;
}

/**
 * The paste-back block.
 *
 * Fenced with the same `===…-BEGIN===`/`===…-END===` sentinels the shell's W1
 * suite uses, so a report can be lifted verbatim out of a noisy device log by
 * `grep`, and so `W1Suite.reportText`'s clipboard copy carries it unchanged.
 */
export function formatDeviceProbeReport(report: DeviceProbeReport): string {
  return [
    `===QUICKJS-PROBE-BEGIN ${report.origin}===`,
    JSON.stringify(report, null, 2),
    `===QUICKJS-PROBE-END ${report.origin}===`,
  ].join("\n");
}
