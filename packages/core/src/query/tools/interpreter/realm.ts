/**
 * The authority-free global for model-authored code (design §19.6 item 3).
 *
 * The measured reason this exists: a script executed as plain `node script.js`
 * inside the OS sandbox still has `require`, `process`, `eval` and the
 * `Function` constructor. It can read a granted file directly — bypassing the
 * counters entirely — and print a forged coverage line on the same stdout the
 * runtime uses. OS enforcement bounds what the *process* may touch; it does
 * nothing about what the *script* may name. That is why design §19.7 requires
 * two layers, and this file is the second one.
 *
 * The rule here is deny-by-default: a script may reach exactly the bindings in
 * {@link createRealm} and nothing else. Anything not listed is not merely
 * blocked, it is unnameable.
 */
import { arrayMethod, ASYNC_ARRAY_METHODS } from "./array-methods.js";

/**
 * Property names that bridge from any value back to the host realm.
 *
 * `({}).constructor.constructor("return process")()` is the canonical escape:
 * every object reaches `Function` through its constructor, and `Function`
 * compiles arbitrary code in the *host* realm where `process` and `require`
 * live. Blocking these three names at every member access closes the bridge,
 * which is why the evaluator routes all property reads through
 * {@link readMember} rather than using `obj[key]` directly.
 */
export const FORBIDDEN_KEYS = new Set([
  "constructor",
  "__proto__",
  "prototype",
  "__defineGetter__",
  "__defineSetter__",
  "__lookupGetter__",
  "__lookupSetter__",
]);

/** Identifiers a script may never bind or reference. */
export const FORBIDDEN_IDENTIFIERS = new Set([
  "eval",
  "Function",
  "require",
  "process",
  "globalThis",
  "global",
  "module",
  "exports",
  "import",
  "Reflect",
  "Proxy",
  "WebAssembly",
  "SharedArrayBuffer",
  "Atomics",
  "XMLHttpRequest",
  "fetch",
  "Worker",
  "importScripts",
]);

/**
 * Globals a model plausibly reaches for that are deliberately absent, with the
 * reason and the alternative.
 *
 * A bare "X is not defined" costs a whole repair turn to diagnose. Naming the
 * substitute makes the denial actionable on the spot.
 *
 * **`Intl` is excluded on measured grounds, not caution.** The same script
 * formatting the same values produced `1,234.5` and `1969-12-31` on one host
 * and `1.234,5` and `1.1.1970` on another, purely from the ambient locale and
 * timezone — the date itself moved by a day. Scripts here bucket records by
 * date and join sources on it, so a host-dependent formatter would inject
 * exactly the nondeterminism the determinism measurement exists to bound, and
 * would do it invisibly. Formatting is presentation anyway: the answer's
 * `value` is a bare number, so nothing about correctness needs a locale.
 */
export const DELIBERATELY_ABSENT = new Map<string, string>([
  [
    "Intl",
    "`Intl` is not available: its output depends on the host's locale and " +
      "timezone, which would make the same script return different numbers " +
      "and different dates on different machines. Format manually instead — " +
      "`toFixed(2)` for money, and build date strings from `getUTCFullYear()`, " +
      "`getUTCMonth()` and `getUTCDate()`, or slice an ISO string.",
  ],
  [
    "setTimeout",
    "There are no timers: a script has a wall-clock budget, not a scheduler. " +
      "Do the work directly.",
  ],
  [
    "structuredClone",
    "`structuredClone` is not available. Use `JSON.parse(JSON.stringify(x))` " +
      "for plain data.",
  ],
]);

export class ConfinementError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfinementError";
  }
}

/**
 * Read a property under confinement.
 *
 * Every member access in the evaluator goes through here, so the forbidden-key
 * check cannot be skipped by computed access (`obj["constructor"]`) or by
 * reaching through an intermediate value.
 */
export function readMember(target: unknown, key: PropertyKey): unknown {
  if (target === null || target === undefined) {
    throw new TypeError(`cannot read "${String(key)}" of ${String(target)}`);
  }
  const name = typeof key === "symbol" ? key.toString() : String(key);
  if (FORBIDDEN_KEYS.has(name)) {
    throw new ConfinementError(
      `access to "${name}" is not allowed — it bridges out of the confined realm`,
    );
  }
  // Higher-order array methods must await script callbacks, which are always
  // async. Native `filter` would see a Promise, treat it as truthy, and keep
  // every element — a silent wrong answer. See `array-methods.ts`.
  if (Array.isArray(target) && ASYNC_ARRAY_METHODS.has(name)) {
    const replacement = arrayMethod(target, name);
    if (replacement) return replacement;
  }
  const value = (target as Record<PropertyKey, unknown>)[key];
  // Methods must stay bound to their receiver: the evaluator calls them
  // detached, and an unbound `String.prototype.slice` would lose `this`.
  if (typeof value === "function") {
    return (value as (...a: unknown[]) => unknown).bind(target);
  }
  return value;
}

/**
 * Build the set of globals a script may name.
 *
 * Deliberately excluded and worth stating: no `Function`, no `eval`, no
 * `require`/`import`, no `process`, no `globalThis` (which would re-expose
 * everything), no timers (a script has a wall-clock budget, not a scheduler),
 * and no network of any kind — egress is denied at the OS layer, and naming it
 * here would only produce confusing failures.
 */
export function createRealm(vana: unknown, onConsole: (msg: string) => void) {
  const console = {
    log: (...args: unknown[]) => onConsole(args.map(stringify).join(" ")),
    warn: (...args: unknown[]) => onConsole(args.map(stringify).join(" ")),
    error: (...args: unknown[]) => onConsole(args.map(stringify).join(" ")),
  };
  return new Map<string, unknown>([
    ["vana", vana],
    ["console", console],
    ["Math", Math],
    ["JSON", JSON],
    ["Date", Date],
    ["Number", Number],
    ["String", String],
    ["Boolean", Boolean],
    ["Array", Array],
    ["Object", Object],
    ["Map", Map],
    ["Set", Set],
    ["RegExp", RegExp],
    ["Error", Error],
    ["TypeError", TypeError],
    ["RangeError", RangeError],
    ["Promise", Promise],
    ["isNaN", isNaN],
    ["isFinite", isFinite],
    ["parseInt", parseInt],
    ["parseFloat", parseFloat],
    ["encodeURIComponent", encodeURIComponent],
    ["decodeURIComponent", decodeURIComponent],
    ["undefined", undefined],
    ["NaN", NaN],
    ["Infinity", Infinity],
  ]);
}

function stringify(v: unknown): string {
  if (typeof v === "string") return v;
  try {
    return JSON.stringify(v) ?? String(v);
  } catch {
    return String(v);
  }
}
