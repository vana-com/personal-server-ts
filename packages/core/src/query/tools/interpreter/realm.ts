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
 * live. Blocking these names at every member access closes that particular
 * spelling of the bridge.
 *
 * **This list is a convenience, not the boundary.** Blocking names was once
 * the whole defence and it failed: reflection reaches the same objects without
 * ever being asked for a guarded name — `getOwnPropertyDescriptor(p,
 * "constructor").value` hands back `Function` under the key `value`. What
 * actually holds the line is {@link HOST_BRIDGES}, which denies the *objects*
 * rather than the words used to spell them. These names are kept because they
 * produce a precise message at the point a script reaches for them.
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

/* ------------------------------------------------------------------------ *
 * The boundary: host intrinsics are denied by identity, not by name.
 * ------------------------------------------------------------------------ */

/**
 * Every host-realm constructor, prototype and namespace object, by identity.
 *
 * ## Why identity and not names
 *
 * The realm used to bind the host's `Object`, `Array`, `Promise` and friends
 * *verbatim*, and rely on {@link FORBIDDEN_KEYS} to stop a script walking from
 * one of them back to `Function`. That is a blocklist over the *spelling* of a
 * property access, and reflection simply does not spell it:
 *
 * ```js
 * const proto = Object.getPrototypeOf(Math.max);              // Function.prototype
 * const F = Object.getOwnPropertyDescriptor(proto, "constructor").value;
 * F("return process")().getBuiltinModule("fs");               // host realm
 * ```
 *
 * No guarded name is ever read: `getPrototypeOf` returns a prototype without
 * anyone typing `prototype`, and the descriptor carries `Function` under
 * `value`. `Object.values(descriptor)[0]` is the same escape without even a
 * property name. A second variant skipped `Function` altogether and used
 * `Object.defineProperty(Object.getPrototypeOf([]), …)` to redefine the
 * runner process's own `Array.prototype`, which the coverage ledger and the
 * result-frame `JSON.stringify` both run on.
 *
 * Extending the name blocklist would have added a fourth name to a list that
 * had already been walked around three ways. So the rule changed shape: a
 * confined script may never **hold**, **call** or **construct** a host
 * intrinsic, whatever route produced it. That is checked against this set, and
 * the set is *derived by traversing the host's own object graph* from
 * primitive seeds rather than typed out — so it stays complete as the host
 * gains intrinsics, and it cannot be incomplete in the way a hand-written list
 * of names was.
 *
 * The realm binds shims instead (see {@link createRealm}), which is what makes
 * the denial affordable: `Object.keys`, `Object.entries` and the rest still
 * work, because the shim carries those functions without carrying the object
 * graph they hang off.
 */
const HOST_BRIDGES: WeakSet<object> = buildHostBridges();

function buildHostBridges(): WeakSet<object> {
  const bridges = new WeakSet<object>();
  const add = (v: unknown): void => {
    if (v !== null && (typeof v === "object" || typeof v === "function")) {
      bridges.add(v as object);
    }
  };
  /** Add a value's whole prototype chain, and each link's constructor. */
  const walk = (value: unknown): void => {
    let proto: unknown = Object.getPrototypeOf(Object(value) as object);
    while (proto !== null && proto !== undefined) {
      add(proto);
      const ctor = (proto as { constructor?: unknown }).constructor;
      if (typeof ctor === "function") {
        add(ctor);
        // `TypeError` reaches `Error` this way, and every function reaches
        // `Function` — the object the escape was actually after.
        let up: unknown = Object.getPrototypeOf(ctor);
        while (up !== null && up !== undefined) {
          add(up);
          up = Object.getPrototypeOf(up as object);
        }
      }
      proto = Object.getPrototypeOf(proto as object);
    }
  };

  // Seeds are *instances*, so the traversal derives the intrinsics rather than
  // naming them. Anything a script can produce lands on one of these chains.
  const seeds: unknown[] = [
    {},
    [],
    "",
    0,
    true,
    Symbol("seed"),
    BigInt(0),
    function seedFn() {},
    async function seedAsyncFn() {},
    function* seedGenFn() {},
    async function* seedAsyncGenFn() {},
    /seed/,
    new Date(0),
    new Map(),
    new Set(),
    new WeakMap(),
    new WeakSet(),
    Promise.resolve(),
    new Error("seed"),
    new TypeError("seed"),
    new RangeError("seed"),
    new ArrayBuffer(0),
    new Uint8Array(0),
    new DataView(new ArrayBuffer(0)),
    [][Symbol.iterator](),
    (function* seedGen() {})(),
  ];
  for (const seed of seeds) walk(seed);

  // Namespace objects have no instances to seed from, and `globalThis` is the
  // thing every escape is ultimately reaching for.
  add(globalThis);
  add(Math);
  add(JSON);
  add(Reflect);
  return bridges;
}

/**
 * Refuse a host intrinsic wherever one surfaces.
 *
 * Called on every value a script reads, calls or constructs. A script that
 * somehow obtains `Function` still cannot invoke it, and one that obtains
 * `Array.prototype` still cannot hand it to `defineProperty` — because the
 * realm has no `defineProperty` and the value never crosses the boundary.
 */
export function assertNotHostBridge(value: unknown, what: string): void {
  if (
    value !== null &&
    (typeof value === "object" || typeof value === "function") &&
    HOST_BRIDGES.has(value as object)
  ) {
    throw new ConfinementError(
      `${what} is a host-realm intrinsic and is not reachable from the confined realm`,
    );
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
  if (target === OBJECT_SHIM) {
    const withheld = WITHHELD_OBJECT_STATICS.get(name);
    if (withheld) throw new ConfinementError(withheld);
  }
  // Higher-order array methods must await script callbacks, which are always
  // async. Native `filter` would see a Promise, treat it as truthy, and keep
  // every element — a silent wrong answer. See `array-methods.ts`.
  if (Array.isArray(target) && ASYNC_ARRAY_METHODS.has(name)) {
    const replacement = arrayMethod(target, name);
    if (replacement) return replacement;
  }
  const value = (target as Record<PropertyKey, unknown>)[key];
  // Identity check before binding: `bind` mints a fresh function object, so a
  // bound `Function` would no longer be recognisable as `Function`.
  assertNotHostBridge(value, `"${name}"`);
  // Methods must stay bound to their receiver: the evaluator calls them
  // detached, and an unbound `String.prototype.slice` would lose `this`.
  if (typeof value === "function") {
    return (value as (...a: unknown[]) => unknown).bind(target);
  }
  return value;
}

/* ------------------------------------------------------------------------ *
 * Shims: the standard library without the object graph behind it.
 * ------------------------------------------------------------------------ */

/**
 * Copy a host intrinsic's statics onto a shim, skipping anything that is
 * itself a bridge.
 *
 * The skip is by identity, so `Array.prototype` and `Promise.prototype` drop
 * out without being named, and a static the host adds later is carried over
 * only if it is safe by the same rule. Each function is bound to its original
 * owner, so `Array.from` keeps working when it is later re-read off the shim
 * (a bound function ignores a second `bind`, which is what makes this stick).
 */
function staticsOf(owner: object): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const name of Object.getOwnPropertyNames(owner)) {
    // Function plumbing, not library surface.
    if (
      name === "prototype" ||
      name === "length" ||
      name === "name" ||
      name === "caller" ||
      name === "arguments"
    ) {
      continue;
    }
    const desc = Object.getOwnPropertyDescriptor(owner, name);
    // An accessor would run host code on read; only plain data crosses.
    if (!desc || !("value" in desc)) continue;
    const value = desc.value as unknown;
    if (
      value !== null &&
      (typeof value === "object" || typeof value === "function") &&
      HOST_BRIDGES.has(value as object)
    ) {
      continue;
    }
    out[name] =
      typeof value === "function"
        ? (value as (...a: unknown[]) => unknown).bind(owner)
        : value;
  }
  return out;
}

/**
 * A constructible stand-in for a host constructor.
 *
 * `new MapShim()` yields a real host `Map` — a constructor returning an object
 * overrides `this` — so instances behave exactly as before and their methods
 * still come off the host prototype through {@link readMember}. What the
 * script never gets is the constructor itself: the shim is a different
 * function object, so it is not in {@link HOST_BRIDGES} and the intrinsic it
 * wraps stays unreachable.
 *
 * `prototype` is pointed at the host's so `x instanceof Error` keeps its
 * ordinary meaning. Reading it is still denied — by key *and* by identity.
 */
function constructorShim<T>(
  ctor: new (...args: never[]) => T,
  callable: (...args: unknown[]) => unknown = (...args) =>
    new (ctor as new (...a: unknown[]) => T)(...args),
): (...args: unknown[]) => unknown {
  const shim = function shimmed(...args: unknown[]): unknown {
    return callable(...args);
  };
  Object.defineProperty(shim, "name", {
    value: (ctor as { name: string }).name,
  });
  shim.prototype = (ctor as unknown as { prototype: object }).prototype;
  Object.assign(shim, staticsOf(ctor as unknown as object));
  // Frozen because the shims are process-wide singletons: without this, one
  // script could redefine `Array.isArray` for whatever script ran next in the
  // same process. The runner is one script per process, but `runQueryScript`
  // is callable in-process and a stale shim would be a silent cross-run leak.
  return Object.freeze(shim);
}

/**
 * `Object` minus reflection.
 *
 * The split is not arbitrary: everything kept reads or copies *data* a script
 * already holds, and everything dropped navigates the object *graph*.
 * `getPrototypeOf`, `getOwnPropertyDescriptor(s)`, `getOwnPropertyNames`,
 * `getOwnPropertySymbols`, `setPrototypeOf`, `defineProperty`,
 * `defineProperties` and `create` are all in the second group, and each of
 * them was a working escape.
 *
 * §19.16 and the real-data benchmark show model-authored code reaching for
 * `keys`, `values`, `entries`, `assign` and `fromEntries` constantly, so those
 * are the point of the exercise rather than a concession.
 */
/**
 * Reflection statics the `Object` shim withholds, and why — for the message.
 *
 * **This is diagnostics, not the boundary.** The boundary is that the shim
 * simply does not carry these functions, and that {@link HOST_BRIDGES} refuses
 * the objects they used to return. Without an explanation, though, a script
 * calling `Object.getPrototypeOf` gets `... is not a function`, which reads as
 * an ordinary bug: the model would spend its single repair turn re-typing the
 * same call. Naming the denial makes it actionable on the spot, exactly as
 * {@link DELIBERATELY_ABSENT} does for absent globals.
 */
const WITHHELD_OBJECT_STATICS = new Map<string, string>(
  [
    "getPrototypeOf",
    "setPrototypeOf",
    "getOwnPropertyDescriptor",
    "getOwnPropertyDescriptors",
    "getOwnPropertyNames",
    "getOwnPropertySymbols",
    "defineProperty",
    "defineProperties",
    "create",
  ].map((name) => [
    name,
    `\`Object.${name}\` is not available: it navigates the object graph, ` +
      `which is how a script would reach out of the confined realm. Work with ` +
      `the data directly — \`Object.keys\`, \`Object.values\`, ` +
      `\`Object.entries\`, \`Object.fromEntries\` and \`Object.assign\` are all ` +
      `available.`,
  ]),
);

const OBJECT_SHIM: Record<string, unknown> = Object.freeze({
  keys: Object.keys.bind(Object),
  values: Object.values.bind(Object),
  entries: Object.entries.bind(Object),
  fromEntries: Object.fromEntries.bind(Object),
  assign: Object.assign.bind(Object),
  freeze: Object.freeze.bind(Object),
  isFrozen: Object.isFrozen.bind(Object),
  is: Object.is.bind(Object),
  hasOwn: Object.hasOwn.bind(Object),
  ...(typeof (Object as { groupBy?: unknown }).groupBy === "function"
    ? {
        groupBy: (
          Object as unknown as { groupBy: (...a: unknown[]) => unknown }
        ).groupBy.bind(Object),
      }
    : {}),
});

const ARRAY_SHIM = constructorShim(Array, (...args) =>
  // `Array(3)` and `Array(1, 2)` differ, and `new Array(...)` must match both.
  Array(...(args as [])),
);
const MAP_SHIM = constructorShim(Map);
const SET_SHIM = constructorShim(Set);
const DATE_SHIM = constructorShim(Date);
const REGEXP_SHIM = constructorShim(RegExp);
const ERROR_SHIM = constructorShim(Error);
const TYPE_ERROR_SHIM = constructorShim(TypeError);
const RANGE_ERROR_SHIM = constructorShim(RangeError);
const NUMBER_SHIM = constructorShim(
  Number as unknown as new (...a: never[]) => number,
  (...args) => Number(args[0]),
);
const STRING_SHIM = constructorShim(
  String as unknown as new (...a: never[]) => string,
  (...args) => (args.length === 0 ? "" : String(args[0])),
);
const BOOLEAN_SHIM = constructorShim(
  Boolean as unknown as new (...a: never[]) => boolean,
  (...args) => Boolean(args[0]),
);
const PROMISE_SHIM: Record<string, unknown> = Object.freeze(staticsOf(Promise));
const MATH_SHIM: Record<string, unknown> = Object.freeze(staticsOf(Math));
const JSON_SHIM: Record<string, unknown> = Object.freeze(staticsOf(JSON));

/**
 * The shims a script may use with `new`.
 *
 * The evaluator checks against this rather than against host constructors,
 * which are no longer nameable — see {@link assertNotHostBridge}.
 */
export const CONSTRUCTIBLE: ReadonlySet<unknown> = new Set<unknown>([
  ARRAY_SHIM,
  MAP_SHIM,
  SET_SHIM,
  DATE_SHIM,
  REGEXP_SHIM,
  ERROR_SHIM,
  TYPE_ERROR_SHIM,
  RANGE_ERROR_SHIM,
]);

/**
 * Build the set of globals a script may name.
 *
 * Deliberately excluded and worth stating: no `Function`, no `eval`, no
 * `require`/`import`, no `process`, no `globalThis` (which would re-expose
 * everything), no timers (a script has a wall-clock budget, not a scheduler),
 * and no network of any kind — egress is denied at the OS layer, and naming it
 * here would only produce confusing failures.
 *
 * **Nothing bound here is a host intrinsic.** Binding one by reference is what
 * re-exposed the whole host object graph through reflection; the entries below
 * are shims that carry the library surface without the graph. The realm's
 * stated rule — "a script may reach exactly these bindings and nothing else" —
 * only became true once that changed.
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
    ["Math", MATH_SHIM],
    ["JSON", JSON_SHIM],
    ["Date", DATE_SHIM],
    ["Number", NUMBER_SHIM],
    ["String", STRING_SHIM],
    ["Boolean", BOOLEAN_SHIM],
    ["Array", ARRAY_SHIM],
    ["Object", OBJECT_SHIM],
    ["Map", MAP_SHIM],
    ["Set", SET_SHIM],
    ["RegExp", REGEXP_SHIM],
    ["Error", ERROR_SHIM],
    ["TypeError", TYPE_ERROR_SHIM],
    ["RangeError", RANGE_ERROR_SHIM],
    ["Promise", PROMISE_SHIM],
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
