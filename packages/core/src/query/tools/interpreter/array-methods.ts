/**
 * Await-aware array methods for the confined realm.
 *
 * Every function the evaluator builds is async, because a script callback must
 * be able to `await vana.classify(...)`. Native `Array.prototype.filter` then
 * sees a *Promise* — always truthy — and keeps every element, silently. That
 * is precisely the class of quiet wrongness this design exists to prevent, so
 * the higher-order methods are reimplemented here to await their callbacks.
 *
 * These operate on plain arrays and return plain arrays; they add no authority
 * and are reachable only through `readMember`.
 */

type Cb = (...args: unknown[]) => unknown;

const isThenable = (v: unknown): v is Promise<unknown> =>
  typeof v === "object" &&
  v !== null &&
  typeof (v as Promise<unknown>).then === "function";

const settle = async (v: unknown): Promise<unknown> =>
  isThenable(v) ? await v : v;

/** Method names whose callback may be async and must therefore be awaited. */
export const ASYNC_ARRAY_METHODS = new Set([
  "map",
  "filter",
  "forEach",
  "find",
  "findIndex",
  "findLast",
  "findLastIndex",
  "some",
  "every",
  "reduce",
  "reduceRight",
  "flatMap",
  "sort",
]);

export function arrayMethod(arr: unknown[], name: string): Cb | undefined {
  switch (name) {
    case "map":
      return async (cb) => {
        const out: unknown[] = [];
        for (let i = 0; i < arr.length; i++) {
          out.push(await settle((cb as Cb)(arr[i], i, arr)));
        }
        return out;
      };
    case "filter":
      return async (cb) => {
        const out: unknown[] = [];
        for (let i = 0; i < arr.length; i++) {
          if (await settle((cb as Cb)(arr[i], i, arr))) out.push(arr[i]);
        }
        return out;
      };
    case "forEach":
      return async (cb) => {
        for (let i = 0; i < arr.length; i++) {
          await settle((cb as Cb)(arr[i], i, arr));
        }
        return undefined;
      };
    case "find":
      return async (cb) => {
        for (let i = 0; i < arr.length; i++) {
          if (await settle((cb as Cb)(arr[i], i, arr))) return arr[i];
        }
        return undefined;
      };
    case "findIndex":
      return async (cb) => {
        for (let i = 0; i < arr.length; i++) {
          if (await settle((cb as Cb)(arr[i], i, arr))) return i;
        }
        return -1;
      };
    case "findLast":
      return async (cb) => {
        for (let i = arr.length - 1; i >= 0; i--) {
          if (await settle((cb as Cb)(arr[i], i, arr))) return arr[i];
        }
        return undefined;
      };
    case "findLastIndex":
      return async (cb) => {
        for (let i = arr.length - 1; i >= 0; i--) {
          if (await settle((cb as Cb)(arr[i], i, arr))) return i;
        }
        return -1;
      };
    case "some":
      return async (cb) => {
        for (let i = 0; i < arr.length; i++) {
          if (await settle((cb as Cb)(arr[i], i, arr))) return true;
        }
        return false;
      };
    case "every":
      return async (cb) => {
        for (let i = 0; i < arr.length; i++) {
          if (!(await settle((cb as Cb)(arr[i], i, arr)))) return false;
        }
        return true;
      };
    case "flatMap":
      return async (cb) => {
        const out: unknown[] = [];
        for (let i = 0; i < arr.length; i++) {
          const v = await settle((cb as Cb)(arr[i], i, arr));
          if (Array.isArray(v)) out.push(...v);
          else out.push(v);
        }
        return out;
      };
    case "reduce":
      return async (...args) => {
        const cb = args[0] as Cb;
        // Distinguish `reduce(fn)` from `reduce(fn, undefined)` by arity, the
        // way the native method does — an explicit undefined seed is legal.
        const hasSeed = args.length >= 2;
        let acc = hasSeed ? args[1] : arr[0];
        for (let i = hasSeed ? 0 : 1; i < arr.length; i++) {
          acc = await settle(cb(acc, arr[i], i, arr));
        }
        return acc;
      };
    case "reduceRight":
      return async (...args) => {
        const cb = args[0] as Cb;
        const hasSeed = args.length >= 2;
        let acc = hasSeed ? args[1] : arr[arr.length - 1];
        for (let i = hasSeed ? arr.length - 1 : arr.length - 2; i >= 0; i--) {
          acc = await settle(cb(acc, arr[i], i, arr));
        }
        return acc;
      };
    case "sort":
      // Merge sort so an awaited comparator is honoured. Native `sort` would
      // receive a Promise and order by nothing.
      return async (cb) => {
        const cmp = async (a: unknown, b: unknown): Promise<number> => {
          if (!cb)
            return String(a) < String(b) ? -1 : String(a) > String(b) ? 1 : 0;
          return Number(await settle((cb as Cb)(a, b)));
        };
        const merge = async (xs: unknown[]): Promise<unknown[]> => {
          if (xs.length <= 1) return xs;
          const mid = Math.floor(xs.length / 2);
          const l = await merge(xs.slice(0, mid));
          const r = await merge(xs.slice(mid));
          const out: unknown[] = [];
          let i = 0;
          let j = 0;
          while (i < l.length && j < r.length) {
            out.push((await cmp(l[i], r[j])) <= 0 ? l[i++] : r[j++]);
          }
          return [...out, ...l.slice(i), ...r.slice(j)];
        };
        const sorted = await merge([...arr]);
        // Match native `sort`: mutate in place and return the same array.
        for (let i = 0; i < sorted.length; i++) arr[i] = sorted[i];
        return arr;
      };
    default:
      return undefined;
  }
}
