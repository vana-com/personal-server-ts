/**
 * Semantic Versioning 2.0.0 precedence, strictly: `MAJOR.MINOR.PATCH`, an
 * optional `-pre.release` and an optional `+build` (ignored for order). A
 * string that is not one is `null`: the caller decides what an unknown order
 * means. (The publish plan's `compareConnectorVersions` reads any digits as a
 * version; the cursor's version rule needs to know when it cannot tell.)
 */
const SEMVER =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

interface Parsed {
  readonly core: readonly [bigint, bigint, bigint];
  readonly pre: readonly string[];
}

function parse(version: string): Parsed | null {
  const m = SEMVER.exec(version);
  if (!m) return null;
  return {
    core: [BigInt(m[1]!), BigInt(m[2]!), BigInt(m[3]!)],
    pre: m[4] === undefined ? [] : m[4].split("."),
  };
}

const numeric = (id: string) => /^\d+$/.test(id);

function comparePre(a: readonly string[], b: readonly string[]): number {
  // A version with no pre-release is higher than one with one.
  if (a.length === 0 || b.length === 0) return b.length - a.length;
  for (let i = 0; i < Math.min(a.length, b.length); i += 1) {
    const x = a[i]!;
    const y = b[i]!;
    if (x === y) continue;
    if (numeric(x) && numeric(y)) return BigInt(x) < BigInt(y) ? -1 : 1;
    if (numeric(x)) return -1;
    if (numeric(y)) return 1;
    return x < y ? -1 : 1;
  }
  return a.length - b.length;
}

/** -1, 0 or 1 as `a` is lower, equal or higher than `b`; null if either is not semver. */
export function compareSemver(a: string, b: string): -1 | 0 | 1 | null {
  const pa = parse(a);
  const pb = parse(b);
  if (!pa || !pb) return null;
  for (let i = 0; i < 3; i += 1)
    if (pa.core[i] !== pb.core[i]) return pa.core[i]! < pb.core[i]! ? -1 : 1;
  return Math.sign(comparePre(pa.pre, pb.pre)) as -1 | 0 | 1;
}
