import { realpathSync } from "node:fs";
import { isAbsolute, normalize, resolve, sep } from "node:path";

/**
 * Hardening for the grant -> `readPaths` computation.
 *
 * Design §3 risk 1: "Data under a grant is one bad `readPaths` computation
 * away from exposure." The OS policy faithfully allows whatever paths it is
 * given, so the *derivation* of that list is as security-critical as the
 * enforcement, and it is the part that lives in our code. Everything here is
 * about refusing to hand the policy a path that means something other than
 * what the caller thought it meant.
 */

export class ReadPathError extends Error {
  constructor(
    readonly path: string,
    readonly reason: string,
  ) {
    super(`Refusing read path ${JSON.stringify(path)}: ${reason}`);
    this.name = "ReadPathError";
  }
}

/** Paths that must never be granted, whatever the caller asks for. */
const FORBIDDEN_ROOTS = [
  "/",
  "/etc",
  "/dev",
  "/proc",
  "/sys",
  "/var/run",
  "/private/etc",
];

function isWithin(child: string, parent: string): boolean {
  if (child === parent) return true;
  const p = parent.endsWith(sep) ? parent : parent + sep;
  return child.startsWith(p);
}

/**
 * Resolve one grant-derived path into an absolute, symlink-free path safe to
 * hand to a sandbox policy, or throw.
 *
 * Rejects: relative paths, paths that normalize outside `confineTo`, paths
 * whose realpath escapes `confineTo` (the symlink case — the string looks
 * contained but the inode is not), and filesystem roots.
 *
 * `confineTo` is the data root the server owns; every granted scope file
 * must live under it. Passing it is what turns "trust the caller's string"
 * into a checked containment.
 */
export function resolveReadPath(input: string, confineTo: string): string {
  if (typeof input !== "string" || input.length === 0) {
    throw new ReadPathError(String(input), "empty");
  }
  if (input.includes("\0")) {
    throw new ReadPathError(input, "contains a NUL byte");
  }
  if (!isAbsolute(input)) {
    throw new ReadPathError(input, "not absolute");
  }

  const root = realpathSync(resolve(confineTo));
  const normalized = normalize(resolve(input));

  if (FORBIDDEN_ROOTS.includes(normalized)) {
    throw new ReadPathError(input, "is a forbidden system root");
  }

  // Containment must be judged on *resolved* paths on both sides, never on
  // the raw strings. Two reasons, and the second is a real bug we hit:
  //
  //  - A symlink inside the root pointing out of it passes any lexical
  //    check while reading data from outside. That is the leak this
  //    function exists to stop.
  //  - The root itself is commonly reached through a symlink (on macOS
  //    `/var` -> `/private/var`, so a tmpdir path and its realpath differ).
  //    Comparing a raw input against a resolved root rejects legitimate
  //    paths — and tempts whoever debugs it into loosening the check.
  let real: string;
  try {
    real = realpathSync(normalized);
  } catch (err) {
    // A path we cannot resolve is a path we cannot vouch for. Refusing is
    // correct: handing an unresolvable path to the policy means granting
    // whatever later appears at that name (a TOCTOU plant).
    throw new ReadPathError(
      input,
      `cannot be resolved: ${(err as Error).message}`,
    );
  }

  if (!isWithin(real, root)) {
    // One message for every escape. Whether it got out lexically or through
    // a symlink is diagnostics, not a distinct security case, and splitting
    // them invites callers to treat one as less serious.
    throw new ReadPathError(
      input,
      `escapes the data root: resolves to ${real}, outside ${root}`,
    );
  }

  return real;
}

/**
 * Resolve a whole grant's worth of paths. Deduplicates, and fails the entire
 * request if any single path is unsafe rather than silently dropping it — a
 * partially-applied grant is a coverage lie.
 */
export function resolveReadPaths(
  inputs: readonly string[],
  confineTo: string,
): string[] {
  const out = new Set<string>();
  for (const input of inputs) {
    out.add(resolveReadPath(input, confineTo));
  }
  return [...out].sort();
}
