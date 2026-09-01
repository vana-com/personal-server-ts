import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";

/**
 * Running the query sandbox from inside a `pkg` single-file binary.
 *
 * The desktop sidecar ships as a `pkg` build, and two of this layer's
 * assumptions stop holding there:
 *
 * - `process.execPath` is *the sidecar binary*, not a Node interpreter. The
 *   OS layer execs it to run the model's script, so under `pkg` it would
 *   re-enter the server's own entrypoint instead of running anything.
 * - Files bundled into the binary live on `pkg`'s virtual `/snapshot`
 *   filesystem. The host process reads them normally, but a `/snapshot` path
 *   cannot be exec'd and cannot be bind-mounted, so anything the *sandbox*
 *   itself must see has to exist as a real file first.
 *
 * Materialisation follows the frpc precedent in `../tunnel/binary.ts`:
 * `<root>/bin/`, install once, a sibling JSON version file so a stale copy is
 * replaced rather than trusted, and a temp file plus rename so a crashed
 * write never leaves a truncated binary behind.
 *
 * Everything here is gated on {@link isPackagedBinary}. Under a normal Node
 * process none of it runs and the OS layer behaves exactly as it always has.
 */

/**
 * `pkg`'s virtual filesystem roots.
 *
 * Both spellings ship in the same loader — POSIX builds mount `/snapshot`,
 * Windows builds `C:\snapshot` — and a binary built for one platform is read
 * by the other in CI, so match both regardless of `process.platform`.
 */
const SNAPSHOT_ROOTS = ["/snapshot", "C:\\snapshot"];

/**
 * The subset of `process` this module probes, so tests can hand it a
 * synthetic one instead of mutating the real global.
 */
export interface PackagedProcess {
  /** Set by the `pkg` loader to the bundled entrypoint. Absent under Node. */
  pkg?: unknown;
  versions: Partial<Record<string, string>>;
  execPath: string;
  env: Partial<Record<string, string>>;
}

/**
 * Is this process a `pkg` single-file binary?
 *
 * Both markers are installed by the loader before any user code runs:
 * `process.pkg` carries the bundled entrypoint and `process.versions.pkg` the
 * builder version. Either alone is conclusive — checking both means a future
 * build that stops setting one still reports honestly, and a plain Node
 * process has neither.
 */
export function isPackagedBinary(proc: PackagedProcess = process): boolean {
  return proc.pkg !== undefined || proc.versions.pkg !== undefined;
}

/**
 * Does this path live on `pkg`'s virtual filesystem?
 *
 * Prefix matching is deliberately anchored at a separator: a real directory
 * named `/snapshots` is not a snapshot path, and treating it as one would
 * send a perfectly bindable path down the materialisation route.
 */
export function isSnapshotPath(path: string): boolean {
  return SNAPSHOT_ROOTS.some(
    (root) =>
      path === root ||
      path.startsWith(root + "/") ||
      path.startsWith(root + "\\"),
  );
}

/**
 * Where materialised files go: the same `<root>/bin/` the tunnel layer
 * installs frpc into.
 */
export function packagedBinDir(storageRoot: string): string {
  return join(storageRoot, "bin");
}

/**
 * Outcome of looking for a Node interpreter the OS layer can actually exec.
 *
 * `bind` says whether the OS layer has to re-allow the path explicitly. The
 * read policy denies broadly and re-allows narrowly, so an interpreter inside
 * a denied region — `<root>/bin/node` sits under the user's home directory,
 * which {@link ../query/node-sandbox.ts `broadDenyRead`} denies — is invisible
 * to the sandbox unless it is named. It is set only when the interpreter is
 * *not* the one already running: in the ordinary Node case the resolved path
 * is `process.execPath`, nothing is added, and the emitted policy is
 * byte-identical to before this module existed.
 */
export type SandboxNodePath =
  | { readonly ok: true; readonly path: string; readonly bind: boolean }
  | { readonly ok: false; readonly reason: string };

export interface ResolveSandboxNodePathOptions {
  /** Explicit override. The embedder knows what it shipped; nothing beats it. */
  nodePath?: string;
  /** The server's data root, for the `<root>/bin/node` lookup. */
  storageRoot?: string;
  /** Test seams. */
  proc?: PackagedProcess;
  isFile?: (path: string) => boolean;
}

/**
 * A candidate has to be a regular file, not merely something that exists.
 * The resolved path is handed to the read policy as an allow entry, and a
 * directory there would re-allow the whole directory rather than one binary.
 */
function isRegularFile(path: string): boolean {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

/** Env var naming an interpreter, matching `PERSONAL_SERVER_ROOT_PATH`. */
export const NODE_PATH_ENV = "PERSONAL_SERVER_QUERY_NODE_PATH";

/** Name of the interpreter the sidecar is expected to install in `<root>/bin/`. */
export const PACKAGED_NODE_NAME =
  process.platform === "win32" ? "node.exe" : "node";

/**
 * Find a real Node interpreter for the OS layer to exec.
 *
 * Under a normal Node process this is `process.execPath` and always succeeds.
 * Under `pkg` that value is the sidecar itself, so it is refused outright and
 * the search runs, in descending order of how much the source knows:
 *
 * 1. an explicit `nodePath`,
 * 2. {@link NODE_PATH_ENV},
 * 3. `<root>/bin/node`, the frpc layout.
 *
 * There is deliberately no `PATH` search. The interpreter runs *inside* the
 * sandbox holding the run's read grants over the user's data, so picking up
 * whichever `node` happens to be first on `PATH` would let anything that can
 * prepend a directory choose the program that reads that data. Failing closed
 * with an actionable message is the correct outcome; a sandbox that starts
 * against an attacker-supplied interpreter is not.
 */
export function resolveSandboxNodePath(
  options: ResolveSandboxNodePathOptions = {},
): SandboxNodePath {
  const proc = options.proc ?? process;
  const fileExists = options.isFile ?? isRegularFile;
  const running = proc.execPath;

  const bindIfMoved = (path: string): SandboxNodePath => ({
    ok: true,
    path,
    bind: path !== running,
  });

  if (!isPackagedBinary(proc)) {
    // Unchanged behaviour: the interpreter running the server runs the script.
    return bindIfMoved(options.nodePath ?? running);
  }

  const tried: string[] = [];
  const candidates = [
    options.nodePath,
    proc.env[NODE_PATH_ENV],
    options.storageRoot === undefined
      ? undefined
      : join(packagedBinDir(options.storageRoot), PACKAGED_NODE_NAME),
  ];

  for (const candidate of candidates) {
    if (candidate === undefined || candidate === "") continue;
    tried.push(candidate);
    // The one mistake worth catching structurally: pointing us back at the
    // sidecar. Exec'ing it re-enters the server rather than running a script,
    // which fails in a way that looks nothing like a bad interpreter path.
    if (candidate === running) continue;
    if (isSnapshotPath(candidate)) continue;
    if (!fileExists(candidate)) continue;
    return bindIfMoved(candidate);
  }

  return {
    ok: false,
    reason:
      "running inside a pkg binary, where process.execPath is the server " +
      "itself rather than a Node interpreter. Ship a real node and name it " +
      `via the nodePath option, ${NODE_PATH_ENV}, or ` +
      `<root>/bin/${PACKAGED_NODE_NAME}` +
      (tried.length === 0 ? "" : ` (tried: ${tried.join(", ")})`),
  };
}

interface InstalledMetadata {
  version: string;
  platform: string;
  installedAt: string;
}

function metadataPath(destPath: string): string {
  return `${destPath}-version.json`;
}

function installedVersion(destPath: string): string | null {
  try {
    const meta: InstalledMetadata = JSON.parse(
      readFileSync(metadataPath(destPath), "utf-8"),
    );
    return meta.version ?? null;
  } catch {
    return null;
  }
}

export interface MaterializeOptions {
  /**
   * Bumping this replaces the installed copy. Callers pass whatever actually
   * identifies the bytes — for a vendored helper, the version of the package
   * that vendors it.
   */
  version: string;
  /** File mode; executables need `0o755`. */
  mode?: number;
}

/**
 * Copy a file out of the `pkg` snapshot onto the real filesystem.
 *
 * Returns the real path, which is what may then be exec'd or bind-mounted.
 * Called with an already-real path it is a no-op that returns it unchanged,
 * so callers do not have to branch on {@link isPackagedBinary} themselves.
 *
 * Synchronous on purpose: the OS layer resolves these paths from inside
 * `ensureInitialized`, which is already serialised process-wide, and a
 * one-off file copy there is cheaper than making the whole resolution async.
 */
export function materializeFromSnapshot(
  sourcePath: string,
  destDir: string,
  options: MaterializeOptions,
): string {
  if (!isSnapshotPath(sourcePath)) return sourcePath;

  const name = sourcePath.split(/[\\/]/).pop();
  if (name === undefined || name === "") {
    throw new Error(
      `Cannot materialize snapshot path ${sourcePath}: no file name`,
    );
  }
  const destPath = join(destDir, name);

  // Fast path, mirroring `ensureFrpcBinary`: the version file matches and the
  // file is still there. A version file without its file is not trusted.
  if (installedVersion(destPath) === options.version && existsSync(destPath)) {
    return destPath;
  }

  mkdirSync(destDir, { recursive: true });
  const bytes = readFileSync(sourcePath);
  // Write-then-rename so a crash mid-copy cannot leave a truncated file that
  // the next boot's version check would happily accept.
  const temp = join(destDir, `_${name}.partial`);
  writeFileSync(temp, bytes, { mode: options.mode ?? 0o644 });
  renameSync(temp, destPath);
  if (options.mode !== undefined) chmodSync(destPath, options.mode);
  writeFileSync(
    metadataPath(destPath),
    `${JSON.stringify(
      {
        version: options.version,
        platform: `${process.platform}_${process.arch}`,
        installedAt: new Date().toISOString(),
      } satisfies InstalledMetadata,
      null,
      2,
    )}\n`,
  );
  return destPath;
}
