import { execFileSync, spawn } from "node:child_process";
import {
  existsSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createRequire } from "node:module";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type { SandboxManager } from "@anthropic-ai/sandbox-runtime";
import type {
  Sandbox,
  SandboxEnforcement,
  SandboxResult,
  SandboxSpec,
  SandboxTermination,
} from "@opendatalabs/personal-server-ts-core/query";

/**
 * ASRT exports `SandboxManager` as a singleton value, not a class, so its
 * type is the value's type. Aliased because it is referenced before the
 * dynamic `import()` that actually loads it.
 */
type SandboxManagerApi = typeof SandboxManager;

/**
 * Node implementation of the query-layer {@link Sandbox}.
 *
 * Two layers, per design §19.7:
 *
 * - **OS enforcement** comes from `@anthropic-ai/sandbox-runtime` (ASRT):
 *   Seatbelt on macOS, bubblewrap+seccomp on Linux, a restricted user on
 *   Windows. ASRT is a *command wrapper* — `wrapWithSandboxArgv` hands back
 *   an argv and an env for us to spawn — not a process supervisor.
 * - **Resource limits are entirely ours.** ASRT has no CPU, memory, or
 *   process-count surface at all (verified against 0.0.74's shipped config
 *   schema: 16 top-level keys, none resource-related, and no
 *   `rlimit`/`setrlimit`/`cgroup` string anywhere in its JS). Because ASRT
 *   never spawns the process it could not impose them even in principle. So
 *   we impose them at spawn, and report honestly which ones the platform
 *   actually enforces.
 *
 * ## The read-policy trap
 *
 * ASRT's read model is **allow-by-default, deny-then-allow**: `allowRead`
 * *re-allows* within regions denied by `denyRead`, and on its own it does
 * nothing. A configuration of `allowRead: [grantedPaths]` with no `denyRead`
 * leaves the entire filesystem readable — measured: such a config read
 * `/etc/passwd` in full. `readPaths` in {@link SandboxSpec} is written as an
 * allowlist, so this implementation converts it into deny-broad +
 * allow-narrow rather than passing it through.
 */

const SANDBOX_RUNTIME_VERSION = "0.0.74";

/**
 * Process-wide serialisation of sandboxed runs.
 *
 * ASRT exports `SandboxManager` as a module-level **singleton**, so its
 * filesystem and network policy is process-global. Two overlapping
 * `initialize()` calls therefore clobber each other, and this is not
 * theoretical: with a per-instance lock, two concurrent runs under different
 * grants left one of them unable to read even its own script, silently
 * producing an empty result. A per-instance queue cannot fix that because
 * the contended resource is not per-instance — the lock has to live where
 * the singleton does.
 *
 * The cost is that query throughput is one script at a time per process.
 * That is the correct trade until ASRT exposes a per-run manager: the
 * alternative is a run executing under another consumer's read policy.
 */
let globalRunQueue: Promise<unknown> = Promise.resolve();

/**
 * Regions denied wholesale before the granted paths are re-allowed.
 *
 * We deny the data-bearing regions rather than `/`, because the sandboxed
 * process still has to read the Node binary and the system libraries it
 * links against. `/usr`, `/System` and `/bin` therefore stay readable; they
 * hold no user data. Everything that could hold user data, credentials or
 * another request's scratch is denied here.
 */
function broadDenyRead(): string[] {
  const denies = [
    homedir(),
    "/etc",
    "/private/etc",
    // Temp roots hold other processes' scratch, including other requests'.
    // Our own run directory is re-allowed by realpath in the allow list.
    // Note: /var itself is NOT denied — `/var/select/sh` is how macOS
    // resolves /bin/sh, and denying it stops the sandbox launching at all.
    "/tmp",
    "/private/tmp",
    "/var/tmp",
    "/private/var/tmp",
    "/var/folders",
    "/private/var/folders",
    "/Volumes",
    "/mnt",
    "/media",
    "/home",
    "/root",
    "/proc",
    "/sys",
  ];
  return [...new Set(denies)];
}

/**
 * macOS reaches most of these through symlinks (`/var` -> `/private/var`,
 * `/tmp` -> `/private/tmp`), and the kernel policy matches on the *resolved*
 * path. An allow entry that is not resolved therefore fails to re-open a
 * region a resolved deny entry closed — which manifests as the sandbox being
 * unable to read its own script. Resolve every allow entry.
 */
function realOrSelf(p: string): string {
  try {
    return realpathSync(p);
  } catch {
    return p;
  }
}

/**
 * The one host binary the Linux sandbox must be able to exec *inside* its own
 * namespace.
 *
 * ASRT's Linux path is two-stage: `bwrap` builds the namespace, then execs
 * ASRT's own `apply-seccomp` helper inside it to install the seccomp filter
 * and become PID 1 of a nested PID namespace. ASRT resolves that helper on
 * the **host** — a plain `existsSync` over its vendor directory — and then
 * uses the same absolute path inside the namespace.
 *
 * The trap is that `denyRead` on Linux is not a kernel policy the way
 * Seatbelt's is: it is `--tmpfs <dir>`. A denied directory is *replaced*, so
 * nothing beneath it exists in the namespace at all. {@link broadDenyRead}
 * denies `/home` and the user's home directory, and a checkout under either
 * — `/home/runner/work/...` on a GitHub runner, `~/src/...` on a Linux
 * workstation — puts
 * `node_modules/@anthropic-ai/sandbox-runtime/vendor/seccomp/<arch>/apply-seccomp`
 * inside that tmpfs. The helper then fails to exec with ENOENT and *every*
 * run dies before the script starts, control cases included.
 *
 * Measured on ubuntu-24.04 / x86_64: `ls` of the helper inside
 * `bwrap --ro-bind / / --tmpfs /home` reports "No such file or directory",
 * and a single `--ro-bind <helper> <helper>` restores it. That is what
 * putting the helper in `allowRead` emits.
 *
 * macOS never exercises this: Seatbelt applies a kernel policy over the real
 * filesystem — nothing is unmounted — and needs no helper binary at all.
 *
 * Re-allowing this one file is deliberately *not* a widening of the
 * grant-derived read allowlist. It is a statically linked binary shipped
 * inside ASRT, holding no user data, in a namespace where `/usr`, `/bin` and
 * `/lib` are already readable through bwrap's `--ro-bind / /`. No path that
 * could carry user data becomes readable, so the property
 * `hostile-scripts.test.ts` asserts — a script reads its granted scope paths
 * and the run scratch dir, nothing else — is unchanged.
 *
 * The path is also handed back to ASRT as `seccomp.applyPath`, which it uses
 * verbatim ahead of its own lookup. That makes "the path we re-allow" and
 * "the path it execs" the same string by construction rather than by two
 * lookups happening to agree.
 */
function linuxSeccompHelperPath(): string | undefined {
  if (process.platform !== "linux") return undefined;
  // Mirrors ASRT's own `getVendorArchitecture()`; it ships no other builds.
  const arch =
    process.arch === "x64" ? "x64" : process.arch === "arm64" ? "arm64" : null;
  if (arch === null) return undefined;
  try {
    const resolveFrom = createRequire(import.meta.url);
    const packageRoot = dirname(
      resolveFrom.resolve("@anthropic-ai/sandbox-runtime/package.json"),
    );
    const helper = join(
      packageRoot,
      "vendor",
      "seccomp",
      arch,
      "apply-seccomp",
    );
    return existsSync(helper) ? helper : undefined;
  } catch {
    // Nothing to re-allow. ASRT falls back to its own lookup and, if that
    // also fails, reports seccomp as unavailable through `checkDependencies`.
    return undefined;
  }
}

/**
 * Build the child's environment from scratch rather than inheriting.
 *
 * `wrapWithSandboxArgv` returns an env derived from `process.env`, so
 * spreading it hands the host's entire environment — API keys, tokens,
 * `INFERENCE_API_KEY` — to model-authored code. No filesystem policy covers
 * that channel: the values are already in memory. Measured: a canary set in
 * the parent was readable inside the sandbox when the returned env was
 * spread.
 *
 * So we take only the variables ASRT *introduced or changed* (its proxy and
 * sandbox plumbing, which the wrapper needs to work) and drop every variable
 * inherited unchanged from the host.
 */
function minimalEnv(
  sandboxEnv: NodeJS.ProcessEnv,
  scratch: string,
): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = {
    PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
    HOME: scratch,
    TMPDIR: scratch,
    LANG: "C",
  };
  for (const [k, v] of Object.entries(sandboxEnv)) {
    if (v === undefined) continue;
    // Only what the sandbox wrapper itself added or rewrote.
    if (process.env[k] !== v) out[k] = v;
  }
  return out;
}

/** Wall-clock grace beyond the CPU limit before we escalate to SIGKILL. */
const KILL_GRACE_MS = 2_000;
/** How often the RSS watchdog samples. Memory is bounded by sampling on
 *  every platform, not by a kernel limit — see {@link buildEnforcement}. */
const RSS_POLL_MS = 50;

function shQuote(s: string): string {
  return `'${s.replaceAll("'", `'\\''`)}'`;
}

/**
 * Build the `ulimit` preamble. These are POSIX shell built-ins that call
 * `setrlimit(2)` before `exec`, so they apply to the Node process and every
 * child it spawns.
 *
 * The shell is not the same shell on both platforms, and that matters more
 * than it looks: macOS `/bin/sh` is bash, Ubuntu's is **dash**, and their
 * `ulimit` built-ins do not accept the same options. A limit spelled for one
 * is silently absent on the other, because every line here is guarded with
 * `|| true` so that a kernel or shell rejecting one limit cannot abort the
 * run. Silence is the price of that guard, so each limit below is written to
 * work on both, and each claim is measured.
 *
 * Platform reality, measured on macOS 26.5 / arm64 and on ubuntu-24.04:
 * - `ulimit -t` (RLIMIT_CPU) works on both, with the soft/hard split below.
 * - RLIMIT_NPROC is `-u` in bash and `-p` in dash, so both are attempted.
 * - `ulimit -v` (RLIMIT_AS) is emitted on **neither**, and this is the
 *   deliberate part.
 *
 * RLIMIT_AS bounds *virtual address space*, which is not the quantity
 * `memoryMb` is about. V8 reserves a large virtual range up front regardless
 * of how small its heap is, so `ulimit -v` set to a realistic memory budget
 * does not cap a runaway allocation — it stops Node from starting at all.
 * Measured on ubuntu-24.04: `ulimit -v 262144` (the suite's 256MB budget)
 * followed by `node -e 'console.log(42)'` never reaches the script. macOS
 * rejects the limit outright ("cannot modify limit: Invalid argument") and a
 * 4GB allocation then succeeds, so it never enforced anything there either.
 *
 * An unusably coarse limit is not containment, and emitting it under
 * `|| true` made it look like one. Memory is bounded by the RSS watchdog in
 * `runOne`, on every platform, and {@link buildEnforcement} says so.
 */
function ulimitPreamble(spec: SandboxSpec): string {
  const cpuSeconds = Math.max(1, Math.ceil(spec.cpuMs / 1000));
  const parts = [
    // RLIMIT_CPU, deliberately as a *split* soft/hard pair: `ulimit -t N`
    // sets both, then `-S -t` lowers the soft one. With soft == hard the
    // kernel raises SIGXCPU and escalates to SIGKILL in the same instant, and
    // the run surfaces as a bare exit 137 that `runOne` cannot tell from any
    // other kill — measured on ubuntu-24.04, where the budget fired within
    // 21ms of `cpuMs` and was still classified `error` rather than `cpu`.
    // (macOS delivered SIGXCPU cleanly, which is why this went unseen.) One
    // second of headroom lets SIGXCPU land first — exit 152, which `runOne`
    // does recognise — while the hard limit remains the backstop for a
    // process that tries to ignore it.
    `ulimit -t ${cpuSeconds + 1} 2>/dev/null || true`,
    `ulimit -S -t ${cpuSeconds} 2>/dev/null || true`,
    `ulimit -c 0 2>/dev/null || true`,
  ];
  if (spec.maxProcesses !== undefined) {
    // RLIMIT_NPROC. `-u` is the bash spelling; dash's ulimit has no `-u` at
    // all and spells this limit `-p`. Emitting only `-u` under `|| true` left
    // the process cap silently absent on every Linux run while
    // `enforcement.processCount` went on claiming it — measured: a
    // 400-process fork bomb under `maxProcesses: 24` produced
    // "ulimit: Illegal option -u" and ran until the *memory* watchdog stopped
    // it. `-p` is pipe size in bash, so it is only ever reached on a shell
    // where `-u` failed.
    parts.push(
      `ulimit -u ${spec.maxProcesses} 2>/dev/null || ulimit -p ${spec.maxProcesses} 2>/dev/null || true`,
    );
  }
  return parts.join("; ");
}

/**
 * What this platform actually enforces. `false` is a fact to surface, not to
 * hide — plan §4.3, "reduced capability must be visible".
 */
function buildEnforcement(sandboxAvailable: boolean): SandboxEnforcement {
  const notes: string[] = [];
  if (!sandboxAvailable) {
    notes.push(
      "OS sandbox unavailable on this platform/installation; filesystem and network are NOT confined",
    );
  }
  if (sandboxAvailable && process.platform === "linux") {
    // Not a reduced capability, but a materially different shape of denial,
    // and a consumer that assumes the macOS shape will misread it. Measured
    // on ubuntu-24.04 (both architectures) — see design §19.7.1.
    notes.push(
      "Linux confines by namespace, not by kernel permission check: a read-denied directory is replaced with an empty private tmpfs rather than returning EACCES, so operations against it succeed against nothing instead of failing. Measured: the home directory lists only sandbox scaffolding and none of the host's contents; a write outside the scratch dir appears to succeed into that tmpfs and is discarded, with no file ever created on the host; /proc is a fresh namespace-private procfs holding two PIDs and the run's own already-scrubbed environ; and a listening socket binds inside an unshared network namespace that nothing outside can reach. Confinement holds in every one of those cases — but a script observing its own syscalls sees success where macOS returns an error.",
    );
    notes.push(
      "KNOWN GAP, Linux: the contents of ~/.npm/_logs are readable inside the sandbox. ASRT unconditionally unions its getDefaultWritePaths() into the write allow-list, which on Linux means a bind mount that survives our denyRead of the home directory. Measured: a host-planted file in that directory was read back in full from inside a run. Not closable through the 0.0.74 config — denyWrite makes the bind read-only, not absent.",
    );
  }
  if (sandboxAvailable) {
    // Both platforms. Reported unconditionally because it is a write that
    // reaches the host filesystem outside the scratch dir, which is exactly
    // what `filesystemWrite: true` would otherwise be taken to exclude.
    notes.push(
      "KNOWN GAP, all platforms: a sandboxed script can create files under ASRT's default write paths — ~/.npm/_logs, ~/.claude/debug, /tmp/claude, /private/tmp/claude — and they land on the real host filesystem. ASRT unions these into the write allow-list regardless of our allowWrite, and its own source warns they 'may allow access to files from other processes'. Measured on macOS (write only; reads denied EPERM) and Linux (read and write). Closable by naming those paths in filesystem.denyWrite, which is a security decision not yet taken.",
    );
  }
  // The memory caveat is the same on both platforms, and used to be reported
  // only on macOS because Linux was assumed to have a kernel limit behind it.
  // It does not: see `ulimitPreamble`. Claiming a limit we do not impose is
  // exactly the kind of thing `SandboxEnforcement` exists to prevent.
  notes.push(
    "Total memory is bounded by an out-of-process RSS watchdog sampling every " +
      RSS_POLL_MS +
      "ms, on every platform, so a burst allocation between samples can briefly exceed memoryMb. No kernel limit backs it: macOS rejects RLIMIT_AS outright and bounds neither Buffer nor external memory through RLIMIT_DATA or --max-old-space-size (measured: 4GB allocated under all three), and on Linux RLIMIT_AS bounds virtual address space rather than resident memory — set to a realistic memoryMb it stops Node starting at all rather than capping it.",
  );
  return {
    filesystemRead: sandboxAvailable,
    filesystemWrite: sandboxAvailable,
    network: sandboxAvailable,
    cpu: true,
    memory: true,
    processCount: true,
    wallClock: true,
    notes,
  };
}

export interface NodeSandboxOptions {
  /**
   * The server's data root. Every `readPaths` entry must resolve inside it;
   * see `resolveReadPaths` in `./read-paths.js`, which callers should run
   * over grant-derived paths before building a {@link SandboxSpec}.
   */
  dataRoot: string;
  /** Node binary used to run scripts. Defaults to the current one. */
  nodePath?: string;
}

export function createNodeSandbox(options: NodeSandboxOptions): Sandbox {
  let manager: SandboxManagerApi | undefined;

  async function loadManager() {
    if (manager) return manager;
    const mod = await import("@anthropic-ai/sandbox-runtime");
    manager = mod.SandboxManager;
    return manager;
  }

  async function ensureInitialized(spec: SandboxSpec): Promise<boolean> {
    const sm = await loadManager();
    if (!sm.isSupportedPlatform()) return false;
    // See {@link linuxSeccompHelperPath}: on Linux `denyRead` unmounts, so
    // the sandbox's own helper has to be bound back in or nothing runs.
    // Deliberately *not* passed through `realOrSelf` — Linux matches the
    // literal path against the deny prefixes and binds that same string, and
    // it is the literal path ASRT execs.
    const seccompHelper = linuxSeccompHelperPath();
    await sm.initialize({
      filesystem: {
        denyRead: broadDenyRead(),
        // Re-allow exactly the granted files plus the scratch dir, resolved
        // so they match the kernel's view of the same paths.
        allowRead: [
          ...[...spec.readPaths, spec.writePath].map(realOrSelf),
          ...(seccompHelper === undefined ? [] : [seccompHelper]),
        ],
        allowWrite: [realOrSelf(spec.writePath)],
        denyWrite: [],
      },
      ...(seccompHelper === undefined
        ? {}
        : { seccomp: { applyPath: seccompHelper } }),
      network: {
        // Zero egress. Not an allowlist with nothing in it by accident —
        // `denyNetwork: true` is non-negotiable in the spec type.
        allowedDomains: [],
        deniedDomains: [],
        strictAllowlist: true,
        allowUnixSockets: [],
        allowAllUnixSockets: false,
        allowLocalBinding: false,
      },
    });
    return true;
  }

  return {
    async capabilities() {
      const sm = await loadManager();
      if (!sm.isSupportedPlatform()) {
        return {
          available: false as const,
          reason: `@anthropic-ai/sandbox-runtime@${SANDBOX_RUNTIME_VERSION} does not support ${process.platform}`,
        };
      }
      const deps = sm.checkDependencies();
      if (deps && "ok" in deps && deps.ok === false) {
        return {
          available: false as const,
          reason: `sandbox dependencies missing: ${JSON.stringify(deps)}`,
        };
      }
      return { available: true as const, enforcement: buildEnforcement(true) };
    },

    run(script: string, spec: SandboxSpec): Promise<SandboxResult> {
      // Serialised process-wide — see `globalRunQueue`. Chaining here makes
      // the race impossible rather than relying on every caller to remember.
      const result = globalRunQueue.then(async () => {
        try {
          return await runOne(script, spec);
        } finally {
          // ASRT's documented lifecycle is initialize -> run -> reset(), and
          // the singleton keeps session state (on Windows, actual filesystem
          // ACEs) between runs. Without this teardown a *second* run under a
          // different policy silently produced no output at all — it could
          // not read even its own script. Always reset, including after a
          // failure, or the next consumer's run is the one that breaks.
          try {
            const sm = await loadManager();
            sm.cleanupAfterCommand();
            await sm.reset();
          } catch {
            // Teardown failure must not mask the run's own result; the next
            // run re-initializes from scratch regardless.
          }
        }
      });
      globalRunQueue = result.catch(() => undefined);
      return result;
    },
  };

  async function runOne(
    script: string,
    spec: SandboxSpec,
  ): Promise<SandboxResult> {
    {
      const started = Date.now();
      const scratch = mkdtempSync(join(spec.writePath, "run-"));
      const scriptPath = join(scratch, "script.js");
      writeFileSync(scriptPath, script, { mode: 0o400 });

      let sandboxAvailable = false;
      try {
        sandboxAvailable = await ensureInitialized(spec);
      } catch (err) {
        rmSync(scratch, { recursive: true, force: true });
        return {
          stdout: "",
          stderr: `sandbox initialization failed: ${(err as Error).message}`,
          exitCode: -1,
          timedOut: false,
          truncated: false,
          durationMs: Date.now() - started,
          termination: "sandboxUnavailable",
          enforcement: buildEnforcement(false),
          violations: [],
        };
      }
      if (!sandboxAvailable) {
        rmSync(scratch, { recursive: true, force: true });
        return {
          stdout: "",
          stderr:
            "refusing to run: no OS sandbox on this platform, and running model-authored code unconfined is not an option",
          exitCode: -1,
          timedOut: false,
          truncated: false,
          durationMs: Date.now() - started,
          termination: "sandboxUnavailable",
          enforcement: buildEnforcement(false),
          violations: [],
        };
      }

      const nodePath = options.nodePath ?? process.execPath;
      const inner = `${ulimitPreamble(spec)}; exec ${shQuote(nodePath)} ${shQuote(scriptPath)}`;

      const sm = await loadManager();
      const commandId = `query-${started}-${Math.random().toString(36).slice(2)}`;
      const { argv, env } = await sm.wrapWithSandboxArgv(
        `/bin/sh -c ${shQuote(inner)}`,
        undefined,
        undefined,
        undefined,
        scratch,
        { commandId },
      );

      const child = spawn(argv[0]!, argv.slice(1), {
        env: minimalEnv(env, scratch),
        cwd: scratch,
        stdio: ["ignore", "pipe", "pipe"],
      });

      let stdout = "";
      let stderr = "";
      let bytes = 0;
      let truncated = false;
      let termination: SandboxTermination | undefined;

      const finish = (reason: SandboxTermination) => {
        if (termination === undefined) termination = reason;
        child.kill("SIGKILL");
      };

      const collect = (chunk: Buffer, into: "out" | "err") => {
        bytes += chunk.length;
        if (bytes > spec.maxOutputBytes) {
          truncated = true;
          finish("outputCap");
          return;
        }
        if (into === "out") stdout += chunk.toString("utf8");
        else stderr += chunk.toString("utf8");
      };
      child.stdout.on("data", (c: Buffer) => collect(c, "out"));
      child.stderr.on("data", (c: Buffer) => collect(c, "err"));

      const wallTimer = setTimeout(() => {
        finish("wallClock");
      }, spec.wallClockMs);

      // Memory watchdog. This is the *only* mechanism that bounds total
      // process memory, on every platform (see buildEnforcement notes), so it
      // samples the whole process group, not just the direct child.
      let watchdogFailed: string | undefined;
      const rssTimer = setInterval(() => {
        if (child.pid === undefined) return;
        try {
          const out = execFileSync("ps", ["-Ao", "pid=,ppid=,rss="], {
            encoding: "utf8",
          });
          const rows = out
            .trim()
            .split("\n")
            .map((l) => l.trim().split(/\s+/).map(Number));
          // Sum RSS over the child and everything descended from it.
          const byParent = new Map<number, number[]>();
          const rssOf = new Map<number, number>();
          for (const [pid, ppid, rss] of rows) {
            if (pid === undefined || ppid === undefined || rss === undefined)
              continue;
            rssOf.set(pid, rss);
            byParent.set(ppid, [...(byParent.get(ppid) ?? []), pid]);
          }
          let total = 0;
          const stack = [child.pid];
          const seen = new Set<number>();
          while (stack.length > 0) {
            const pid = stack.pop()!;
            if (seen.has(pid)) continue;
            seen.add(pid);
            total += rssOf.get(pid) ?? 0;
            stack.push(...(byParent.get(pid) ?? []));
          }
          if (total / 1024 > spec.memoryMb) finish("memory");
        } catch (err) {
          // Never swallow this. The watchdog is the *only* thing bounding
          // memory anywhere, so a broken watchdog means the memory budget is
          // not enforced at all — and a silent catch here is exactly how that
          // ships unnoticed. Record it, stop claiming the enforcement, and
          // fail the run closed rather than letting it allocate freely.
          watchdogFailed = (err as Error).message;
          finish("memory");
        }
      }, RSS_POLL_MS);

      const exit = await new Promise<{ code: number; signal: string | null }>(
        (resolve) => {
          child.on("close", (code, signal) =>
            resolve({ code: code ?? -1, signal }),
          );
          child.on("error", () => resolve({ code: -1, signal: null }));
        },
      );

      clearTimeout(wallTimer);
      clearInterval(rssTimer);
      setTimeout(() => {
        rmSync(scratch, { recursive: true, force: true });
      }, KILL_GRACE_MS).unref();

      // SIGXCPU is RLIMIT_CPU firing: exit 152 via a shell, or the signal
      // directly. This is the CPU budget, not a wall-clock timeout.
      if (termination === undefined) {
        if (exit.signal === "SIGXCPU" || exit.code === 152) {
          termination = "cpu";
        } else if (exit.code === 0) {
          termination = "completed";
        } else {
          termination = "error";
        }
      }

      let violations: string[] = [];
      try {
        const store = sm.getSandboxViolationStore();
        const events = store?.getViolationsForCommand?.(commandId) ?? [];
        violations = events.map((e: unknown) =>
          typeof e === "string" ? e : JSON.stringify(e),
        );
      } catch {
        violations = [];
      }

      const enforcement = buildEnforcement(true);
      if (watchdogFailed !== undefined) {
        enforcement.memory = false;
        enforcement.notes.push(
          `memory watchdog failed (${watchdogFailed}); the memory budget was NOT enforced for this run`,
        );
      }

      return {
        stdout,
        stderr,
        exitCode: exit.code,
        timedOut: termination === "wallClock" || termination === "cpu",
        truncated,
        durationMs: Date.now() - started,
        termination,
        enforcement,
        violations,
      };
    }
  }
}

export { SANDBOX_RUNTIME_VERSION };
