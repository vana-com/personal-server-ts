import { execFileSync, spawn } from "node:child_process";
import { mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
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
 *  macOS, not by a kernel limit — see {@link buildEnforcement}. */
const RSS_POLL_MS = 50;

function shQuote(s: string): string {
  return `'${s.replaceAll("'", `'\\''`)}'`;
}

/**
 * Build the `ulimit` preamble. These are POSIX shell built-ins that call
 * `setrlimit(2)` before `exec`, so they apply to the Node process and every
 * child it spawns.
 *
 * Platform reality, measured on macOS 26.5 / arm64:
 * - `ulimit -t` (RLIMIT_CPU) **works** — SIGXCPU, exit 152.
 * - `ulimit -v` (RLIMIT_AS) is **rejected by the kernel**
 *   ("cannot modify limit: Invalid argument") and a 4GB allocation then
 *   succeeds. We still emit it, guarded, because it does work on Linux.
 * - `ulimit -u` (RLIMIT_NPROC) is accepted and bounds fork bombs.
 */
function ulimitPreamble(spec: SandboxSpec): string {
  const cpuSeconds = Math.max(1, Math.ceil(spec.cpuMs / 1000));
  const parts = [
    // `|| true` so a kernel that rejects a limit does not abort the run;
    // `enforcement` reports what actually took effect.
    `ulimit -t ${cpuSeconds} 2>/dev/null || true`,
    `ulimit -c 0 2>/dev/null || true`,
  ];
  if (spec.maxProcesses !== undefined) {
    parts.push(`ulimit -u ${spec.maxProcesses} 2>/dev/null || true`);
  }
  if (process.platform === "linux") {
    // RLIMIT_AS in kilobytes. Linux enforces this; macOS does not.
    parts.push(`ulimit -v ${spec.memoryMb * 1024} 2>/dev/null || true`);
  }
  return parts.join("; ");
}

/**
 * What this platform actually enforces. `false` is a fact to surface, not to
 * hide — plan §4.3, "reduced capability must be visible".
 */
function buildEnforcement(sandboxAvailable: boolean): SandboxEnforcement {
  const linux = process.platform === "linux";
  const notes: string[] = [];
  if (!sandboxAvailable) {
    notes.push(
      "OS sandbox unavailable on this platform/installation; filesystem and network are NOT confined",
    );
  }
  if (!linux) {
    notes.push(
      "RLIMIT_AS is rejected by the macOS kernel, and neither RLIMIT_DATA nor --max-old-space-size bounds Buffer/external memory (measured: 4GB allocated under all three). Total memory is bounded by an RSS watchdog sampling every " +
        RSS_POLL_MS +
        "ms, so a burst allocation between samples can briefly exceed memoryMb.",
    );
  }
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
    await sm.initialize({
      filesystem: {
        denyRead: broadDenyRead(),
        // Re-allow exactly the granted files plus the scratch dir, resolved
        // so they match the kernel's view of the same paths.
        allowRead: [...spec.readPaths, spec.writePath].map(realOrSelf),
        allowWrite: [realOrSelf(spec.writePath)],
        denyWrite: [],
      },
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

      // Memory watchdog. On macOS this is the *only* mechanism that bounds
      // total process memory (see buildEnforcement notes), so it samples the
      // whole process group, not just the direct child.
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
          // Never swallow this. On macOS the watchdog is the *only* thing
          // bounding memory, so a broken watchdog means the memory budget is
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
