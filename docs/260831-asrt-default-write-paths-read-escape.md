# `getDefaultWritePaths()` defeats `filesystem.denyRead`, and cannot be opted out of

Upstream bug report, drafted for `@anthropic-ai/sandbox-runtime`. Not filed.

- **Package:** `@anthropic-ai/sandbox-runtime`
- **Version:** `0.0.74` (pinned exactly in `packages/server/package.json:47`)
- **Platform where the read escape was measured:** ubuntu-24.04, bubblewrap
  0.9.0, arm64 (native) and x86_64
- **Also affected, write half only:** macOS/arm64 (Seatbelt)

Every line number below is against the shipped JS of 0.0.74 as published on
npm (`dist/…`), and every measurement is from
`docs/260828-query-layer-design.md` §19.7.1, which records the runs.

## Summary

`getDefaultWritePaths()` unions four host-wide directories —
`~/.npm/_logs`, `~/.claude/debug`, `/tmp/claude`, `/private/tmp/claude` — into
the write allow-list on every run, regardless of what the caller passed as
`filesystem.allowWrite`. There is no configuration surface that removes them.

On Linux that union does not only grant writes. Because the write allow-list
is implemented as a `--bind` of each path into the namespace, and because the
`denyRead` implementation re-binds allowed write paths back on top of the
tmpfs it just mounted, those four directories stay **readable** inside the
sandbox even when the caller explicitly denies reads of `$HOME` and `/tmp`.
A caller cannot express "do not grant these", and `denyWrite` does not help:
it maps to `denyWithinAllow`, which makes the bind read-only rather than
absent.

The result is that a sandboxed process reads host directories that the caller
denied and never granted — directories ASRT's own source describes as
possibly holding "files from other processes".

## Our configuration

We run model-generated JavaScript over one user's granted files. ASRT is the
OS layer of that sandbox. The whole config is in
`packages/server/src/query/node-sandbox.ts:501-530`; the filesystem half is:

```ts
await sm.initialize({
  filesystem: {
    denyRead: broadDenyRead(), // $HOME, /etc, /tmp, /private/tmp, /var/tmp,
    // /var/folders, /Volumes, /mnt, /media, /home, /root, /proc, /sys
    allowRead: [...spec.readPaths, spec.writePath].map(realOrSelf),
    allowWrite: [realOrSelf(spec.writePath)], // one per-run scratch dir
    denyWrite: asrtDefaultWritePathDenials(defaultWritePaths ?? []),
  },
  // network: zero egress
});
```

`broadDenyRead()` (`node-sandbox.ts:85-109`) denies the user's home directory
and both spellings of `/tmp` outright. `allowWrite` names exactly one
directory: a per-run scratch dir that is swept afterwards. Nothing in this
config asks for the default write paths, and nothing in it re-allows reads
under `$HOME` or `/tmp` except the run's own scratch dir.

## What happens

1. `SandboxManager` builds the write policy as
   `allowOnly: [...getDefaultWritePaths(), ...userAllowWrite]`
   (`dist/sandbox/sandbox-manager.js:1212`; the same union also appears at
   `:972` and `:946`). The caller's `allowWrite` is added to the defaults, and
   there is no flag, config key, or overload that yields the defaults-free set.
2. `getDefaultWritePaths()` (`dist/sandbox/sandbox-utils.js:369-383`) returns
   six character devices plus `/tmp/claude`, `/private/tmp/claude`,
   `$HOME/.npm/_logs` and `$HOME/.claude/debug`. Its own doc comment
   (`:362-368`, repeated in `dist/sandbox/sandbox-utils.d.ts:127-133`) reads:

   > WARNING: These default paths are intentionally broad for compatibility
   > but may allow access to files from other processes. In highly
   > security-sensitive environments, you should configure more restrictive
   > write paths.

   That is exactly what we tried to do, and the API does not permit it.

3. On Linux, `generateFilesystemArgs` starts from `--ro-bind / /`
   (`dist/sandbox/linux-sandbox-utils.js:702`) and then emits
   `--bind <p> <p>` for every entry of `allowOnly`
   (`linux-sandbox-utils.js:745`). So each default write path becomes a real
   bind mount of the host directory, readable and writable.
4. `denyRead` is then applied by mounting a tmpfs over each denied directory —
   and immediately re-binding the write paths the tmpfs covered
   (`linux-sandbox-utils.js:636-646`):

   ```js
   args.push("--tmpfs", normalizedPath);
   // tmpfs wiped any earlier write binds under this path — restore them.
   for (const writePath of allowedWritePaths) {
     if (writePath.startsWith(denySep) || writePath === normalizedPath) {
       args.push("--bind", writePath, writePath);
     }
   }
   ```

   `$HOME/.npm/_logs` and `$HOME/.claude/debug` are under our denied `$HOME`,
   and `/tmp/claude` is under our denied `/tmp`, so all three are restored on
   top of the deny. **The caller's `denyRead` is silently overridden by paths
   the caller never asked for.**

5. `filesystem.denyWrite` becomes `denyWithinAllow`
   (`sandbox-manager.js:1213-1215`), which on Linux emits
   `--ro-bind <p> <p>` for paths inside the write allow-list
   (`linux-sandbox-utils.js:1106`). That downgrades the mount to read-only. It
   does not unmount it, so it cannot close the read.

## Minimal reproduction

Linux, with a canary planted on the host first:

```sh
mkdir -p ~/.npm/_logs /tmp/claude
echo "HOST-ONLY-CANARY" > ~/.npm/_logs/CANARY.txt
echo "HOST-ONLY-CANARY" > /tmp/claude/CANARY.txt
```

```js
import { homedir } from "node:os";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { spawn } from "node:child_process";
import { SandboxManager } from "@anthropic-ai/sandbox-runtime";

const scratch = mkdtempSync(`${tmpdir()}/asrt-repro-`);

await SandboxManager.initialize({
  filesystem: {
    denyRead: [homedir(), "/tmp", "/private/tmp"],
    allowRead: [scratch],
    allowWrite: [scratch],
    // Even with the four defaults named here, the read below still succeeds.
    denyWrite: [
      `${homedir()}/.npm/_logs`,
      `${homedir()}/.claude/debug`,
      "/tmp/claude",
      "/private/tmp/claude",
    ],
  },
  network: {
    allowedDomains: [],
    deniedDomains: [],
    strictAllowlist: true,
    allowUnixSockets: [],
    allowAllUnixSockets: false,
    allowLocalBinding: false,
  },
});

const { argv, env } = await SandboxManager.wrapWithSandboxArgv(
  `/bin/sh -c 'ls -a "$HOME/.npm/_logs"; cat "$HOME/.npm/_logs/CANARY.txt"'`,
  undefined,
  undefined,
  undefined,
  scratch,
  { commandId: "asrt-repro" },
);

spawn(argv[0], argv.slice(1), { env, cwd: scratch, stdio: "inherit" });
```

## Observed vs expected

**Observed** (measured on ubuntu-24.04/arm64, bubblewrap 0.9.0, ASRT 0.0.74,
with the `denyWrite` fix already in place): the host-planted canary in
`~/.npm/_logs`, `~/.claude/debug` and `/tmp/claude` was read back **in full**
from inside the sandbox, and `readdir` of each returned the real host
contents — not the empty tmpfs the `denyRead` of `$HOME` and `/tmp` produces
everywhere else.

**Expected:** a path the caller denied reads on, and never granted writes to,
is not readable from inside the sandbox. At minimum, a caller should be able
to express that.

Before the `denyWrite` fix, the write half was live too, on both platforms:

| Platform    | Before `denyWrite`                                                                          | After `denyWrite`                                        |
| ----------- | ------------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| macOS/arm64 | writes to all four paths landed on the host; reads denied `EPERM` (write-only escape)       | `EPERM` on all four                                      |
| Linux/arm64 | writes landed on the host **and** real directory contents were readable (read-write escape) | `EROFS` on the three that exist; reads **still succeed** |

## Impact

The trust boundary is: model-generated code runs inside the sandbox and may
read only the files the caller passed in `allowRead` for that one request.
Everything else on the host is out of scope by construction — that is the
entire reason the sandbox is there.

These four paths are shared, host-wide, and written by unrelated processes;
ASRT's own comment says as much. On a host where more than one agent or tool
runs, one sandboxed run can read another's debug output and npm logs. Those
can carry file paths, arguments, error payloads and other operational detail
about work the run was never granted. It is a confidentiality leak across
tenants on one host, not a route to code execution or to write on the host
(the write half is closed, see below).

Scope, stated plainly: it needs an attacker-influenced payload already running
inside the sandbox, which for us is the normal case — the sandbox exists
precisely because the code inside it is untrusted.

## What we did, and why the read half is still open

**Write half — closed.** `filesystem.denyWrite` maps to `denyWithinAllow`,
applied _within_ `allowOnly`, which is the one supported way to subtract from
a set we never added to. We derive the deny list from ASRT's own
`getDefaultWritePaths()` rather than transcribing it
(`node-sandbox.ts:171-177`), taking the complement of the `/dev/*` character
devices, so a fifth default path added in a future release is denied by
default instead of quietly widening the writable set. Verified: `EPERM` on
macOS, `EROFS` on Linux, and no host file created.

**Read half — not closable at 0.0.74.** Every lever 0.0.74 exposes was tried:

- `filesystem.allowWrite` cannot shrink the set; the defaults are unioned in
  ahead of it (`sandbox-manager.js:1212`).
- `filesystem.denyWrite` → `denyWithinAllow` only re-binds read-only
  (`linux-sandbox-utils.js:1106`); the mount stays.
- `filesystem.denyRead` is applied _before_ the write binds are restored over
  it (`linux-sandbox-utils.js:636-646`), so it loses to them by construction.

We record the gap verbatim in the enforcement report we hand our own
consumers (`node-sandbox.ts:430`), so nobody downstream assumes it is closed.

## Ask

One of, in order of preference:

1. **A config surface for opting out of the default write paths** — e.g. a
   `filesystem.useDefaultWritePaths: false`, or honouring an explicit
   `allowWrite` as the complete set. A caller that has already denied reads of
   `$HOME` and `/tmp` has stated its intent unambiguously.
2. **Stop unioning them unconditionally** — make `getDefaultWritePaths()`
   opt-in for callers who want the compatibility behaviour, rather than
   opt-out-impossible for callers who do not.
3. Failing either, **make `denyWrite` unmount rather than re-bind read-only**
   when the denied path is one ASRT itself added and the caller never
   requested, so `denyWrite` can close both halves.

The narrower fix — never restoring a default write path over a caller's
`denyRead` tmpfs — would also close what we hit, but leaves the broader
"caller cannot decline the defaults" problem in place.

## Unverified

- **The reduced reproduction above has not been executed as written.** It is
  transcribed from our real call site (`node-sandbox.ts:501-636`), and the
  behaviour it is meant to elicit is what §19.7.1 measured through that call
  site on ubuntu-24.04/arm64. It has not been re-run in this stripped-down
  form, and not on x86_64 — §19.7.1's x86_64 evidence is a CI pass/fail count,
  not this probe.
- **Whether newer ASRT releases still behave this way is unknown.** Everything
  here is 0.0.74, the version we pin. No later version was inspected.
- **Windows is untested.** ASRT's Windows path is a restricted user with ACL
  stamps (`dist/sandbox/windows-sandbox-utils.js`), a different mechanism
  entirely; we run only macOS and Linux.
- **The macOS read behaviour is stated as measured, not as understood.** Reads
  of the same paths were denied `EPERM` there. We did not trace the Seatbelt
  profile far enough to say why the two platforms diverge.
- **Whose data actually sits in those directories on a given host is not
  something we measured.** The impact argument rests on ASRT's own warning
  that they "may allow access to files from other processes", plus what the
  directory names denote.
