import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { connect } from "node:net";
import { homedir, tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type {
  SandboxResult,
  SandboxSpec,
} from "@opendatalabs/personal-server-ts-core/query";
import { createNodeSandbox } from "./node-sandbox.js";

/**
 * The security contract (implementation plan, phase 4a acceptance).
 *
 * Every case here is a thing model-authored code might try. All must fail
 * closed. A new bypass is a P0.
 *
 * These assert on the **denial**, not merely on non-success: a script that
 * errored for an unrelated reason (a typo, a missing module) would otherwise
 * be a false pass. Each hostile script prints an explicit `BREACH-*` token on
 * success and a `DENIED-*` token on the expected failure, and the assertions
 * require the absence of the breach token *and* the presence of a denial —
 * so a case that silently did nothing fails the test rather than passing it.
 *
 * Nothing here reaches the network. The network cases assert egress is
 * denied; if one ever succeeds the test fails loudly rather than retrying.
 *
 * ## Outcome, not mechanism
 *
 * The two supported platforms deny differently, and four cases here used to
 * encode the macOS spelling of the denial rather than the guarantee behind
 * it. Seatbelt applies a kernel policy over the real filesystem and returns a
 * permission error; bubblewrap substitutes an empty private namespace — a
 * `--tmpfs` over a read-denied directory, a fresh procfs, an unshared netns —
 * so the same call *succeeds against nothing*. Both contain; only one raises
 * an errno. Measured on ubuntu-24.04, both architectures — design §19.7.1.
 *
 * So the confinement cases below assert the property — no host content is
 * observable, no byte lands on the host, no host process or host environment
 * is visible, nothing outside can reach in — by a route that either mechanism
 * satisfies and a real breach would not. Where the macOS mechanism is itself
 * worth pinning, it is kept as an extra `process.platform === "darwin"`
 * assertion beside the platform-neutral one, never in place of it.
 */

const RUN_MS = 20_000;

// The sandbox is only meaningful where ASRT supports the platform. On an
// unsupported one `run()` refuses with `sandboxUnavailable`, which is itself
// the fail-closed behaviour — asserted separately below.
const supported = process.platform === "darwin" || process.platform === "linux";

let dataRoot: string;
let grantedFile: string;
let secretFile: string;
let scratch: string;
let sandbox: ReturnType<typeof createNodeSandbox>;

/**
 * Every file this suite plants in the real host home carries this prefix, so
 * `afterAll` can sweep them whether the run passed, failed or breached.
 */
const HOST_HOME_PREFIX = ".ps-query-hostile-test-";
/**
 * The payload of the home-directory canary. Confining the home directory is
 * asserted by planting this outside and failing if it is ever observed
 * inside — a unique string cannot coincide the way an entry *count* can, and
 * unlike an errno it means the same thing under either denial mechanism.
 * Deliberately never interpolated into a hostile script, so its presence in a
 * run's output can only mean the run read it off the host.
 */
const HOME_CANARY_CONTENT = "PS-QUERY-HOME-CANARY-MUST-NEVER-BE-READABLE";
/** Names, not contents: what a `/proc` environment leak would spell. */
const PROC_ENV_CANARY = "PS_QUERY_PROC_CANARY";
/** What the host must fail to read back off a socket the sandbox opened. */
const INBOUND_PAYLOAD = "PS-QUERY-INSIDE-SANDBOX-LISTENER";

let homeCanaryName: string;
let homeCanaryFile: string;
/** Host paths the write case aims at; asserted absent, and swept after. */
let hostWriteTargets: string[];
/**
 * ASRT's own default write paths — the ones `getDefaultWritePaths()` unions
 * into the write allow-list whatever the caller asked for. See the test that
 * uses these.
 */
const ASRT_DEFAULT_WRITE_DIRS = [
  "/tmp/claude",
  "/private/tmp/claude",
  join(homedir(), ".npm", "_logs"),
  join(homedir(), ".claude", "debug"),
];
/** One file per entry above; asserted absent on the host, and swept after. */
let asrtWriteTargets: string[];
/**
 * Directories from {@link ASRT_DEFAULT_WRITE_DIRS} this suite had to create
 * because the machine did not have them. Removed again in `afterAll` so the
 * test leaves no trace, and tracked separately from ones that were already
 * there, which must survive.
 */
let asrtDirsCreated: string[];

beforeAll(() => {
  dataRoot = mkdtempSync(join(tmpdir(), "ps-query-data-"));
  grantedFile = join(dataRoot, "oura_sleep.json");
  writeFileSync(grantedFile, JSON.stringify([{ day: "2024-01-01", total: 1 }]));

  // A file the grant does NOT cover, standing in for another scope's data.
  const otherRoot = mkdtempSync(join(tmpdir(), "ps-query-secret-"));
  secretFile = join(otherRoot, "not-granted.json");
  writeFileSync(secretFile, "TOPSECRET-NOT-IN-GRANT");

  scratch = mkdtempSync(join(tmpdir(), "ps-query-scratch-"));

  // Planted in the *real* host home, which the sandbox denies wholesale. The
  // suite never asserts on how that denial is spelled, only that this content
  // and this name stay unobservable from inside.
  homeCanaryName = `${HOST_HOME_PREFIX}canary-${process.pid}`;
  homeCanaryFile = join(homedir(), homeCanaryName);
  writeFileSync(homeCanaryFile, HOME_CANARY_CONTENT);

  hostWriteTargets = [
    // Inside the granted scope's own root but outside the scratch dir: the
    // nearest thing to a plausible escape.
    join(dataRoot, "written-by-sandbox.txt"),
    // And the user's home, which is denied by a different rule.
    join(homedir(), `${HOST_HOME_PREFIX}written-by-sandbox-${process.pid}.txt`),
  ];

  // The ASRT default write paths, made real. A write refused because the
  // directory does not exist on this machine is not evidence of anything, so
  // each one is created if absent — otherwise the assertion below would pass
  // vacuously on a clean checkout and only ever fail on a developer's laptop.
  //
  // Created one level at a time, deepest recorded last, rather than with
  // `recursive: true`. `recursive` would create intermediate directories this
  // suite could not then name in order to remove them — `/private/tmp/claude`
  // does not exist on Linux, and a run with enough privilege would leave a
  // stray `/private` behind on the host forever. Nothing a containment test
  // does should litter the machine it is protecting.
  asrtDirsCreated = [];
  for (const d of ASRT_DEFAULT_WRITE_DIRS) {
    if (existsSync(d)) continue;
    const missing: string[] = [];
    for (let p = d; !existsSync(p) && p !== dirname(p); p = dirname(p)) {
      missing.unshift(p);
    }
    for (const p of missing) {
      try {
        mkdirSync(p);
        asrtDirsCreated.push(p);
      } catch {
        // Unwritable by the test user (a locked-down /tmp, or `/` as non-root,
        // which is how `/private/...` fails on Linux). The write case still
        // asserts the host file is absent; it just cannot also prove the
        // directory was there. Stop climbing — the deeper levels cannot be
        // created either.
        break;
      }
    }
  }
  asrtWriteTargets = ASRT_DEFAULT_WRITE_DIRS.map((d) =>
    join(d, `${HOST_HOME_PREFIX}asrt-default-${process.pid}.txt`),
  );

  sandbox = createNodeSandbox({ dataRoot });
});

afterAll(() => {
  for (const d of [dataRoot, scratch]) {
    if (d && existsSync(d)) rmSync(d, { recursive: true, force: true });
  }
  // Never leave anything of ours in the user's home, including a file a
  // breach put there.
  for (const f of [
    homeCanaryFile,
    ...(hostWriteTargets ?? []),
    ...(asrtWriteTargets ?? []),
  ]) {
    if (f && existsSync(f)) rmSync(f, { force: true });
  }
  // Only the ones this suite created, deepest first, and only while still
  // empty — so a directory the machine was already using is never removed and
  // an intermediate one we made is not left behind.
  for (const d of [...(asrtDirsCreated ?? [])].reverse()) {
    try {
      rmdirSync(d);
    } catch {
      // Non-empty or already gone. Either way, not ours to force.
    }
  }
});

function spec(over: Partial<SandboxSpec> = {}): SandboxSpec {
  return {
    readPaths: [grantedFile],
    writePath: scratch,
    denyNetwork: true,
    cpuMs: 3_000,
    memoryMb: 256,
    wallClockMs: 8_000,
    maxOutputBytes: 200_000,
    maxProcesses: 64,
    ...over,
  };
}

async function run(script: string, over?: Partial<SandboxSpec>) {
  return await sandbox.run(script, spec(over));
}

/** Combined output, for asserting on breach/denial tokens. */
function out(r: SandboxResult): string {
  return `${r.stdout}\n${r.stderr}`;
}

/**
 * Try, from the host, to reach a listener the sandbox may have opened, and
 * return what came back — or `null` if nothing did.
 *
 * This is the inbound half of the network contract. Bind *failure* is one way
 * to get it and is what Seatbelt does; bubblewrap gets the same guarantee by
 * putting the bind inside an unshared network namespace whose loopback is not
 * the host's, so the bind succeeds against an interface nothing outside can
 * route to. Reachability is the property both satisfy.
 *
 * A bare successful connect is not treated as a breach — something unrelated
 * could hold the port — only receiving the run's own payload is, which is why
 * the sandboxed listener answers with one.
 */
async function probeInboundFromHost(
  port: number,
  payload: string,
  budgetMs: number,
): Promise<string | null> {
  const deadline = Date.now() + budgetMs;
  while (Date.now() < deadline) {
    const got = await new Promise<string | null>((resolve) => {
      const socket = connect({ port, host: "127.0.0.1" });
      let buf = "";
      const finish = (v: string | null) => {
        socket.destroy();
        resolve(v);
      };
      socket.setTimeout(500, () => finish(null));
      socket.on("error", () => finish(null));
      socket.on("data", (d) => {
        buf += String(d);
        if (buf.includes(payload)) finish(buf);
      });
      socket.on("close", () => resolve(buf.includes(payload) ? buf : null));
    });
    if (got !== null) return got;
    await new Promise((r) => setTimeout(r, 150));
  }
  return null;
}

/**
 * The core assertion: the breach token must be absent, and the run must show
 * a positive sign of denial rather than merely having failed.
 */
function expectFailedClosed(r: SandboxResult, breachToken: string) {
  expect(
    out(r),
    `BREACH: ${breachToken} succeeded inside the sandbox`,
  ).not.toContain(breachToken);
  const denied =
    out(r).includes("DENIED-") ||
    r.termination === "policyDenied" ||
    r.violations.length > 0 ||
    r.exitCode !== 0;
  expect(denied, "no positive evidence of denial — possible false pass").toBe(
    true,
  );
}

describe.skipIf(!supported)("hostile scripts fail closed", () => {
  it(
    "allows the granted read (control — proves the harness runs code at all)",
    async () => {
      const r = await run(`
      const fs = require("fs");
      const d = fs.readFileSync(${JSON.stringify(grantedFile)}, "utf8");
      console.log("CONTROL-READ-OK " + d.length);
    `);
      // If this fails, every "denied" result below is meaningless.
      expect(out(r)).toContain("CONTROL-READ-OK");
      expect(r.termination).toBe("completed");
    },
    RUN_MS,
  );

  it(
    "denies reading a file outside readPaths",
    async () => {
      const r = await run(`
      const fs = require("fs");
      try {
        const d = fs.readFileSync(${JSON.stringify(secretFile)}, "utf8");
        console.log("BREACH-READ-OUTSIDE " + d);
      } catch (e) { console.log("DENIED-READ-OUTSIDE " + e.code); }
    `);
      expectFailedClosed(r, "BREACH-READ-OUTSIDE");
      expect(out(r)).not.toContain("TOPSECRET-NOT-IN-GRANT");
    },
    RUN_MS,
  );

  it(
    "denies reading /etc/passwd",
    async () => {
      const r = await run(`
      const fs = require("fs");
      try {
        const d = fs.readFileSync("/etc/passwd", "utf8");
        console.log("BREACH-READ-ETC bytes=" + d.length);
      } catch (e) { console.log("DENIED-READ-ETC " + e.code); }
    `);
      expectFailedClosed(r, "BREACH-READ-ETC");
    },
    RUN_MS,
  );

  it(
    "cannot observe any content of the user's home directory",
    async () => {
      // The property is that no host-home content reaches the run. It is
      // deliberately not "readdir raises an errno": that is only the macOS
      // spelling. On Linux the home directory is replaced by an empty private
      // tmpfs, so `readdir` succeeds and returns sandbox scaffolding — a
      // success against nothing, not a read of the host.
      //
      // Counting entries cannot separate those two, and a count can coincide
      // outright. A canary planted outside and read from inside can: if the
      // run sees it the home directory is genuinely exposed, and if it does
      // not then no host content is reachable however the denial was spelled.
      // The script prints whatever it managed to read, so a leak arrives in
      // the output as evidence rather than as a token the script had to stay
      // well-behaved enough to emit.
      const r = await run(`
      const fs = require("fs");
      try {
        const d = fs.readFileSync(${JSON.stringify(homeCanaryFile)}, "utf8");
        console.log("BREACH-READ-HOME-CANARY " + d);
      } catch (e) { console.log("DENIED-READ-HOME-CANARY " + e.code); }
      try {
        const names = fs.readdirSync(${JSON.stringify(homedir())});
        console.log("HOME-LISTING " + JSON.stringify(names));
      } catch (e) { console.log("DENIED-READ-HOME " + e.code); }
    `);
      // The guarantee: neither the canary's contents nor even its name is
      // observable, by the direct read or through the directory listing.
      expect(
        out(r),
        "host home content was readable inside the sandbox",
      ).not.toContain(HOME_CANARY_CONTENT);
      expect(
        out(r),
        "the host home's real directory listing reached the sandbox",
      ).not.toContain(homeCanaryName);
      expect(out(r)).not.toContain("BREACH-READ-HOME-CANARY");
      // Positive evidence the script ran far enough to attempt the read, so
      // a run that died early cannot pass the negatives vacuously.
      expect(out(r), "the script never reached the canary read").toContain(
        "DENIED-READ-HOME-CANARY",
      );
      // The macOS mechanism, kept rather than dropped: Seatbelt denies by
      // kernel permission check, so both operations raise an errno there. On
      // Linux they succeed against an empty tmpfs instead, which the
      // assertions above already prove holds no host content.
      if (process.platform === "darwin") {
        expect(out(r), "Seatbelt should refuse the home read").toMatch(
          /DENIED-READ-HOME-CANARY (EPERM|EACCES|ENOENT)/,
        );
        expect(out(r), "Seatbelt should refuse the home listing").toMatch(
          /DENIED-READ-HOME (EPERM|EACCES|ENOENT)/,
        );
      }
    },
    RUN_MS,
  );

  it(
    "denies opening a TCP socket",
    async () => {
      const r = await run(`
      const net = require("net");
      const s = net.connect(80, "93.184.216.34");
      s.on("connect", () => { console.log("BREACH-TCP-CONNECT"); process.exit(0); });
      s.on("error", (e) => { console.log("DENIED-TCP " + e.code); process.exit(0); });
      setTimeout(() => { console.log("DENIED-TCP timeout"); process.exit(0); }, 4000);
    `);
      expectFailedClosed(r, "BREACH-TCP-CONNECT");
    },
    RUN_MS,
  );

  it(
    "denies DNS resolution",
    async () => {
      const r = await run(`
      const dns = require("dns");
      dns.resolve4("example.com", (e, a) => {
        if (e) { console.log("DENIED-DNS " + e.code); }
        else { console.log("BREACH-DNS " + JSON.stringify(a)); }
        process.exit(0);
      });
      setTimeout(() => { console.log("DENIED-DNS timeout"); process.exit(0); }, 4000);
    `);
      expectFailedClosed(r, "BREACH-DNS");
    },
    RUN_MS,
  );

  it(
    "denies an outbound HTTPS request",
    async () => {
      const r = await run(`
      fetch("https://example.com")
        .then(() => { console.log("BREACH-HTTPS"); process.exit(0); })
        .catch((e) => { console.log("DENIED-HTTPS " + e.message.slice(0,60)); process.exit(0); });
      setTimeout(() => { console.log("DENIED-HTTPS timeout"); process.exit(0); }, 5000);
    `);
      expectFailedClosed(r, "BREACH-HTTPS");
    },
    RUN_MS,
  );

  it(
    "denies a raw UDP / DNS-over-UDP send",
    async () => {
      const r = await run(`
      const dgram = require("dgram");
      try {
        const s = dgram.createSocket("udp4");
        s.send(Buffer.from("x"), 53, "8.8.8.8", (e) => {
          if (e) { console.log("DENIED-UDP " + e.code); } else { console.log("BREACH-UDP-SENT"); }
          process.exit(0);
        });
      } catch (e) { console.log("DENIED-UDP " + e.code); process.exit(0); }
      setTimeout(() => { console.log("DENIED-UDP timeout"); process.exit(0); }, 4000);
    `);
      expectFailedClosed(r, "BREACH-UDP-SENT");
    },
    RUN_MS,
  );

  it(
    "denies IPv6 egress",
    async () => {
      const r = await run(`
      const net = require("net");
      const s = net.connect(80, "2606:2800:220:1:248:1893:25c8:1946");
      s.on("connect", () => { console.log("BREACH-IPV6"); process.exit(0); });
      s.on("error", (e) => { console.log("DENIED-IPV6 " + e.code); process.exit(0); });
      setTimeout(() => { console.log("DENIED-IPV6 timeout"); process.exit(0); }, 4000);
    `);
      expectFailedClosed(r, "BREACH-IPV6");
    },
    RUN_MS,
  );

  it(
    "nothing outside can reach a socket the sandbox opens",
    async () => {
      // The egress suite above covers outbound. This case is the other
      // direction: whether model-authored code can open a door into the run.
      //
      // Asserting that `listen()` fails tests the mechanism, and only one
      // platform's. Seatbelt refuses the bind; bubblewrap allows it inside an
      // unshared network namespace that nothing outside can route to — and
      // ASRT's `network.allowLocalBinding: false`, which we do pass, is
      // referenced only in its macOS code and is inert on Linux. Both still
      // deliver the guarantee, so assert the guarantee: while the run holds a
      // listener open on every interface, the host tries to connect and must
      // not get the run's payload back.
      const port = 18731;
      const running = run(`
      const net = require("net");
      const srv = net.createServer((c) => { c.end(${JSON.stringify(
        INBOUND_PAYLOAD,
      )}); });
      srv.on("error", (e) => { console.log("BIND-THREW " + e.code); process.exit(0); });
      srv.listen(${port}, "0.0.0.0", () => { console.log("BIND-RETURNED"); });
      setTimeout(() => { console.log("BIND-WINDOW-CLOSED"); process.exit(0); }, 6000);
    `);
      // Probe while that window is open, then collect the run.
      const reached = await probeInboundFromHost(port, INBOUND_PAYLOAD, 5_000);
      const r = await running;

      // The guarantee.
      expect(
        reached,
        "the host reached a listening socket opened inside the sandbox",
      ).toBeNull();
      // Positive evidence the bind was actually attempted, so a run that
      // never executed cannot pass by simply having opened nothing.
      expect(out(r), "the script never attempted the bind").toMatch(
        /BIND-RETURNED|BIND-THREW /,
      );
      // The macOS mechanism, kept: Seatbelt refuses the bind outright, and
      // `allowLocalBinding: false` is the setting that does it.
      if (process.platform === "darwin") {
        expect(out(r), "Seatbelt should refuse the bind").toContain(
          "BIND-THREW",
        );
        expect(out(r)).not.toContain("BIND-RETURNED");
      }
    },
    RUN_MS,
  );

  it(
    "denies connecting to a UNIX domain socket",
    async () => {
      const r = await run(`
      const net = require("net");
      const s = net.connect("/var/run/docker.sock");
      s.on("connect", () => { console.log("BREACH-UNIX-SOCKET"); process.exit(0); });
      s.on("error", (e) => { console.log("DENIED-UNIX " + e.code); process.exit(0); });
      setTimeout(() => { console.log("DENIED-UNIX timeout"); process.exit(0); }, 3000);
    `);
      expectFailedClosed(r, "BREACH-UNIX-SOCKET");
    },
    RUN_MS,
  );

  it(
    "no write outside the scratch dir ever lands on the host",
    async () => {
      // Whether the call threw is the mechanism; whether the byte landed is
      // the guarantee. Seatbelt refuses the write with an errno. Bubblewrap
      // has replaced the target's directory with a private tmpfs, so the
      // write returns success and even reads back *inside* the run — and is
      // discarded with the namespace. Nothing reaches the host either way, so
      // the assertion is on the host filesystem afterwards.
      //
      // Two targets, because they are denied by different rules: the granted
      // scope's own root (the nearest plausible escape) and the user's home.
      const r = await run(`
      const fs = require("fs");
      for (const t of ${JSON.stringify(hostWriteTargets)}) {
        try {
          fs.writeFileSync(t, "x");
          console.log("WRITE-CALL-RETURNED");
        } catch (e) { console.log("WRITE-CALL-THREW " + e.code); }
      }
    `);
      // The guarantee. Swept before asserting so that a breach cannot leave
      // a file behind in the user's home on the way to failing the test.
      const landed = hostWriteTargets.filter((t) => existsSync(t));
      for (const t of landed) rmSync(t, { force: true });
      expect(landed, "a sandboxed write created a file on the host").toEqual(
        [],
      );
      // Positive evidence both writes were actually attempted, so a run that
      // never executed cannot pass on an empty filesystem.
      const attempts = out(r).match(/WRITE-CALL-(RETURNED|THREW)/g) ?? [];
      expect(attempts, "the script did not attempt both writes").toHaveLength(
        hostWriteTargets.length,
      );
      // The macOS mechanism, kept: Seatbelt refuses the syscall outright, so
      // no write may report success there.
      if (process.platform === "darwin") {
        expect(out(r), "Seatbelt should refuse the write").toContain(
          "WRITE-CALL-THREW",
        );
        expect(out(r)).not.toContain("WRITE-CALL-RETURNED");
      }
    },
    RUN_MS,
  );

  it(
    "no write to ASRT's own default write paths lands on the host",
    async () => {
      // The assertion that was missing, and the one that would have caught a
      // real escape being shipped.
      //
      // The case above aims at paths *our* config denies, which is the easy
      // half. These four are different in kind: ASRT grants them itself.
      // `SandboxManager` composes the write policy as
      // `allowOnly: [...getDefaultWritePaths(), ...userAllowWrite]`, so they
      // are writable regardless of what `allowWrite` says, and ASRT's own
      // source warns they "may allow access to files from other processes".
      // Measured before `node-sandbox.ts` named them in `denyWrite`: a
      // sandboxed script's writes to all four landed on the real host
      // filesystem holding the script's bytes, on macOS (write-only; reads
      // refused EPERM) and on Linux (read and write).
      //
      // Nothing about that is visible from inside a run, from the granted
      // scope, or from any assertion the rest of this file makes — which is
      // exactly why it survived. The property is the same one the case above
      // asserts, applied to the paths a dependency opened rather than the
      // ones we did: no byte reaches the host outside the scratch dir.
      //
      // Scope, stated rather than left to silence: this asserts the **write**
      // half only. The read half is not closable at ASRT 0.0.74 — `denyWrite`
      // maps to `denyWithinAllow`, which leaves the path bind-mounted and
      // therefore readable on Linux. That gap is carried in
      // `SandboxEnforcement.notes` and design §19.7.1, not asserted here,
      // because a test that must pass cannot assert something still open.
      const r = await run(`
      const fs = require("fs");
      for (const t of ${JSON.stringify(asrtWriteTargets)}) {
        try {
          fs.writeFileSync(t, "BREACH-PAYLOAD");
          console.log("ASRT-WRITE-RETURNED " + t);
        } catch (e) { console.log("ASRT-WRITE-THREW " + t + " " + e.code); }
      }
    `);
      // The guarantee. Swept before asserting so a breach cannot leave a file
      // in the user's home on its way to failing the test.
      const landed = asrtWriteTargets.filter((t) => existsSync(t));
      for (const t of landed) rmSync(t, { force: true });
      expect(
        landed,
        "a sandboxed write reached the host through ASRT's default write paths",
      ).toEqual([]);
      // Positive evidence every write was actually attempted, so a run that
      // died early cannot pass on an empty filesystem.
      const attempts = out(r).match(/ASRT-WRITE-(RETURNED|THREW)/g) ?? [];
      expect(
        attempts,
        "the script did not attempt every default-write-path write",
      ).toHaveLength(asrtWriteTargets.length);
      // The macOS mechanism, kept beside the platform-neutral guarantee:
      // `denyWithinAllow` becomes a Seatbelt deny rule, so the syscall is
      // refused outright and no write may report success.
      if (process.platform === "darwin") {
        expect(out(r), "Seatbelt should refuse the write").toContain(
          "ASRT-WRITE-THREW",
        );
        expect(out(r)).not.toContain("ASRT-WRITE-RETURNED");
      }
    },
    RUN_MS,
  );

  it(
    "the run's temp dir is its own scratch dir, not a shared host directory",
    async () => {
      // The other half of the same escape, and the one a script reaches
      // without naming a path at all.
      //
      // ASRT sets `TMPDIR=/tmp/claude` for the sandboxed process — one of the
      // default write paths above — via an `env VAR=value` prefix on the argv
      // it returns, which is applied at exec time and so wins over any
      // environment the caller composes. The effect was that `os.tmpdir()`
      // inside a run pointed at a shared host directory, aiming every library
      // that writes a temp file out of the sandbox by default.
      //
      // So the property is not just "the write is refused" but "the temp dir
      // is somewhere legitimate" — and both halves matter: a temp dir that
      // was merely denied would be contained but broken, which is what ASRT
      // 0.0.74 leaves behind on its own (measured on macOS: `os.tmpdir()` was
      // `/tmp/claude` and `mkdtempSync` under it failed with EPERM).
      const r = await run(`
      const fs = require("fs");
      const os = require("os");
      const path = require("path");
      console.log("TMPDIR-IS " + os.tmpdir());
      try {
        const d = fs.mkdtempSync(path.join(os.tmpdir(), "probe-"));
        console.log("TMPDIR-WRITABLE " + d);
      } catch (e) { console.log("TMPDIR-UNWRITABLE " + e.code); }
    `);
      const reported = out(r)
        .match(/^TMPDIR-IS (.*)$/m)?.[1]
        ?.trim();
      // Positive evidence the run got far enough to report anything.
      expect(reported, "the script never reported its temp dir").toBeTruthy();
      for (const d of ASRT_DEFAULT_WRITE_DIRS) {
        expect(
          reported,
          `the run's temp dir is ASRT's shared ${d}, not its own scratch dir`,
        ).not.toContain(d);
      }
      // Positively: it is inside the scratch dir this run was given. Compared
      // against the realpath because macOS reaches the scratch dir through
      // /private, and the run sees the resolved spelling.
      expect(
        realpathSync(reported!).startsWith(realpathSync(scratch)),
        `temp dir ${reported} is outside the run's scratch dir ${scratch}`,
      ).toBe(true);
      // And it actually works, so this cannot be satisfied by pointing TMPDIR
      // at somewhere unusable.
      expect(out(r), "the run's own temp dir was not writable").toContain(
        "TMPDIR-WRITABLE",
      );
    },
    RUN_MS,
  );

  it(
    "denies a symlink escape out of the scratch dir",
    async () => {
      const link = join(scratch, "escape-link");
      if (existsSync(link)) rmSync(link, { force: true });
      symlinkSync(secretFile, link);
      const r = await run(`
      const fs = require("fs");
      try {
        const d = fs.readFileSync(${JSON.stringify(link)}, "utf8");
        console.log("BREACH-SYMLINK " + d);
      } catch (e) { console.log("DENIED-SYMLINK " + e.code); }
    `);
      expectFailedClosed(r, "BREACH-SYMLINK");
      expect(out(r)).not.toContain("TOPSECRET-NOT-IN-GRANT");
    },
    RUN_MS,
  );

  it(
    "terminates a fork bomb without taking the host down",
    async () => {
      // `child_process.spawn` is asynchronous, so counting *calls* would count
      // requests that never became processes. RLIMIT_NPROC surfaces as an
      // async EAGAIN 'error' event, so the property to assert is how many
      // children actually started, not how many spawns were issued.
      const r = await run(
        `
      const cp = require("child_process");
      let live = 0, denied = 0;
      for (let i = 0; i < 400; i++) {
        const c = cp.spawn(process.execPath, ["-e", "setTimeout(()=>{},5000)"]);
        c.on("spawn", () => { live++; });
        c.on("error", (e) => { if (e.code === "EAGAIN") denied++; });
      }
      setTimeout(() => {
        console.log("FORK-RESULT live=" + live + " denied=" + denied);
        if (denied === 0 && live >= 400) console.log("BREACH-FORKBOMB live=" + live);
        else console.log("DENIED-FORK live=" + live + " denied=" + denied);
        process.exit(0);
      }, 2500);
    `,
        { maxProcesses: 24, wallClockMs: 8_000, cpuMs: 6_000 },
      );
      expect(out(r)).not.toContain("BREACH-FORKBOMB");
      // Positive evidence that the process limit actually engaged.
      expect(out(r)).toMatch(/DENIED-FORK|FORK-RESULT/);
      // And the host is still here to assert it.
      expect(["error", "wallClock", "cpu", "memory", "completed"]).toContain(
        r.termination,
      );
    },
    RUN_MS,
  );

  it("stops a 4GB allocation at the memory budget", async () => {
    const r = await run(
      `
      const chunks = [];
      for (let i = 0; i < 64; i++) {
        chunks.push(Buffer.alloc(64 * 1024 * 1024, 1));
      }
      console.log("BREACH-ALLOC-4GB");
    `,
      { memoryMb: 256, wallClockMs: 15_000, cpuMs: 12_000 },
    );
    expect(out(r)).not.toContain("BREACH-ALLOC-4GB");
    expect(r.termination).toBe("memory");
    // The watchdog is the only thing bounding memory on macOS, and a broken
    // one reports itself here rather than silently not enforcing. Asserting
    // only on `termination` let a dead watchdog pass once already.
    expect(r.enforcement.memory).toBe(true);
    expect(r.enforcement.notes.join(" ")).not.toContain("watchdog failed");
  }, 30_000);

  it(
    "reports every limit it claims to enforce, honestly",
    async () => {
      // A trivial run: the point is the enforcement report, not the script.
      const r = await run(`console.log("ok")`);
      expect(r.termination).toBe("completed");
      for (const k of [
        "filesystemRead",
        "filesystemWrite",
        "network",
        "cpu",
        "memory",
        "processCount",
        "wallClock",
      ] as const) {
        expect(r.enforcement[k], `enforcement.${k} must be reported`).toBe(
          true,
        );
      }
    },
    RUN_MS,
  );

  it("stops an infinite loop on the CPU budget", async () => {
    const r = await run(
      `
      const t = Date.now();
      for (;;) { if (Date.now() - t > 60000) { console.log("BREACH-SPIN-FOREVER"); break; } }
    `,
      { cpuMs: 2_000, wallClockMs: 20_000 },
    );
    expect(out(r)).not.toContain("BREACH-SPIN-FOREVER");
    expect(["cpu", "wallClock"]).toContain(r.termination);
  }, 30_000);

  it(
    "stops a sleeping script on the wall-clock budget",
    async () => {
      const r = await run(
        `
      setTimeout(() => { console.log("BREACH-WALLCLOCK"); }, 30000);
    `,
        { wallClockMs: 2_000, cpuMs: 20_000 },
      );
      expect(out(r)).not.toContain("BREACH-WALLCLOCK");
      expect(r.termination).toBe("wallClock");
    },
    RUN_MS,
  );

  it("truncates and kills on the output cap", async () => {
    const r = await run(
      `
      const line = "A".repeat(1000);
      for (let i = 0; i < 100000; i++) console.log(line);
      console.log("BREACH-OUTPUT-UNBOUNDED");
    `,
      { maxOutputBytes: 50_000, wallClockMs: 15_000 },
    );
    expect(r.truncated).toBe(true);
    expect(r.termination).toBe("outputCap");
    expect(out(r).length).toBeLessThan(5_000_000);
  }, 30_000);

  it(
    "does not leak host environment variables",
    async () => {
      process.env.PS_QUERY_CANARY = "CANARY-SHOULD-NOT-APPEAR";
      const r = await run(`
      const v = Object.entries(process.env).map(([k,x]) => k + "=" + x).join("\\n");
      if (v.includes("CANARY-SHOULD-NOT-APPEAR")) console.log("BREACH-ENV-LEAK");
      else console.log("DENIED-ENV no canary");
    `);
      delete process.env.PS_QUERY_CANARY;
      expectFailedClosed(r, "BREACH-ENV-LEAK");
    },
    RUN_MS,
  );

  it(
    "cannot see the host's process table or the host's environment",
    async () => {
      // This case stays platform-forked, and irreducibly so: macOS has no
      // procfs at all, so there is no host process table for it to be absent
      // from. The two arms therefore probe the same property — the host's
      // running state is not observable — through the mechanism each platform
      // actually has.
      //
      // On Linux `bwrap` mounts a fresh procfs the sandbox cannot work
      // without, so "is /proc readable" is the wrong question; it is readable
      // by design. The right question is what a leak would *look* like, and
      // it has two shapes: the host's processes appearing in the table, and
      // un-scrubbed host environment readable through `/proc/<pid>/environ`.
      // Assert those two absences specifically. A small PID count is a
      // symptom of the private namespace, not the property, and a count can
      // coincide — so it is printed as evidence and not asserted on.
      if (process.platform === "linux") {
        process.env[PROC_ENV_CANARY] = "PROC-CANARY-SHOULD-NOT-APPEAR";
        let r;
        try {
          // The script reports the environment variable *names* it can see
          // anywhere in the process table. Names, not values, so the canary
          // never has to be interpolated into the script: its appearance in
          // the output can only mean the run read it out of a host process.
          r = await run(`
      const fs = require("fs");
      try {
        const pids = fs.readdirSync("/proc").filter((n) => /^[0-9]+$/.test(n));
        console.log("PROC-PIDS " + pids.join(","));
        const names = new Set();
        for (const pid of pids.concat(["self"])) {
          try {
            const raw = fs.readFileSync("/proc/" + pid + "/environ", "utf8");
            for (const kv of raw.split("\u0000")) {
              if (kv) names.add(kv.split("=")[0]);
            }
          } catch (e) { /* a pid that exited, or one we may not read */ }
        }
        console.log("PROC-ENV-NAMES " + [...names].sort().join(" "));
        console.log("PROC-SWEEP-DONE");
      } catch (e) { console.log("DENIED-PROC " + e.code); }
    `);
        } finally {
          delete process.env[PROC_ENV_CANARY];
        }
        // Positive evidence: either the sweep completed, or /proc was denied
        // outright. A run that died early satisfies neither.
        expect(
          out(r),
          "the script neither swept /proc nor was denied it",
        ).toMatch(/PROC-SWEEP-DONE|DENIED-PROC /);
        if (out(r).includes("PROC-SWEEP-DONE")) {
          // Shape one: the host's own process must not be in the table. This
          // test process is running on the host by definition, so its PID is
          // the one host PID guaranteed to exist while the assertion runs.
          const pidLine = /PROC-PIDS (.*)/.exec(out(r));
          expect(pidLine, "the sweep printed no PID list").not.toBeNull();
          const pids = (pidLine?.[1] ?? "").split(",").filter(Boolean);
          expect(pids, "the sweep saw no PIDs at all").not.toHaveLength(0);
          expect(
            pids,
            "the host's own PID is visible in the sandbox's process table",
          ).not.toContain(String(process.pid));
          // Shape two: no host environment anywhere in that table. The canary
          // is set on the host for the duration of the run, so seeing its
          // name means a host process's environ was readable — which is what
          // the un-namespaced /proc leak would actually look like.
          const nameLine = /PROC-ENV-NAMES (.*)/.exec(out(r));
          expect(nameLine, "the sweep printed no env names").not.toBeNull();
          expect(
            out(r),
            "a host process's environment was readable through /proc",
          ).not.toContain(PROC_ENV_CANARY);
        }
      } else {
        // macOS: no procfs, so probe host memory directly instead. Seatbelt
        // denies by permission check, so the original breach/denial shape is
        // exactly right here and is kept unchanged.
        const r = await run(`
      const fs = require("fs");
      try {
        const d = fs.readFileSync("/dev/kmem");
        console.log("BREACH-PROCDEV bytes=" + d.length);
      } catch (e) { console.log("DENIED-PROCDEV " + e.code); }
    `);
        expectFailedClosed(r, "BREACH-PROCDEV");
        expect(out(r), "Seatbelt should refuse the /dev read").toContain(
          "DENIED-PROCDEV",
        );
      }
    },
    RUN_MS,
  );

  it(
    "denies loading a native addon via process.dlopen",
    async () => {
      const r = await run(`
      try {
        const m = { exports: {} };
        process.dlopen(m, "/usr/lib/libSystem.dylib");
        console.log("BREACH-DLOPEN");
      } catch (e) { console.log("DENIED-DLOPEN " + (e.code || e.message.slice(0,40))); }
    `);
      expectFailedClosed(r, "BREACH-DLOPEN");
    },
    RUN_MS,
  );

  it(
    "cannot reach the granted file's directory beyond the granted file",
    async () => {
      // readPaths names one file; the directory around it is not granted.
      const sibling = join(dataRoot, "sibling-not-granted.json");
      writeFileSync(sibling, "SIBLING-SECRET");
      const r = await run(`
      const fs = require("fs");
      try {
        const d = fs.readFileSync(${JSON.stringify(sibling)}, "utf8");
        console.log("BREACH-SIBLING " + d);
      } catch (e) { console.log("DENIED-SIBLING " + e.code); }
    `);
      expectFailedClosed(r, "BREACH-SIBLING");
      expect(out(r)).not.toContain("SIBLING-SECRET");
    },
    RUN_MS,
  );

  it("a child process cannot outlive the run", async () => {
    const marker = join(scratch, "orphan-marker.txt");
    if (existsSync(marker)) rmSync(marker, { force: true });
    await run(
      `
      const cp = require("child_process");
      cp.spawn(process.execPath, ["-e",
        "setTimeout(()=>{require('fs').writeFileSync(" + JSON.stringify(JSON.stringify(marker)) + ",'orphan')},3000)"
      ], { detached: true, stdio: "ignore" }).unref();
      setTimeout(()=>{}, 30000);
    `,
      { wallClockMs: 1_500 },
    );
    // Wait past when the orphan would have written.
    await new Promise((r) => setTimeout(r, 5_000));
    expect(
      existsSync(marker),
      "a detached child outlived the sandboxed run",
    ).toBe(false);
  }, 30_000);
});

describe.skipIf(!supported)(
  "concurrent runs do not share a read policy",
  () => {
    it("a run cannot read another concurrent run's granted file", async () => {
      // ASRT's SandboxManager is a process-global singleton, so two overlapping
      // runs could otherwise execute under whichever policy initialized last.
      const rootA = mkdtempSync(join(tmpdir(), "grant-a-"));
      const rootB = mkdtempSync(join(tmpdir(), "grant-b-"));
      const fileA = join(rootA, "a.json");
      const fileB = join(rootB, "b.json");
      writeFileSync(fileA, "AAA-GRANT-A-ONLY");
      writeFileSync(fileB, "BBB-GRANT-B-ONLY");

      const sbA = createNodeSandbox({ dataRoot: rootA });
      const sbB = createNodeSandbox({ dataRoot: rootB });
      const scratchA = mkdtempSync(join(tmpdir(), "sc-a-"));
      const scratchB = mkdtempSync(join(tmpdir(), "sc-b-"));

      const mk = (read: string, write: string): SandboxSpec => ({
        readPaths: [read],
        writePath: write,
        denyNetwork: true,
        cpuMs: 5_000,
        memoryMb: 256,
        wallClockMs: 10_000,
        maxOutputBytes: 100_000,
        maxProcesses: 32,
      });

      // Each run reads its own file *and* tries the other's, while both are in
      // flight. Asserting only the negative would pass when a run silently did
      // not execute at all — which is exactly what happened before the run
      // queue was made process-wide: one side produced no output whatsoever
      // and the "it didn't read the other grant" assertion passed vacuously.
      const scriptFor = (own: string, other: string) => `
      const fs = require("fs");
      try { console.log("OWN:" + fs.readFileSync(${JSON.stringify(own)}, "utf8")); }
      catch (e) { console.log("OWN-DENIED " + e.code); }
      try { console.log("OTHER:" + fs.readFileSync(${JSON.stringify(other)}, "utf8")); }
      catch (e) { console.log("OTHER-DENIED " + e.code); }
    `;

      try {
        const [ra, rb] = await Promise.all([
          sbA.run(scriptFor(fileA, fileB), mk(fileA, scratchA)),
          sbB.run(scriptFor(fileB, fileA), mk(fileB, scratchB)),
        ]);
        // Positive control: each run actually ran and saw its own grant.
        expect(out(ra), "run A did not execute").toContain("AAA-GRANT-A-ONLY");
        expect(out(rb), "run B did not execute").toContain("BBB-GRANT-B-ONLY");
        // Isolation: neither saw the other's.
        expect(out(ra)).not.toContain("BBB-GRANT-B-ONLY");
        expect(out(rb)).not.toContain("AAA-GRANT-A-ONLY");
      } finally {
        for (const d of [rootA, rootB, scratchA, scratchB]) {
          rmSync(d, { recursive: true, force: true });
        }
      }
    }, 40_000);
  },
);

describe("fails closed when no OS sandbox is available", () => {
  it.skipIf(supported)(
    "refuses to run rather than running unconfined",
    async () => {
      const sb = createNodeSandbox({ dataRoot: tmpdir() });
      const r = await sb.run("console.log('should not run')", spec());
      expect(r.termination).toBe("sandboxUnavailable");
      expect(r.stdout).not.toContain("should not run");
    },
  );

  it("reports capabilities honestly", async () => {
    const sb = createNodeSandbox({ dataRoot: tmpdir() });
    const caps = await sb.capabilities();
    if (caps.available) {
      // Never claim an enforcement we did not implement.
      expect(caps.enforcement.network).toBe(true);
      expect(Array.isArray(caps.enforcement.notes)).toBe(true);
    } else {
      expect(caps.reason.length).toBeGreaterThan(0);
    }
  });
});
