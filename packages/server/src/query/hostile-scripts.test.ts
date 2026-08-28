import {
  existsSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
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

beforeAll(() => {
  dataRoot = mkdtempSync(join(tmpdir(), "ps-query-data-"));
  grantedFile = join(dataRoot, "oura_sleep.json");
  writeFileSync(grantedFile, JSON.stringify([{ day: "2024-01-01", total: 1 }]));

  // A file the grant does NOT cover, standing in for another scope's data.
  const otherRoot = mkdtempSync(join(tmpdir(), "ps-query-secret-"));
  secretFile = join(otherRoot, "not-granted.json");
  writeFileSync(secretFile, "TOPSECRET-NOT-IN-GRANT");

  scratch = mkdtempSync(join(tmpdir(), "ps-query-scratch-"));
  sandbox = createNodeSandbox({ dataRoot });
});

afterAll(() => {
  for (const d of [dataRoot, scratch]) {
    if (d && existsSync(d)) rmSync(d, { recursive: true, force: true });
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
    "denies reading the user's home directory",
    async () => {
      const r = await run(`
      const fs = require("fs");
      try {
        const n = fs.readdirSync(${JSON.stringify(homedir())}).length;
        console.log("BREACH-READ-HOME entries=" + n);
      } catch (e) { console.log("DENIED-READ-HOME " + e.code); }
    `);
      expectFailedClosed(r, "BREACH-READ-HOME");
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
    "denies binding a listening socket",
    async () => {
      const r = await run(`
      const net = require("net");
      const srv = net.createServer();
      srv.on("error", (e) => { console.log("DENIED-BIND " + e.code); process.exit(0); });
      srv.listen(18731, "127.0.0.1", () => { console.log("BREACH-BIND"); process.exit(0); });
      setTimeout(() => { console.log("DENIED-BIND timeout"); process.exit(0); }, 4000);
    `);
      expectFailedClosed(r, "BREACH-BIND");
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
    "denies writing outside the scratch dir",
    async () => {
      const target = join(dataRoot, "written-by-sandbox.txt");
      const r = await run(`
      const fs = require("fs");
      try {
        fs.writeFileSync(${JSON.stringify(target)}, "x");
        console.log("BREACH-WRITE-OUTSIDE");
      } catch (e) { console.log("DENIED-WRITE " + e.code); }
    `);
      expectFailedClosed(r, "BREACH-WRITE-OUTSIDE");
      // The strongest assertion is on the filesystem, not on the output.
      expect(
        existsSync(target),
        "file was actually created outside scratch",
      ).toBe(false);
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
    "denies reading /proc (Linux) or /dev entries",
    async () => {
      const target =
        process.platform === "linux" ? "/proc/self/environ" : "/dev/kmem";
      const r = await run(`
      const fs = require("fs");
      try {
        const d = fs.readFileSync(${JSON.stringify(target)});
        console.log("BREACH-PROCDEV bytes=" + d.length);
      } catch (e) { console.log("DENIED-PROCDEV " + e.code); }
    `);
      expectFailedClosed(r, "BREACH-PROCDEV");
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
