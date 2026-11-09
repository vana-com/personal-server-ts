/**
 * The command line: arguments, exit codes, and a real loopback HTTP gateway
 * and storage (the host guard allows 127.0.0.1 only because the test passes it
 * as the Dev gateway and storage URL).
 */

import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { readFile, rm } from "node:fs/promises";
import { afterEach, describe, expect, it, vi } from "vitest";
import { main } from "./legacy-retire-dry-run.js";
import { persistFixture } from "./retire-dry-run/persisted-fixture.test-utils.js";

vi.setConfig({ testTimeout: 60_000 });

let server: Server | null = null;
const cleanup: string[] = [];
afterEach(async () => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
  await new Promise((r) => (server ? server.close(r) : r(null)));
  server = null;
  for (const dir of cleanup.splice(0)) {
    await rm(dir, { recursive: true, force: true });
  }
});

async function listen(
  serve: (url: URL) => Promise<Response>,
  methods: string[],
): Promise<string> {
  server = createServer(async (req, res) => {
    methods.push(req.method ?? "");
    const response = await serve(new URL(req.url ?? "/", "http://127.0.0.1"));
    res.writeHead(response.status, { "content-type": "application/json" });
    res.end(Buffer.from(await response.arrayBuffer()));
  });
  await new Promise<void>((r) => server!.listen(0, "127.0.0.1", r));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

describe("legacy-retire-dry-run command", () => {
  it("writes the report and exits 0 against a loopback gateway and storage", async () => {
    const p = await persistFixture({ importDone: true, fullRun: true });
    cleanup.push(p.home);
    const methods: string[] = [];
    const base = await listen(p.serve, methods);
    vi.stubEnv("VANA_MASTER_KEY_SIGNATURE", p.signature);
    vi.spyOn(process.stderr, "write").mockReturnValue(true);

    const code = await main([
      "--data-dir",
      p.dataDir,
      "--out",
      p.outPath,
      "--gateway-url",
      base,
      "--storage-url",
      base,
    ]);

    expect(code).toBe(0);
    const report = JSON.parse(await readFile(p.outPath, "utf8"));
    expect(report).toMatchObject({
      status: "ok",
      mode: "dry-run",
      hosts: { gateway: "127.0.0.1", storage: "127.0.0.1" },
      totals: { reported: 5, wouldDelete: 3 },
    });
    expect(new Set(methods)).toEqual(new Set(["GET"]));
  });

  it("exits 2 and writes nothing for a folder that is not a copy under ~/.tmp", async () => {
    const stderr = vi.spyOn(process.stderr, "write").mockReturnValue(true);
    vi.stubEnv("VANA_MASTER_KEY_SIGNATURE", "0x00");
    const code = await main(["--data-dir", "/", "--out", "/nope.json"]);
    expect(code).toBe(2);
    expect(stderr.mock.calls.join("")).toMatch(/Refusing/);
  });

  it("exits 2 with usage when an argument is missing", async () => {
    const stderr = vi.spyOn(process.stderr, "write").mockReturnValue(true);
    expect(await main([])).toBe(2);
    expect(stderr.mock.calls.join("")).toMatch(/Usage/);
  });
});
