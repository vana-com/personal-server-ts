/**
 * The host's legacy importer, through the public Node entry
 * (`startPersonalServer`): it is built from the option the host passes, runs
 * when the Account answers On and at boot for an owner already switched, and
 * is aborted and awaited by `stop()`.
 */
import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer as createNetServer } from "node:net";
import { join } from "node:path";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { createTestWallet } from "@opendatalabs/personal-server-ts-core/test-utils";
import type { ImportRunner } from "@opendatalabs/personal-server-ts-core/sync/account-mode";
import { startPersonalServer } from "./client.js";

const ownerWallet = createTestWallet(9);
const cleanups: Array<() => Promise<void>> = [];

afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

async function freePort(): Promise<number> {
  const probe = createNetServer();
  await new Promise<void>((resolve) => probe.listen(0, "127.0.0.1", resolve));
  const address = probe.address();
  await new Promise<void>((resolve) => probe.close(() => resolve()));
  if (!address || typeof address === "string") throw new Error("no port");
  return address.port;
}

function fakeImporter() {
  const runs: AbortSignal[] = [];
  const importer: ImportRunner = {
    // Runs until aborted, so a stop that does not abort would hang.
    run: (signal) =>
      new Promise<void>((resolve) => {
        runs.push(signal);
        signal.addEventListener("abort", () => resolve());
      }),
  };
  return { importer, runs };
}

async function until(check: () => boolean): Promise<void> {
  for (let i = 0; i < 200 && !check(); i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

async function start(rootPath: string, importer: ImportRunner) {
  const port = await freePort();
  const ps = await startPersonalServer({
    rootPath,
    config: ServerConfigSchema.parse({
      server: { port, origin: `http://localhost:${port}` },
      logging: { level: "fatal", pretty: false },
      devUi: { enabled: false },
      sync: { enabled: false, lastProcessedTimestamp: null },
      tunnel: { enabled: false },
    }),
    ownerSignature: await ownerWallet.signMessage("vana-master-key-v1"),
    localApproval: false,
    legacyImporter: importer,
  });
  return ps;
}

const answer = (ps: Awaited<ReturnType<typeof start>>, state: "on" | "off") =>
  ps.submitAccountModeEvidence?.({ owner: ownerWallet.address, state });

describe("startPersonalServer and the legacy importer", () => {
  it("runs the importer it was given when the Account says On, not for Off", async () => {
    const rootPath = await mkdtemp(
      join(process.env.HOME ?? "", ".tmp", "ps-wake-"),
    );
    cleanups.push(() => rm(rootPath, { recursive: true, force: true }));
    const { importer, runs } = fakeImporter();
    const ps = await start(rootPath, importer);
    cleanups.push(() => ps.stop());

    await answer(ps, "off");
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(runs).toHaveLength(0);

    await answer(ps, "on");
    await until(() => runs.length > 0);
    expect(runs).toHaveLength(1);

    // stop() aborts the run and waits for it: this would hang otherwise.
    await ps.stop();
    expect(runs[0]?.aborted).toBe(true);
  }, 30_000);

  it("runs it at boot for an owner whose saved answer is On", async () => {
    const rootPath = await mkdtemp(
      join(process.env.HOME ?? "", ".tmp", "ps-wake-"),
    );
    cleanups.push(() => rm(rootPath, { recursive: true, force: true }));
    const first = fakeImporter();
    const one = await start(rootPath, first.importer);
    await answer(one, "on");
    await until(() => first.runs.length > 0);
    await one.stop();

    const second = fakeImporter();
    const two = await start(rootPath, second.importer);
    cleanups.push(() => two.stop());
    await until(() => second.runs.length > 0);
    expect(second.runs).toHaveLength(1);
  }, 30_000);
});
