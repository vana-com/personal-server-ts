/**
 * Retirement after the legacy import, through the public Node entry
 * (`startPersonalServer`): the host's `legacyRetire` port is opened after the
 * host's importer returns, and `streamSync.retireLegacy` from the server's own
 * config decides whether the old copy is erased or only read back.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer as createNetServer } from "node:net";
import { join } from "node:path";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { createTestWallet } from "@opendatalabs/personal-server-ts-core/test-utils";
import type { ImportRunner } from "@opendatalabs/personal-server-ts-core/sync/account-mode";
import type { LegacyCopy } from "@opendatalabs/personal-server-ts-core/localdb";
import { startPersonalServer } from "./client.js";
import type { LegacyRetirePort } from "./localdb/retire-after-import.js";

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

async function until(check: () => boolean): Promise<void> {
  for (let i = 0; i < 300 && !check(); i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

const copy: LegacyCopy = {
  id: "copy-1",
  path: "/legacy/copy.json",
  contentHash: "hash",
  revision: "revision",
  dataSet: "fixture.profile",
  sources: [],
};

function fixture(openError?: Error) {
  const events: string[] = [];
  const importer: ImportRunner = {
    run: async () => void events.push("import"),
  };
  const erase = vi.fn(async () => {
    events.push("erase");
    return true;
  });
  let deps: unknown;
  const port: LegacyRetirePort = {
    open: async (d) => {
      events.push("open");
      deps = d;
      if (openError) throw openError;
      return {
        access: {
          copies: async function* () {
            yield copy;
          },
          readBack: async () => [],
          erase,
        },
        close: async () => void events.push("close"),
      };
    },
  };
  return { importer, port, events, erase, deps: () => deps };
}

async function start(
  rootPath: string,
  retireLegacy: boolean,
  f: ReturnType<typeof fixture>,
) {
  const port = await freePort();
  return startPersonalServer({
    rootPath,
    config: ServerConfigSchema.parse({
      server: { port, origin: `http://localhost:${port}` },
      logging: { level: "fatal", pretty: false },
      devUi: { enabled: false },
      sync: { enabled: false, lastProcessedTimestamp: null },
      tunnel: { enabled: false },
      streamSync: { retireLegacy },
    }),
    ownerSignature: await ownerWallet.signMessage("vana-master-key-v1"),
    localApproval: false,
    legacyImporter: f.importer,
    legacyRetire: f.port,
  });
}

const answer = (ps: Awaited<ReturnType<typeof start>>, state: "on" | "off") =>
  ps.submitAccountModeEvidence?.({ owner: ownerWallet.address, state });

async function scratch() {
  const rootPath = await mkdtemp(
    join(process.env.HOME ?? "", ".tmp", "ps-retire-"),
  );
  cleanups.push(() => rm(rootPath, { recursive: true, force: true }));
  return rootPath;
}

describe("startPersonalServer and retirement after the legacy import", () => {
  it("setting on: the import returns, then the old copy is erased with the server's database", async () => {
    const f = fixture();
    const ps = await start(await scratch(), true, f);
    cleanups.push(() => ps.stop());
    await answer(ps, "on");
    await until(() => f.events.includes("close"));
    expect(f.events).toEqual(["import", "open", "erase", "close"]);
    expect(f.deps()).toMatchObject({ ownerAddress: expect.any(String) });
  }, 30_000);

  it("setting off: the same run only reads back, nothing is erased", async () => {
    const f = fixture();
    const ps = await start(await scratch(), false, f);
    cleanups.push(() => ps.stop());
    await answer(ps, "on");
    await until(() => f.events.includes("close"));
    expect(f.events).toEqual(["import", "open", "close"]);
    expect(f.erase).not.toHaveBeenCalled();
  }, 30_000);

  it("an Account answer of Off imports and retires nothing", async () => {
    const f = fixture();
    const ps = await start(await scratch(), true, f);
    cleanups.push(() => ps.stop());
    await answer(ps, "off");
    await new Promise((resolve) => setTimeout(resolve, 200));
    expect(f.events).toEqual([]);
  }, 30_000);

  it("a retirement failure does not stop the server, and the next start retries", async () => {
    const rootPath = await scratch();
    const broken = fixture(new Error("legacy store unavailable"));
    const one = await start(rootPath, true, broken);
    await answer(one, "on");
    await until(() => broken.events.includes("open"));
    expect(broken.events).toEqual(["import", "open"]);
    await expect(one.info()).resolves.toMatchObject({ status: "ready" });
    await one.stop();

    const healthy = fixture();
    const two = await start(rootPath, true, healthy);
    cleanups.push(() => two.stop());
    await until(() => healthy.events.includes("close"));
    expect(healthy.events).toEqual(["import", "open", "erase", "close"]);
  }, 30_000);
});
