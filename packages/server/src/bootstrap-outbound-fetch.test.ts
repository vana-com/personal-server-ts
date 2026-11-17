/**
 * Every client of the data gateway and of storage that the Node host builds
 * sends through the host's one outbound `fetch`. A client left on
 * `globalThis.fetch` opens a new connection after any 4 s gap. Real Node
 * composition; the clients are the real ones, wrapped only to record the
 * `fetch` each was given.
 */
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { privateKeyToAccount } from "viem/accounts";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { createMemoryModeRecordStore } from "@opendatalabs/personal-server-ts-core/sync/account-mode";
import type * as AdaptersModule from "@opendatalabs/personal-server-ts-core/storage/adapters";
import type * as AdditionsModule from "@opendatalabs/personal-server-ts-core/additions";
import type * as LineageModule from "@opendatalabs/personal-server-ts-core/lineage";
import type * as StreamSyncModule from "@opendatalabs/personal-server-ts-core/stream-sync";
import type * as SyncModule from "@opendatalabs/personal-server-ts-core/sync";
import type * as OutboundFetchModule from "./outbound-fetch.js";
import { createServer, type ServerContext } from "./bootstrap.js";

const given = vi.hoisted(
  () => new Map<string, Array<typeof fetch | undefined>>(),
);
const pools = vi.hoisted(() => ({ made: 0, closed: 0 }));
function record(client: string, options: { fetch?: typeof fetch } | undefined) {
  const list = given.get(client) ?? [];
  list.push(options?.fetch);
  given.set(client, list);
}

vi.mock("./outbound-fetch.js", async (importOriginal) => {
  const actual = await importOriginal<typeof OutboundFetchModule>();
  return {
    ...actual,
    createKeepAliveFetch: (
      ...args: Parameters<typeof actual.createKeepAliveFetch>
    ) => {
      const pool = actual.createKeepAliveFetch(...args);
      pools.made += 1;
      return {
        ...pool,
        close: async () => {
          pools.closed += 1;
          await pool.close();
        },
      };
    },
  };
});
vi.mock(
  "@opendatalabs/personal-server-ts-core/storage/adapters",
  async (importOriginal) => {
    const actual = await importOriginal<typeof AdaptersModule>();
    return {
      ...actual,
      createVanaSyncStorageAdapter: (
        ...args: Parameters<typeof actual.createVanaSyncStorageAdapter>
      ) => (
        record("storage", args[0]),
        actual.createVanaSyncStorageAdapter(...args)
      ),
    };
  },
);
vi.mock(
  "@opendatalabs/personal-server-ts-core/additions",
  async (importOriginal) => {
    const actual = await importOriginal<typeof AdditionsModule>();
    return {
      ...actual,
      createVersionInventoryClient: (
        ...args: Parameters<typeof actual.createVersionInventoryClient>
      ) => (
        record("version-inventory", args[0]),
        actual.createVersionInventoryClient(...args)
      ),
    };
  },
);
vi.mock(
  "@opendatalabs/personal-server-ts-core/lineage",
  async (importOriginal) => {
    const actual = await importOriginal<typeof LineageModule>();
    return {
      ...actual,
      createGatewayLineageClient: (
        ...args: Parameters<typeof actual.createGatewayLineageClient>
      ) => (
        record("lineage", args[0]),
        actual.createGatewayLineageClient(...args)
      ),
    };
  },
);
vi.mock(
  "@opendatalabs/personal-server-ts-core/stream-sync",
  async (importOriginal) => {
    const actual = await importOriginal<typeof StreamSyncModule>();
    return {
      ...actual,
      createGatewayStreamSyncRegistry: (
        ...args: Parameters<typeof actual.createGatewayStreamSyncRegistry>
      ) => (
        record("registry", args[0]),
        actual.createGatewayStreamSyncRegistry(...args)
      ),
    };
  },
);
vi.mock(
  "@opendatalabs/personal-server-ts-core/sync",
  async (importOriginal) => {
    const actual = await importOriginal<typeof SyncModule>();
    return {
      ...actual,
      createGatewayDataPointFeed: (
        ...args: Parameters<typeof actual.createGatewayDataPointFeed>
      ) => (
        record("data-point-feed", args[0]),
        actual.createGatewayDataPointFeed(...args)
      ),
      createGatewayDeleteDataPort: (
        ...args: Parameters<typeof actual.createGatewayDeleteDataPort>
      ) => (
        record("delete-data", args[0]),
        actual.createGatewayDeleteDataPort(...args)
      ),
    };
  },
);

const contexts: ServerContext[] = [];
const directories: string[] = [];
afterEach(async () => {
  for (const context of contexts.splice(0)) await context.cleanup();
  given.clear();
  pools.made = 0;
  pools.closed = 0;
  for (const directory of directories.splice(0))
    await rm(directory, { recursive: true, force: true });
  vi.unstubAllEnvs();
});

async function boot(outboundFetch?: typeof fetch) {
  const root = await mkdtemp(join(tmpdir(), "outbound-fetch-"));
  directories.push(root);
  const signature = await privateKeyToAccount(
    `0x${"22".repeat(32)}`,
  ).signMessage({ message: "Disposable outbound fetch fixture" });
  vi.stubEnv("PS_ACCESS_TOKEN", "outbound-fetch-fixture");
  vi.stubEnv("VANA_OWNER_PRIVATE_KEY", "");
  const context = await createServer(
    ServerConfigSchema.parse({
      tunnel: { enabled: false },
      sync: { enabled: true },
      logging: { level: "fatal", pretty: false },
    }),
    {
      rootPath: root,
      ownerSignature: signature,
      accountModeStore: createMemoryModeRecordStore(),
      ...(outboundFetch && { outboundFetch }),
    },
  );
  contexts.push(context);
  return context;
}

const CLIENTS = [
  "storage",
  "registry",
  "data-point-feed",
  "delete-data",
  "version-inventory",
  "lineage",
];

describe("the host's outbound fetch", () => {
  it("is the one fetch every gateway and storage client is given", async () => {
    // Answers nothing from the network: the registry's change probe runs at boot.
    const outbound = vi.fn(async () => new Response("{}", { status: 404 }));

    await boot(outbound as unknown as typeof fetch);

    for (const client of CLIENTS) {
      const fetches = given.get(client) ?? [];
      expect(fetches.length, `${client} was built`).toBeGreaterThan(0);
      expect(
        fetches.every((fetch) => fetch === outbound),
        `${client} sends through the host fetch`,
      ).toBe(true);
    }
  });

  it("is a keep-alive fetch of its own when the host passes none", async () => {
    await boot();

    for (const client of CLIENTS) {
      const fetches = given.get(client) ?? [];
      expect(fetches.length, `${client} was built`).toBeGreaterThan(0);
      expect(
        fetches.every(
          (fetch) => fetch !== undefined && fetch !== globalThis.fetch,
        ),
        `${client} does not use globalThis.fetch`,
      ).toBe(true);
      expect(new Set(fetches).size, `${client} shares one fetch`).toBe(1);
    }
    const all = CLIENTS.flatMap((client) => given.get(client) ?? []);
    expect(new Set(all).size, "one fetch for every client").toBe(1);
  });

  it("closes the host's connection pool when the server stops", async () => {
    const context = await boot();
    expect(pools.made).toBe(1);
    expect(pools.closed).toBe(0);

    await context.cleanup();
    contexts.splice(contexts.indexOf(context), 1);

    expect(pools.closed).toBe(1);
  });

  it("lets cleanup run twice: a harness that restarts a boot cleans the old one again", async () => {
    const context = await boot();

    await context.cleanup();
    await expect(context.cleanup()).resolves.toBeUndefined();

    contexts.splice(contexts.indexOf(context), 1);
  });

  it("leaves a fetch the host passed to its owner, making no pool of its own", async () => {
    const context = await boot(
      vi.fn(
        async () => new Response("{}", { status: 404 }),
      ) as unknown as typeof fetch,
    );

    await context.cleanup();
    contexts.splice(contexts.indexOf(context), 1);

    expect(pools.made).toBe(0);
    expect(pools.closed).toBe(0);
  });
});
