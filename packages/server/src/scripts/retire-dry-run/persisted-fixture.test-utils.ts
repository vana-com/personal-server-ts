/**
 * The #595 synthetic fixture, persisted: its legacy files go into a data
 * folder through the real Node storage stack (SQLite index + files), and its
 * published heads are served by a fake gateway and storage over `fetch`.
 * Every value is made up.
 */

import { mkdir, mkdtemp, copyFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { toHex } from "viem";
import {
  streamSyncHomeId,
  streamSyncNetwork,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import { recoverOwnerAddress } from "@opendatalabs/personal-server-ts-core/keys";
import { createDataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import { masterKey } from "../../../../core/src/stream-sync-read/service-fixture.js";
import {
  buildSyntheticFixture,
  type SyntheticFixture,
} from "../../../../core/src/sync/legacy-retire/synthetic-fixture.js";
import { DEV_GATEWAY_URL, DEV_STORAGE_URL } from "./hosts.js";
import { initializeDatabase } from "../../storage/index-schema.js";
import { createIndexManager } from "../../storage/index-manager.js";
import { createNodeDataStorage } from "../../storage/node-data-storage.js";

// The fake network answers to the tool's pinned Dev hosts: the tool refuses
// any other, so the fixture cannot name its own.
export const GATEWAY_URL = DEV_GATEWAY_URL;
export const STORAGE_URL = DEV_STORAGE_URL;
export const CHAIN_ID = 14800;

/** A throwaway "home" under the real ~/.tmp (disk-backed), with `.tmp` in it. */
export async function makeHome(): Promise<string> {
  const base = join(homedir(), ".tmp");
  await mkdir(base, { recursive: true });
  const home = await mkdtemp(join(base, "retire-dry-run-test-"));
  await mkdir(join(home, ".tmp"), { recursive: true });
  return home;
}

export interface PersistedFixture {
  readonly fx: SyntheticFixture;
  readonly home: string;
  /** The folder a person would hand to the tool (a copy of the root). */
  readonly dataDir: string;
  readonly outPath: string;
  readonly signature: `0x${string}`;
  readonly ownerAddress: `0x${string}`;
  /** Every request the fake network saw. */
  readonly requests: { method: string; host: string; url: string }[];
  /** `fetch` for the fake gateway and storage; install with vi.stubGlobal. */
  readonly fetch: typeof fetch;
  /** The same fake network by path, for a real loopback server. */
  readonly serve: (url: URL) => Promise<Response>;
}

export async function persistFixture(
  options: {
    home?: string;
    /** Write `legacy-retire/ledger.json` with the import done. */
    importDone?: boolean;
    /**
     * With `importDone`: the device also staged rows for every connector
     * (default true). False is an import over an empty source: done, but
     * nothing staged.
     */
    staged?: boolean;
    /** Make the full-run proof of every deleted stream true. */
    fullRun?: boolean;
    /** Write the device's registry mirror (default true). */
    mirror?: boolean;
  } = {},
): Promise<PersistedFixture> {
  const fx = await buildSyntheticFixture();
  const home = options.home ?? (await makeHome());
  const live = join(home, "live-root");
  const dataDir = join(home, ".tmp", "copy");
  await mkdir(join(live, "data"), { recursive: true });

  // 1. The live root, written by the real stack. The WAL is never checkpointed
  //    so the copy below carries data only in the -wal file.
  const db = initializeDatabase(join(live, "index.db"));
  db.pragma("wal_autocheckpoint = 0");
  const node = createNodeDataStorage({
    indexManager: createIndexManager(db),
    hierarchyOptions: { dataDir: join(live, "data") },
  });
  for (const entry of fx.storage.entries) {
    const envelope = await fx.storage.readEnvelope(
      entry.scope,
      entry.collectedAt,
    );
    const written = await node.writeEnvelope(
      createDataFileEnvelope(
        entry.scope,
        entry.collectedAt,
        envelope.data as Record<string, unknown>,
      ),
    );
    await node.insertEntry({
      fileId: null,
      schemaId: null,
      path: written.relativePath,
      scope: entry.scope,
      collectedAt: entry.collectedAt,
      sizeBytes: written.sizeBytes,
      afterTombstoneVersion: null,
    });
  }

  // The in-memory fixture stores every legacy file at the memory store's
  // epoch, long before the registry's delete. The delete fence needs the file
  // to predate the delete by when this device stored it (created_at) too.
  db.prepare("UPDATE data_files SET created_at = ?").run(
    new Date(0).toISOString(),
  );

  const signature = toHex(await masterKey(901)) as `0x${string}`;
  const ownerAddress = await recoverOwnerAddress(signature);
  const config = {
    gateway: { url: GATEWAY_URL },
    storage: { config: { vana: { apiUrl: STORAGE_URL } } },
  };
  await writeFile(join(live, "config.json"), JSON.stringify(config));

  // The device's registry mirror, as its running server persisted it (it
  // saw the tombstone before the stream was re-published).
  if (options.mirror !== false) {
    await mkdir(join(live, "stream-sync-read"), { recursive: true });
    await writeFile(
      join(live, "stream-sync-read", "mirror.json"),
      fx.fixture.files.files.get("mirror.json")!,
    );
  }

  // 2. This device's stream-sync home: import state and full-run proof.
  const homeId = streamSyncHomeId({
    ownerAddress,
    network: streamSyncNetwork({ chainId: CHAIN_ID, url: GATEWAY_URL }),
  });
  const homeDir = join(live, "stream-sync-homes", homeId);
  if (options.importDone) {
    const imported: Record<string, { streams: number; at: string }> = {};
    if (options.staged !== false) {
      for (const scope of fx.scopes) {
        for (const s of fx.reader.retireBasis(scope.scope)?.streams ?? []) {
          imported[s.connector] = { streams: 1, at: "2026-10-30T00:00:00Z" };
        }
      }
    }
    await mkdir(join(homeDir, "legacy-retire"), { recursive: true });
    await writeFile(
      join(homeDir, "legacy-retire", "ledger.json"),
      JSON.stringify({ importComplete: true, imported, readbacks: {} }),
    );
  }
  if (options.fullRun) {
    const fullSince: Record<string, Record<string, number>> = {};
    for (const scope of fx.scopes) {
      for (const s of fx.reader.retireBasis(scope.scope)?.streams ?? []) {
        (fullSince[s.connector] ??= {})[s.stream] = Number.MAX_SAFE_INTEGER;
      }
    }
    await mkdir(homeDir, { recursive: true });
    await writeFile(join(homeDir, "state.json"), JSON.stringify({ fullSince }));
  }

  // 3. The copy: index.db and index.db-wal (never -shm) plus everything else.
  await mkdir(dataDir, { recursive: true });
  await copyTree(live, dataDir, (name) => name.endsWith("-shm"));
  db.close();

  const requests: PersistedFixture["requests"] = [];
  const blobPath = new RegExp(
    `^/v1/chains/${CHAIN_ID}/blobs/${ownerAddress.toLowerCase()}/(.+)$`,
  );
  /** The fake gateway and storage, by path, whatever the host is. */
  const serve = async (url: URL): Promise<Response> => {
    if (url.pathname === "/v1/data") {
      return Response.json({
        data: { dataPoints: [...fx.fixture.rows.values()] },
        pagination: { hasMore: false, nextCursor: null },
      });
    }
    const blob = blobPath.exec(url.pathname);
    if (blob) {
      const key = blob[1]!.split("/").map(decodeURIComponent).join("/");
      const bytes = fx.fixture.blobs.get(key);
      return bytes
        ? new Response(bytes as BodyInit, { status: 200 })
        : new Response("not found", { status: 404 });
    }
    return new Response("not found", { status: 404 });
  };
  const fakeFetch = (async (target: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(
      typeof target === "string" || target instanceof URL ? target : target.url,
    );
    const method = (init?.method ?? "GET").toUpperCase();
    requests.push({ method, host: url.hostname, url: url.pathname });
    return serve(url);
  }) as typeof fetch;

  return {
    fx,
    home,
    dataDir,
    outPath: join(home, ".tmp", "report.json"),
    signature,
    ownerAddress,
    requests,
    fetch: fakeFetch,
    serve,
  };
}

async function copyTree(
  from: string,
  to: string,
  skip: (name: string) => boolean,
): Promise<void> {
  const { readdir } = await import("node:fs/promises");
  for (const item of await readdir(from, { withFileTypes: true })) {
    if (skip(item.name)) continue;
    if (item.isDirectory()) {
      await mkdir(join(to, item.name), { recursive: true });
      await copyTree(join(from, item.name), join(to, item.name), skip);
    } else {
      await copyFile(join(from, item.name), join(to, item.name));
    }
  }
}
