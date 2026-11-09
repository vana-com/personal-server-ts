/**
 * The read-only dry run of the legacy retire, on a byte copy of a Personal
 * Server data folder.
 *
 * It composes parts the running server already has (the SQLite index and file
 * store, the published-head reader, the retire pass) and none of its writers:
 * no `StreamSyncWriter`, no `LegacyImporter`, no sync manager, no connector
 * runs, no `createServer`. See `run.test.ts` for the checks that keep it so.
 */

import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import {
  createRetireHost,
  retireLegacyFiles,
  RetireLedger,
  type RetireReport,
} from "@opendatalabs/personal-server-ts-core/sync";
import {
  createMemoryStreamSyncFiles,
  streamSyncNetwork,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import type { ServerConfig } from "@opendatalabs/personal-server-ts-core/schemas";
import { assertCopyOnly } from "./copy-only.js";
import { fingerprintTree } from "./fingerprint.js";
import { openLegacyStore } from "./legacy-store.js";
import { installNetworkGuard, NetworkGuardError } from "./network-guard.js";
import {
  allowedHostsOf,
  loadPublishedHeads,
  MIRROR_PATH,
  parseConfig,
} from "./published-heads.js";
import { readHomeState } from "./home-state.js";
import { abortedReport, buildReport, type RedactedReport } from "./report.js";

const SIGNATURE = /^0x[0-9a-fA-F]{130}$/;

export class DryRunSetupError extends Error {
  constructor(
    readonly code: "no_owner_signature" | "bad_owner_signature" | "bad_config",
    message: string,
  ) {
    super(message);
    this.name = "DryRunSetupError";
  }
}

export interface DryRunOptions {
  /** The copy of the Personal Server root (holds `index.db`, `data/`). */
  readonly dataDir: string;
  readonly outPath: string;
  readonly home: string;
  /** Owner master-key signature; the tool reads it from the environment. */
  readonly masterKeySignature: string | undefined;
  readonly gatewayUrl?: string;
  readonly storageUrl?: string;
  readonly now?: () => Date;
  readonly log?: (line: string) => void;
}

async function readOptional(path: string): Promise<Uint8Array | null> {
  try {
    return await readFile(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw error;
  }
}

/** The few config.json fields the tool overrides; the schema checks the rest. */
interface ConfigJson {
  gateway?: Record<string, unknown>;
  storage?: { config?: Record<string, unknown> } & Record<string, unknown>;
}

async function readConfig(
  rootDir: string,
  override: Pick<DryRunOptions, "gatewayUrl" | "storageUrl">,
): Promise<ServerConfig> {
  let raw: ConfigJson = {};
  try {
    raw = JSON.parse(await readFile(join(rootDir, "config.json"), "utf8"));
  } catch {
    // No config in the copy: the schema defaults name the Dev hosts.
  }
  if (override.gatewayUrl) {
    raw = { ...raw, gateway: { ...raw.gateway, url: override.gatewayUrl } };
  }
  if (override.storageUrl) {
    raw = {
      ...raw,
      storage: {
        ...raw.storage,
        config: {
          ...raw.storage?.config,
          vana: { apiUrl: override.storageUrl },
        },
      },
    };
  }
  try {
    return parseConfig(raw);
  } catch {
    throw new DryRunSetupError("bad_config", "config.json does not parse");
  }
}

export async function runLegacyRetireDryRun(
  options: DryRunOptions,
): Promise<RedactedReport> {
  const log = options.log ?? (() => undefined);
  const now = options.now ?? (() => new Date());
  const { dataDir, outPath } = await assertCopyOnly({
    dataDir: options.dataDir,
    outPath: options.outPath,
    home: options.home,
  });

  if (!options.masterKeySignature) {
    throw new DryRunSetupError(
      "no_owner_signature",
      "Set VANA_MASTER_KEY_SIGNATURE: the owner's key is not in the data folder.",
    );
  }
  if (!SIGNATURE.test(options.masterKeySignature)) {
    throw new DryRunSetupError(
      "bad_owner_signature",
      "VANA_MASTER_KEY_SIGNATURE is not a 65-byte hex signature.",
    );
  }
  // The device's own network names its stream-sync home; flags only change
  // where requests go (for a local test server), never which home is read.
  const deviceConfig = await readConfig(dataDir, {});
  const config = await readConfig(dataDir, options);
  const hosts = allowedHostsOf(config);
  log(`Allowed hosts (GET only): ${hosts.gateway}, ${hosts.storage}`);

  const before = await fingerprintTree(dataDir);
  const scratchDir = join(dirname(outPath), `${basename(outPath)}.work`);
  const guard = installNetworkGuard({
    allowedHosts: [hosts.gateway, hosts.storage],
  });
  let store: Awaited<ReturnType<typeof openLegacyStore>> | null = null;
  let retire: RetireReport | null = null;
  let report: RedactedReport;
  try {
    store = await openLegacyStore({ rootDir: dataDir, scratchDir });
    const heads = await loadPublishedHeads({
      config,
      masterKeySignature: options.masterKeySignature as `0x${string}`,
      mirrorBytes: await readOptional(
        join(dataDir, "stream-sync-read", MIRROR_PATH),
      ),
    });
    const home = await readHomeState({
      rootDir: dataDir,
      ownerAddress: heads.ownerAddress,
      network: streamSyncNetwork(deviceConfig.gateway),
    });

    // The ledger lives in memory and starts with this device's import state
    // only; every readback is made fresh and nothing is persisted.
    const ledger = new RetireLedger(createMemoryStreamSyncFiles());
    await ledger.update((data) => {
      data.importComplete = home.importComplete;
      data.imported = home.imported;
    });
    const host = createRetireHost({
      reader: heads.reader,
      writer: {
        fullRunSince: async (connector, stream, deleteVersion) => {
          const at = home.fullSince[connector]?.[stream];
          return at !== undefined && at >= deleteVersion;
        },
      },
      ledger,
    });
    retire = await retireLegacyFiles({
      storage: store.storage,
      host,
      ledger,
      deleteEnabled: false,
      dryRun: true,
      readbackBeforeImport: true,
      now,
    });
    guard.assertNoViolations();
    if ((await fingerprintTree(dataDir)) !== before) {
      throw new Error("data_folder_changed");
    }
    const records = new Map(Object.entries((await ledger.read()).readbacks));
    report = buildReport({
      generatedAt: now().toISOString(),
      retire,
      records,
      hosts,
      deviceImport: {
        complete: home.importComplete,
        connectors: Object.keys(home.imported).length,
      },
      publishedListing: heads.listing,
      store: store.countVersions(),
    });
  } catch (error) {
    const reason =
      error instanceof NetworkGuardError
        ? `network_guard:${error.violation.reason}`
        : error instanceof Error && error.message === "data_folder_changed"
          ? "data_folder_changed"
          : error instanceof Error
            ? error.name
            : "unknown";
    // A guard violation may have been swallowed on the way here.
    const violated = guard.violations.length > 0;
    await mkdir(dirname(outPath), { recursive: true });
    await writeFile(
      outPath,
      JSON.stringify(
        abortedReport({
          generatedAt: now().toISOString(),
          abortReason: violated ? "network_guard" : reason,
          hosts,
        }),
        null,
        2,
      ),
    );
    throw error;
  } finally {
    guard.uninstall();
    store?.close();
    await rm(scratchDir, { recursive: true, force: true });
  }
  await writeFile(outPath, JSON.stringify(report, null, 2));
  return report;
}
