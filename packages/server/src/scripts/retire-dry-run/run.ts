/**
 * The read-only dry run of the legacy retire, on a byte copy of a Personal
 * Server data folder.
 *
 * It composes parts the running server already has (the SQLite index and file
 * store, the published-head reader, the retire pass) and none of its writers:
 * no `StreamSyncWriter`, no `LegacyImporter`, no sync manager, no connector
 * runs, no `createServer`. See `run.test.ts` for the checks that keep it so.
 *
 * Load order: this module imports only Node built-ins, the guard, and pure
 * helpers. The guard installs before any package module or the SQLite store is
 * loaded (dynamic `import()` below). `entry-static-imports.test.ts` checks the
 * static imports of this module and of the entry; `run-entry-order.test.ts`
 * checks that a module which keeps a reference to `fetch` from its load time
 * gets the guarded one.
 */

import { randomBytes } from "node:crypto";
import { mkdtemp, readFile, rename, rm, writeFile } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import type { RetireReport } from "@opendatalabs/personal-server-ts-core/sync";
import type { ServerConfig } from "@opendatalabs/personal-server-ts-core/schemas";
import type { openLegacyStore as OpenLegacyStore } from "./legacy-store.js";
import { assertCopyOnly } from "./copy-only.js";
import { copyAge, fingerprintTree } from "./fingerprint.js";
import { pinHosts } from "./hosts.js";
import { DryRunSetupError } from "./setup-error.js";
import { installNetworkGuard, NetworkGuardError } from "./network-guard.js";
import { abortedReport, buildReport, type RedactedReport } from "./report.js";

const SIGNATURE = /^0x[0-9a-fA-F]{130}$/;

export { DryRunSetupError };

export interface DryRunOptions {
  /** The copy of the Personal Server root (holds `index.db`, `data/`). */
  readonly dataDir: string;
  readonly outPath: string;
  readonly home: string;
  /** Owner master-key signature; the tool reads it from the environment. */
  readonly masterKeySignature: string | undefined;
  /** Which runtime config file to read; required when the folder has both. */
  readonly configFile?: RuntimeConfigFile;
  /** Select a pinned Dev host (see `hosts.ts`); any other value is refused. */
  readonly gatewayUrl?: string;
  readonly storageUrl?: string;
  /** For tests only: also allow the exact loopback `host:port` given above. */
  readonly testOnlyAllowLoopback?: boolean;
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

interface ConfigJson {
  gateway?: Record<string, unknown>;
  storage?: { config?: { vana?: { apiUrl?: unknown } } };
}

/** The two files a runtime reads its config from. */
export const RUNTIME_CONFIG_FILES = ["server.json", "config.json"] as const;
export type RuntimeConfigFile = (typeof RUNTIME_CONFIG_FILES)[number];

async function readTextOrNull(path: string): Promise<string | null> {
  try {
    return await readFile(path, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw error;
  }
}

/**
 * The copy's runtime config. A Desktop folder holds `server.json`: the app
 * writes its gateway and storage into it and boots the runtime on it, and it
 * also overlays derived defaults at boot. A self-hosted runtime boots on
 * `config.json` (packages/server/src/bootstrap.ts). With one file in the folder
 * that file is used. With both, the folder does not say which runtime owns it,
 * so the caller must name the file (`--config`). Nothing is merged.
 */
async function readRuntimeConfig(
  rootDir: string,
  choice: RuntimeConfigFile | undefined,
): Promise<ConfigJson> {
  const texts = new Map<RuntimeConfigFile, string>();
  for (const name of RUNTIME_CONFIG_FILES) {
    const text = await readTextOrNull(join(rootDir, name));
    if (text !== null) texts.set(name, text);
  }
  let name: RuntimeConfigFile | undefined;
  if (choice !== undefined) {
    if (!texts.has(choice)) {
      throw new DryRunSetupError(
        "config_missing",
        "The file named by --config is not in the copy.",
      );
    }
    name = choice;
  } else if (texts.size > 1) {
    throw new DryRunSetupError(
      "config_ambiguous",
      "The copy holds both server.json and config.json. Pass --config server.json or --config config.json to name the file the runtime boots on.",
    );
  } else {
    name = [...texts.keys()][0];
  }
  if (name === undefined) return {}; // No config in the copy: the Dev hosts are the defaults.
  try {
    const parsed: unknown = JSON.parse(texts.get(name)!);
    return typeof parsed === "object" && parsed !== null
      ? (parsed as ConfigJson)
      : {};
  } catch {
    return {};
  }
}

const stringOrUndefined = (value: unknown): string | undefined =>
  typeof value === "string" ? value : undefined;

export async function runLegacyRetireDryRun(
  options: DryRunOptions,
): Promise<RedactedReport> {
  const log = options.log ?? (() => undefined);
  const now = options.now ?? (() => new Date());
  const { dataDir, outPath, tmpRoot } = await assertCopyOnly({
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
  // Flags and the copy's config only select among the pinned Dev hosts
  // (hosts.ts). The schema parse runs after the guard is in place (below).
  const raw = await readRuntimeConfig(dataDir, options.configFile);
  const pinned = pinHosts({
    gatewayUrl: options.gatewayUrl ?? stringOrUndefined(raw.gateway?.url),
    storageUrl:
      options.storageUrl ??
      stringOrUndefined(raw.storage?.config?.vana?.apiUrl),
    testOnlyAllowLoopback: options.testOnlyAllowLoopback === true,
  });
  const hosts = pinned.hosts;
  log(`Allowed hosts (GET only): ${hosts.gateway}, ${hosts.storage}`);

  const before = await fingerprintTree(dataDir);
  const copy = await copyAge(dataDir);
  // A new, empty folder of the tool's own, never derived from `--out`: no
  // path the person gives can name it, so it cannot be the copy.
  const scratchDir = await mkdtemp(join(tmpRoot, "retire-dry-run-"));
  const guard = installNetworkGuard({ allowedHosts: pinned.allowed });
  let store: Awaited<ReturnType<typeof OpenLegacyStore>> | null = null;
  let retire: RetireReport | null = null;
  let report: RedactedReport;
  try {
    // Loaded only now, with the guard in place (see the header).
    const { createRetireHost, retireLegacyFiles, RetireLedger } =
      await import("@opendatalabs/personal-server-ts-core/sync");
    const { createMemoryStreamSyncFiles, streamSyncNetwork } =
      await import("@opendatalabs/personal-server-ts-core/stream-sync");
    const { openLegacyStore } = await import("./legacy-store.js");
    const { loadPublishedHeads, MIRROR_PATH, parseConfig } =
      await import("./published-heads.js");
    const { readHomeState } = await import("./home-state.js");
    const { recheckReadyFiles } = await import("./recheck.js");

    // The device's own network names its stream-sync home.
    let deviceConfig: ServerConfig;
    try {
      deviceConfig = parseConfig(raw);
    } catch {
      throw new DryRunSetupError(
        "bad_config",
        "the copy's runtime config does not parse",
      );
    }
    const config = parseConfig({
      ...raw,
      gateway: { ...raw.gateway, url: pinned.gatewayUrl },
      storage: {
        ...raw.storage,
        config: { ...raw.storage?.config, vana: { apiUrl: pinned.storageUrl } },
      },
    });
    store = await openLegacyStore({ rootDir: dataDir, scratchDir });
    const heads = await loadPublishedHeads({
      config,
      masterKeySignature: options.masterKeySignature as `0x${string}`,
      now,
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
      now,
    });
    // The real pass hashes a file again right before it erases it. It never
    // gets there in a dry run, so take that step here (read only).
    const records = new Map(Object.entries((await ledger.read()).readbacks));
    retire = await recheckReadyFiles({
      retire,
      records,
      storage: store.storage,
    });
    guard.assertNoViolations();
    if ((await fingerprintTree(dataDir)) !== before) {
      throw new Error("data_folder_changed");
    }
    report = buildReport({
      generatedAt: now().toISOString(),
      retire,
      records,
      hosts,
      copy,
      deviceImport: {
        complete: home.importComplete,
        connectors: Object.keys(home.imported).length,
        receipts: Object.values(home.imported).filter((i) => i.staged).length,
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
    await writeReport(
      outPath,
      abortedReport({
        generatedAt: now().toISOString(),
        abortReason: violated ? "network_guard" : reason,
        hosts,
      }),
    );
    throw error;
  } finally {
    guard.uninstall();
    store?.close();
    await rm(scratchDir, { recursive: true, force: true });
  }
  await writeReport(outPath, report);
  return report;
}

/**
 * Write to a new file beside `--out` and rename it over `--out`. A rename
 * replaces the path itself, so a link put there after the check is replaced
 * and never followed.
 */
async function writeReport(
  outPath: string,
  report: RedactedReport,
): Promise<void> {
  const temp = join(
    dirname(outPath),
    `.${basename(outPath)}.${randomBytes(6).toString("hex")}.tmp`,
  );
  try {
    await writeFile(temp, JSON.stringify(report, null, 2), { flag: "wx" });
    await rename(temp, outPath);
  } catch (error) {
    await rm(temp, { force: true });
    throw error;
  }
}
