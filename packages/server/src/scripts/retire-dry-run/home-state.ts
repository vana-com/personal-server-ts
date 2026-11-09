/**
 * What the dry run reads of this device's stream-sync home, with plain reads.
 *
 * The home is opened by the running server under an exclusive SQLite lock; the
 * tool never takes that lock and never writes there. It reads two small JSON
 * files of the copy:
 *   - `legacy-retire/ledger.json`: whether this device's import is done, and
 *     its per-stream receipts (the stored readbacks are ignored, so every
 *     readback is fresh);
 *   - `state.json`: `fullSince`, which the writer keeps (stream-sync/writer.ts,
 *     `WriterState.fullSince`) to prove a full run re-collected a stream.
 * A missing or unreadable file proves nothing, as it does for the server.
 */

import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { streamSyncHomeId } from "@opendatalabs/personal-server-ts-core/stream-sync";

/** What the ledger holds of one connector's import. */
export interface ImportedRecord {
  streams: number;
  at: string;
  /**
   * The receipt: per stream, what the device's import reports it staged. The
   * tool passes it to the retire pass unread; the pass decides what it proves.
   * A record without one (written before receipts) proves no stream.
   */
  staged?: Record<string, number>;
}

export interface HomeState {
  readonly importComplete: boolean;
  readonly imported: Record<string, ImportedRecord>;
  readonly fullSince: Record<string, Record<string, number>>;
}

async function readJson(path: string): Promise<Record<string, unknown>> {
  try {
    const parsed: unknown = JSON.parse(await readFile(path, "utf8"));
    return typeof parsed === "object" && parsed !== null
      ? (parsed as Record<string, unknown>)
      : {};
  } catch {
    return {};
  }
}

const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/**
 * The imports the ledger lists. A receipt that is not a plain map of finite
 * non-negative numbers is dropped whole: a malformed receipt proves nothing,
 * the same as a missing one.
 */
function importedOf(value: unknown): Record<string, ImportedRecord> {
  const out: Record<string, ImportedRecord> = {};
  if (!isObject(value)) return out;
  for (const [connector, record] of Object.entries(value)) {
    if (!isObject(record)) continue;
    const entry: ImportedRecord = {
      streams: typeof record.streams === "number" ? record.streams : 0,
      at: typeof record.at === "string" ? record.at : "",
    };
    const staged = record.staged;
    if (
      isObject(staged) &&
      Object.values(staged).every(
        (n) => Number.isFinite(n) && (n as number) >= 0,
      )
    ) {
      entry.staged = staged as Record<string, number>;
    }
    out[connector] = entry;
  }
  return out;
}

export async function readHomeState(input: {
  readonly rootDir: string;
  readonly ownerAddress: string;
  readonly network: string;
}): Promise<HomeState> {
  const id = streamSyncHomeId(input);
  const home = join(input.rootDir, "stream-sync-homes", id);
  const ledger = await readJson(join(home, "legacy-retire", "ledger.json"));
  const state = await readJson(join(home, "state.json"));
  return {
    importComplete: ledger.importComplete === true,
    imported: importedOf(ledger.imported),
    fullSince: (state.fullSince ?? {}) as HomeState["fullSince"],
  };
}
