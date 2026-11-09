/**
 * What the dry run reads of this device's stream-sync home, with plain reads.
 *
 * The home is opened by the running server under an exclusive SQLite lock; the
 * tool never takes that lock and never writes there. It reads two small JSON
 * files of the copy:
 *   - `legacy-retire/ledger.json`: whether this device's import is done (the
 *     stored readbacks are ignored, so every readback is fresh);
 *   - `state.json`: `fullSince`, which the writer keeps (stream-sync/writer.ts,
 *     `WriterState.fullSince`) to prove a full run re-collected a stream.
 * A missing or unreadable file proves nothing, as it does for the server.
 */

import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { streamSyncHomeId } from "@opendatalabs/personal-server-ts-core/stream-sync";

export interface HomeState {
  readonly importComplete: boolean;
  readonly imported: Record<string, { streams: number; at: string }>;
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
    imported: (ledger.imported ?? {}) as HomeState["imported"],
    fullSince: (state.fullSince ?? {}) as HomeState["fullSince"],
  };
}
