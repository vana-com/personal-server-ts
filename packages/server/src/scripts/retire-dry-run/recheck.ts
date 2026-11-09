/**
 * The last check before a real delete, made in the dry run without the delete.
 *
 * The retire pass hashes a file once more right before it erases it, and holds
 * the erase to that hash (`contentHash` in `storage/legacy-entity-key-sets`).
 * A dry run never reaches that step, so a file that changed after its readback
 * would still be reported as ready. This pass takes the same step for every
 * file the pass found ready: it reads the file again, hashes it with the same
 * function, and compares it with the hash its readback recorded. A file that
 * differs, cannot be read, or has no recorded hash is `file_changed`, as the
 * real pass decides. It only reads.
 */

import {
  fileHolds,
  type ReadbackRecord,
  type RetireDeps,
  type RetireFileReport,
  type RetireReport,
} from "@opendatalabs/personal-server-ts-core/sync";

/** `<id>|<path>|<collectedAt>` (`versionKey`): the time is after the last bar. */
const collectedAtOf = (version: string): string =>
  version.slice(version.lastIndexOf("|") + 1);

export async function recheckReadyFiles(input: {
  readonly retire: RetireReport;
  readonly records: ReadonlyMap<string, ReadbackRecord>;
  readonly storage: Pick<RetireDeps["storage"], "readEnvelope">;
}): Promise<RetireReport> {
  const files: RetireFileReport[] = [];
  for (const file of input.retire.files) {
    if (file.decision !== "ready") {
      files.push(file);
      continue;
    }
    const readHash = input.records.get(
      `${file.scope}|${file.version}`,
    )?.fileHash;
    const holds = await fileHolds(
      input.storage,
      file.scope,
      collectedAtOf(file.version),
      readHash,
    );
    files.push(
      holds ? file : { ...file, decision: "file_changed", wouldDelete: false },
    );
  }
  return { ...input.retire, files };
}
