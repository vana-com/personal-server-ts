/**
 * Read-only dry run of the legacy retire on a COPY of a Personal Server data
 * folder. It deletes, imports and publishes nothing.
 *
 *   VANA_MASTER_KEY_SIGNATURE=0x… \
 *   node packages/server/dist/scripts/legacy-retire-dry-run.js \
 *     --data-dir ~/.tmp/ps-copy --out ~/.tmp/ps-copy-report.json
 *
 * Exit codes: 0 report written, 2 refused or aborted (see stderr).
 */

import { homedir } from "node:os";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { CopyOnlyError } from "./retire-dry-run/copy-only.js";
import { LegacyStoreError } from "./retire-dry-run/legacy-store.js";
import { NetworkGuardError } from "./retire-dry-run/network-guard.js";
import { runLegacyRetireDryRun } from "./retire-dry-run/run.js";
import { DryRunSetupError } from "./retire-dry-run/setup-error.js";

const USAGE =
  "Usage: legacy-retire-dry-run --data-dir <copy under ~/.tmp> --out <report.json> " +
  "[--gateway-url <url>] [--storage-url <url>]\n" +
  "The URLs may only select a pinned Dev host. Use cp -p so the report shows the copy's age.\n" +
  "Set VANA_MASTER_KEY_SIGNATURE in the environment.";

export async function main(argv: readonly string[]): Promise<number> {
  const { values } = parseArgs({
    args: [...argv],
    options: {
      "data-dir": { type: "string" },
      out: { type: "string" },
      "gateway-url": { type: "string" },
      "storage-url": { type: "string" },
      "test-only-allow-loopback": { type: "boolean" },
    },
    strict: true,
  });
  if (!values["data-dir"] || !values.out) {
    process.stderr.write(`${USAGE}\n`);
    return 2;
  }
  try {
    const report = await runLegacyRetireDryRun({
      dataDir: values["data-dir"],
      outPath: values.out,
      home: homedir(),
      masterKeySignature: process.env.VANA_MASTER_KEY_SIGNATURE,
      ...(values["gateway-url"] ? { gatewayUrl: values["gateway-url"] } : {}),
      ...(values["storage-url"] ? { storageUrl: values["storage-url"] } : {}),
      testOnlyAllowLoopback: values["test-only-allow-loopback"] === true,
      log: (line) => process.stderr.write(`${line}\n`),
    });
    process.stderr.write(
      `Report written to ${values.out}: ${report.totals.reported} files, ` +
        `${report.totals.wouldDelete} would be deleted (nothing was).\n`,
    );
    return 0;
  } catch (error) {
    process.stderr.write(`${messageFor(error)}\n`);
    return 2;
  }
}

/**
 * Fixed text only. A library error can quote an input (a signature, a path),
 * so an error this tool does not own is named by its class and nothing more.
 */
function messageFor(error: unknown): string {
  if (
    error instanceof CopyOnlyError ||
    error instanceof DryRunSetupError ||
    error instanceof LegacyStoreError
  ) {
    return `Refused: ${error.message.replace(/^Refusing: /, "")}`;
  }
  if (error instanceof NetworkGuardError) {
    return `Refused: the network guard stopped a request (${error.violation.reason}). A report with status "aborted" was written.`;
  }
  const name = error instanceof Error ? error.name : "unknown";
  return `Failed: ${/^[A-Za-z]{1,40}$/.test(name) ? name : "unknown"}. A report with status "aborted" was written when possible.`;
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  main(process.argv.slice(2)).then((code) => {
    process.exitCode = code;
  });
}
