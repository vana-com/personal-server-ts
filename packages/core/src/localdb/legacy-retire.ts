import type { LocalSyncDeps } from "./deps.js";
import { createImportLedger } from "./import-ledger.js";
import type {
  ImportReadback,
  LegacyCopy,
  LegacyRetireFileReport,
  LegacyRetireReport,
} from "./legacy-import-types.js";

/** Host capability comes only from switched-owner legacy-access. */
export interface LegacyRetireAccess {
  copies(): AsyncIterable<LegacyCopy>;
  /** Diagnostic only: the database is authoritative after the one-time seed. */
  readBack(copy: LegacyCopy): Promise<readonly ImportReadback[]>;
  /** Compare id/path/hash under the existing storage lock before unlink. */
  erase(copy: LegacyCopy): Promise<boolean>;
  /** Exact absence plus the durable intent for this id/path/hash. */
  erasedWithIntent?(copy: LegacyCopy): Promise<boolean>;
  finishErase?(copy: LegacyCopy): Promise<void>;
}

export interface LegacyRetireOptions {
  readonly streamSync?: { readonly retireLegacy?: boolean };
  readonly dryRun?: boolean;
  readonly reportFile: (report: LegacyRetireFileReport) => void;
}

/** Full replacement: unsupported sources and read-back bugs are reported, never
 * retention gates. Removal is opt-in; only the host's exact-copy fence can
 * authorize an unlink. Never create or reconnect a database connection here. */
export async function retireLegacyCopies(
  deps: LocalSyncDeps,
  access: LegacyRetireAccess,
  options: LegacyRetireOptions,
): Promise<LegacyRetireReport> {
  const mode =
    options.dryRun === true
      ? "dry-run"
      : options.streamSync?.retireLegacy === true
        ? "delete"
        : "readback-only";
  let files = 0,
    ready = 0,
    deleted = 0,
    unimported = 0,
    readbackFailures = 0,
    missing = 0;
  const ledger = createImportLedger(deps.db);
  for await (const candidate of access.copies()) {
    const copy: LegacyCopy = Object.freeze({
      ...candidate,
      sources: Object.freeze(
        candidate.sources.map((s) => Object.freeze({ ...s })),
      ),
    });
    files++;
    const report = (
      decision: LegacyRetireFileReport["decision"],
      reason: string | null,
    ) => options.reportFile({ file: copy.id, decision, reason });
    if (!copy.sources.length) unimported++;
    if (!copy.id || !copy.path || !copy.contentHash) {
      // Absence without intent is not evidence of a successful erase. Nothing
      // exists to retain; report it without inventing a receipt or intent.
      missing++;
      report("skipped", "missing-copy-proof");
      continue;
    }
    let diagnostic: string | null = copy.sources.length
      ? null
      : "unimported-copy";
    const connections = [
      ...new Set(copy.sources.map((s) => s.connectionId)),
    ].sort();
    const locked = async (index: number): Promise<void> => {
      if (index < connections.length)
        return deps.queue.run(connections[index]!, "end", () =>
          locked(index + 1),
        );
      const reconciled =
        mode === "delete" && (await access.erasedWithIntent?.(copy));
      if (!reconciled && copy.sources.length) {
        try {
          const proofs = await access.readBack(copy);
          for (const proof of proofs.filter((p) => !p.pass)) {
            readbackFailures++;
            diagnostic = proof.reason ?? "readback-failed";
            deps.logger.warn(
              { file: copy.id, reason: diagnostic },
              "Legacy import read-back failed",
            );
          }
          if (proofs.length < copy.sources.length) {
            readbackFailures += copy.sources.length - proofs.length;
            diagnostic = "missing-import-proof";
          }
        } catch {
          readbackFailures++;
          diagnostic = "readback-unavailable";
        }
      }
      ready++;
      if (mode !== "delete") {
        report("ready", diagnostic);
        return;
      }
      if (!reconciled && !(await access.erase(copy))) {
        ready--;
        report("changed", "copy-changed-or-absent");
        return;
      }
      // Journaled absence is sufficient even when import was unsupported or a
      // receipt is missing. Existing receipts may be retired; never synthesize.
      const statements = [];
      for (const source of copy.sources) {
        const receipt = await ledger.get(
          source.source,
          source.connectionId,
          source.stream,
        );
        if (receipt)
          statements.push(
            ...ledger.statements({
              ...receipt,
              state: "retired",
              at: deps.now(),
            }),
          );
      }
      if (statements.length) await deps.db.batch(statements);
      await access.finishErase?.(copy);
      if (!reconciled) deleted++;
      report("retired", reconciled ? "erase-reconciled" : diagnostic);
    };
    await locked(0);
  }
  return { mode, files, ready, deleted, unimported, readbackFailures, missing };
}
