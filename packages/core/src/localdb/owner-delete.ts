/**
 * Owner record delete on a switched (stream-sync) account, as a run
 * (spec-core §8 "Delete a record"; §9 RS item 1).
 *
 * A switched account's records come from connector runs and travel to the
 * owner's other devices through the connection log. A delete written only to
 * this database would be undone by the next sync. So the resource server
 * writes the delete the way a connector does: one run on the connection,
 * selecting only the record's stream, with one explicit delete row, ended
 * with connector end evidence. Run end removes the row (`deleteRunRecords`,
 * merge.ts) and stamps the removal with the run's observation time; the run's
 * commit schedules the publication that carries the tombstone to every device,
 * exactly as for a connector's own explicit delete.
 *
 * The run is not a full read of the stream (`resumed: true`), so it can never
 * replace the stream whole, and it saves no cursor (`checkpoints: {}`), so the
 * connector's own cursor stays as it was.
 */
import { controlScope } from "@opendatalabs/personal-server-ts-stream-sync";
import type { RunIntake } from "../stream-sync/intake.js";
import { RunIntakeError } from "../stream-sync/intake.js";
import type { RawEndV1 } from "../stream-sync/raw-end.js";
import type { ConnectionLink } from "./connection-link.js";
import { createLinkedRecordQuery } from "./connection-link.js";
import type { SqlReader } from "./driver.js";

export type OwnerRecordDeleteResult =
  | { readonly kind: "deleted"; readonly runId: string }
  | { readonly kind: "not_found" }
  | {
      readonly kind: "refused";
      /** A reason a client can read; no record data. */
      readonly reason: string;
      readonly retryable: boolean;
    };

export interface OwnerRecordDeleteInput {
  readonly instance: string;
  readonly stream: string;
  readonly recordKey: string;
}

export interface OwnerRecordDeleteDeps {
  readonly db: SqlReader;
  readonly intake: RunIntake;
  readonly ownerAddress: string;
  readonly newRunId: () => string;
  readonly now: () => number;
  /**
   * The digest of a connector artifact this host verified, for `connector`.
   * `version` is the artifact version the connection's runs last used, when
   * known, so the delete runs under the same declarations.
   */
  readonly artifactDigestFor: (
    connector: string,
    version: string | null,
  ) => string | undefined;
}

export function createOwnerRecordDelete(
  deps: OwnerRecordDeleteDeps,
  link: ConnectionLink,
) {
  const query = createLinkedRecordQuery(deps.db, link);
  return async (
    input: OwnerRecordDeleteInput,
  ): Promise<OwnerRecordDeleteResult> => {
    const target = link(input.instance, input.stream);
    if (!target) return { kind: "not_found" };
    const record = await query.getRecord({
      connectionId: input.instance,
      stream: input.stream,
      recordKey: input.recordKey,
    });
    if (!record) return { kind: "not_found" };
    // Runs name a connection by connector in the identity-less namespace
    // (run-intake.ts `controlScope(connector, "")`).
    if (target.namespace !== "")
      return {
        kind: "refused",
        reason: "This connection cannot be written by a run on this server",
        retryable: false,
      };
    // Either stream semantics: spec-core §4, `append_only`: "Explicit
    // deletion is permitted."
    const connectionId = controlScope(target.connector, "");
    const [last] = await deps.db.query<{ artifact_version: string }>(
      "SELECT artifact_version FROM runs WHERE connection_id=? ORDER BY o DESC LIMIT 1",
      [connectionId],
    );
    const artifactDigest = deps.artifactDigestFor(
      target.connector,
      last?.artifact_version ?? null,
    );
    if (!artifactDigest)
      return {
        kind: "refused",
        reason:
          "This server holds no verified connector artifact for this connection",
        retryable: false,
      };
    const runId = deps.newRunId();
    try {
      const begun = await deps.intake.begin(runId, {
        connector: target.connector,
        artifactDigest,
        owner: { address: deps.ownerAddress, leaseId: null },
        selectedStreams: [input.stream],
        streams: [{ name: input.stream, resumed: true }],
        observedAt: deps.now(),
      });
      if (begun.status !== "collecting") {
        if (begun.status === "will_discard")
          await deps.intake.abort(runId, "cancelled").catch(() => undefined);
        return {
          kind: "refused",
          reason:
            "The account registry could not be reached; the delete was not made",
          retryable: true,
        };
      }
      await deps.intake.batch(runId, {
        batch: 0,
        records: [
          {
            stream: input.stream,
            op: "delete",
            key: input.recordKey,
            data: JSON.parse(record.body),
          },
        ],
      });
      const end: RawEndV1 = {
        wireDialect: "connector-end-evidence/1",
        lastBatch: 0,
        selectedStreams: [input.stream],
        done: { status: "succeeded", recordsEmitted: 1 },
        errors: [],
        checkpoints: {},
        preflightExcludedStreams: [],
        detailCoverage: {},
        invalidDetailCoverageStreams: [],
        wholeStreamEvidence: [],
      };
      await deps.intake.end(runId, end);
    } catch (error) {
      if (error instanceof RunIntakeError)
        return {
          kind: "refused",
          reason: error.code,
          retryable: error.status === 503,
        };
      throw error;
    }
    // The run's end is the commit: the row must be gone now.
    const remains = await query.getRecord({
      connectionId: input.instance,
      stream: input.stream,
      recordKey: input.recordKey,
    });
    if (remains)
      return {
        kind: "refused",
        reason: "The delete run did not remove the record",
        retryable: false,
      };
    return { kind: "deleted", runId };
  };
}
