import { GatewayRefusalError } from "../sync/delete-data-port.js";
import { isGatewayRefusalCode } from "../sync/gateway-refusal.js";
import type { IndexEntry } from "../storage/index/index.js";
import type { LegacyHead } from "./legacy-delete.js";
import type { LegacyRetirerDeps } from "./legacy-retire-intent.js";
import {
  blocked,
  PART_DONE,
  PART_PENDING,
  type DeletePart,
} from "./delete-status.js";
import type { LogVersionLister } from "./log-erase.js";
import type { TombstoneFinalityPort } from "../ports/index.js";

/** Throws synchronously when the caller no longer owns write authority. */
export type RetirementAuthority = () => void;
export interface RetirementRows {
  /** Take a detached snapshot under the index writer lock, then save it. */
  capture<T>(
    save: (rows: readonly IndexEntry[]) => Promise<T>,
    authority: RetirementAuthority,
  ): Promise<T>;
  erase(row: IndexEntry, authority: RetirementAuthority): Promise<void>;
  absent(
    rows: readonly IndexEntry[],
    authority: RetirementAuthority,
  ): Promise<boolean>;
}
export interface LegacyRetirePipelinePorts {
  mode(): string;
  scopesOf(connector: string): readonly string[];
  streamsOf(connector: string, scope: string): readonly string[];
  head(scope: string, signal?: AbortSignal): Promise<LegacyHead>;
  tombstone(
    scope: string,
    head: Extract<LegacyHead, { state: "live" }>,
    authority: RetirementAuthority,
    signal?: AbortSignal,
  ): Promise<void>;
  eraseBlob(
    scope: string,
    version: string,
    authority: RetirementAuthority,
    signal?: AbortSignal,
  ): Promise<boolean>;
  finality: Pick<TombstoneFinalityPort, "tombstoneState">;
  versions: LogVersionLister;
  rows: RetirementRows;
}
interface Scope {
  scope: string;
  head: LegacyHead;
  streams: readonly string[];
  rows: readonly IndexEntry[];
}
interface Manifest {
  scopes: readonly Scope[];
}
const versionOf = (head: LegacyHead): bigint | null =>
  head.state === "absent"
    ? null
    : BigInt(head.state === "live" ? head.fence.expectedVersion : head.version);
export function capturedAtPin(row: IndexEntry, head: LegacyHead): boolean {
  const pin = versionOf(head);
  const tombstone =
    pin === null ? null : pin + (head.state === "live" ? 1n : 0n);
  return (
    (pin === null || BigInt(row.version) <= pin) &&
    (row.afterTombstoneVersion == null ||
      (tombstone !== null && BigInt(row.afterTombstoneVersion) < tombstone))
  );
}
function sameHead(a: LegacyHead, b: LegacyHead): boolean {
  if (a.state !== b.state) return false;
  if (a.state === "absent") return true;
  if (a.state === "deleted")
    return b.state === "deleted" && a.version === b.version;
  return (
    b.state === "live" &&
    a.fence.expectedVersion === b.fence.expectedVersion &&
    a.fence.dataHash.toLowerCase() === b.fence.dataHash.toLowerCase() &&
    a.fence.metadataHash.toLowerCase() === b.fence.metadataHash.toLowerCase()
  );
}
export function createLegacyRetirePipeline(
  deps: LegacyRetirerDeps,
  ports: LegacyRetirePipelinePorts,
) {
  const owner = deps.ownerAddress.toLowerCase();
  const existing = async (connector: string) =>
    (
      await deps.db.query<{ retire_id: string }>(
        "SELECT retire_id FROM legacy_retirements WHERE owner = ? AND connector = ?",
        [owner, connector],
      )
    )[0];
  return {
    async capture(
      connector: string,
      authority: RetirementAuthority,
    ): Promise<string> {
      const old = await existing(connector);
      if (old) return old.retire_id;
      const scopes: Scope[] = [];
      for (const scope of ports.scopesOf(connector)) {
        authority();
        if (scope.startsWith("vana.system."))
          throw new Error("reserved legacy scope");
        scopes.push({
          scope,
          head: await ports.head(scope),
          streams: [...ports.streamsOf(connector, scope)],
          rows: [],
        });
      }
      return ports.rows.capture(async (rows) => {
        authority();
        const manifest: Manifest = {
          scopes: scopes.map((scope) => ({
            ...scope,
            rows: rows.filter(
              (row) =>
                row.scope === scope.scope && capturedAtPin(row, scope.head),
            ),
          })),
        };
        const id = deps.newOp();
        authority();
        await deps.db.batch([
          {
            sql: "INSERT OR IGNORE INTO legacy_retirements (owner, connector, retire_id, state, scopes, created_at) VALUES (?, ?, ?, 'open', ?, ?)",
            params: [
              owner,
              connector,
              id,
              JSON.stringify(
                manifest.scopes.map(({ scope, head, streams }) => ({
                  scope,
                  head,
                  streams,
                })),
              ),
              deps.now(),
            ],
          },
          {
            sql: "INSERT OR IGNORE INTO legacy_retire_manifests (retire_id, manifest) SELECT ?, ? WHERE EXISTS (SELECT 1 FROM legacy_retirements WHERE retire_id = ?)",
            params: [id, JSON.stringify(manifest), id],
          },
        ]);
        return (await existing(connector))!.retire_id;
      }, authority);
    },
    async advance(
      retireId: string,
      authority: RetirementAuthority,
      signal: AbortSignal,
    ): Promise<DeletePart> {
      const check = () => {
        signal.throwIfAborted();
        authority();
      };
      const [stored] = await deps.db.query<{ manifest: string }>(
        "SELECT manifest FROM legacy_retire_manifests WHERE retire_id = ?",
        [retireId],
      );
      if (!stored) return blocked("legacy_manifest_missing");
      const manifest = JSON.parse(stored.manifest) as Manifest;
      const receipts = new Set(
        (
          await deps.db.query<{ scope: string; version: string }>(
            "SELECT scope, version FROM legacy_retire_receipts WHERE retire_id = ?",
            [retireId],
          )
        ).map((r) => `${r.scope}@${r.version}`),
      );
      const requiredReceipts = new Set<string>();
      for (const scope of manifest.scopes) {
        check();
        const pin = versionOf(scope.head);
        const tombstone =
          pin === null
            ? null
            : String(pin + (scope.head.state === "live" ? 1n : 0n));
        const matches = (head: LegacyHead) =>
          tombstone === null
            ? head.state === "absent"
            : head.state === "deleted" && head.version === tombstone;
        let head = await ports.head(scope.scope, signal);
        if (
          scope.head.state === "live" &&
          head.state === "live" &&
          sameHead(head, scope.head)
        ) {
          check();
          try {
            await ports.tombstone(scope.scope, scope.head, check, signal);
          } catch (error) {
            check();
            if (
              error instanceof GatewayRefusalError &&
              isGatewayRefusalCode(error.code)
            )
              return blocked(error.code);
            const current = await ports.head(scope.scope, signal);
            if (!matches(current) && !sameHead(current, scope.head))
              return blocked("legacy_head_changed");
            throw error;
          }
          check();
          head = await ports.head(scope.scope, signal);
        }
        if (!matches(head)) return blocked("legacy_head_changed");
      }
      for (const scope of manifest.scopes) {
        check();
        const pin = versionOf(scope.head);
        const tombstone =
          pin === null
            ? null
            : String(pin + (scope.head.state === "live" ? 1n : 0n));
        const matches = (head: LegacyHead) =>
          tombstone === null
            ? head.state === "absent"
            : head.state === "deleted" && head.version === tombstone;
        if (!matches(await ports.head(scope.scope, signal)))
          return blocked("legacy_head_changed");
        if (tombstone !== null) {
          check();
          const final = await ports.finality.tombstoneState(
            scope.scope,
            tombstone,
          );
          if (final.finalized !== tombstone || final.rolledBack)
            return PART_PENDING;
          check();
          const history = await ports.versions.list(scope.scope, { signal });
          if (
            !history.complete ||
            !history.versions.some(
              (v) => v.isTombstone && v.expectedVersion === tombstone,
            )
          )
            return PART_PENDING;
          for (const blob of history.versions.filter(
            (v) => !v.isTombstone && BigInt(v.expectedVersion) <= pin!,
          )) {
            check();
            const key = `${scope.scope}@${blob.expectedVersion}`;
            requiredReceipts.add(key);
            if (receipts.has(key)) continue;
            if (!matches(await ports.head(scope.scope, signal)))
              return blocked("legacy_head_changed");
            check();
            if (
              !(await ports.eraseBlob(
                scope.scope,
                blob.expectedVersion,
                check,
                signal,
              ))
            )
              return PART_PENDING;
            check();
            await deps.db.batch([
              {
                sql: "INSERT OR IGNORE INTO legacy_retire_receipts (retire_id, scope, version) VALUES (?, ?, ?)",
                params: [retireId, scope.scope, blob.expectedVersion],
              },
            ]);
            receipts.add(key);
          }
        }
      }
      // Remote completion for the whole manifest precedes any local erase.
      for (const scope of manifest.scopes) {
        check();
        const pin = versionOf(scope.head);
        const head = await ports.head(scope.scope, signal);
        if (
          pin === null
            ? head.state !== "absent"
            : head.state !== "deleted" ||
              BigInt(head.version) !==
                pin + (scope.head.state === "live" ? 1n : 0n)
        )
          return blocked("legacy_head_changed");
        for (const row of scope.rows) {
          check();
          await ports.rows.erase(row, check);
        }
        check();
        if (!(await ports.rows.absent(scope.rows, check))) return PART_PENDING;
      }
      check();
      const durableReceipts = new Set(
        (
          await deps.db.query<{ scope: string; version: string }>(
            "SELECT scope, version FROM legacy_retire_receipts WHERE retire_id = ?",
            [retireId],
          )
        ).map((row) => `${row.scope}@${row.version}`),
      );
      if ([...requiredReceipts].some((key) => !durableReceipts.has(key)))
        return PART_PENDING;
      // Recheck every captured identity and head after the last scope, too.
      for (const scope of manifest.scopes) {
        check();
        if (!(await ports.rows.absent(scope.rows, check))) return PART_PENDING;
        check();
        const head = await ports.head(scope.scope, signal);
        const pin = versionOf(scope.head);
        if (
          pin === null
            ? head.state !== "absent"
            : head.state !== "deleted" ||
              BigInt(head.version) !==
                pin + (scope.head.state === "live" ? 1n : 0n)
        )
          return blocked("legacy_head_changed");
      }
      check();
      await deps.db.batch([
        {
          sql: "UPDATE legacy_retirements SET state = 'done' WHERE owner = ? AND retire_id = ?",
          params: [owner, retireId],
        },
      ]);
      return PART_DONE;
    },
  };
}
