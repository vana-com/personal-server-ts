// A fake registry gateway over `fetch`, for tests of the batch commit. It
// implements the wire contract of POST /v1/data/batch and of `requires` on
// POST /v1/data, in memory, so the real gateway adapter and the real publish
// driver run against it. Signatures are not checked.
import { computeDataPointId } from "@opendatalabs/personal-server-ts-core/sync";

type Version = { dataHash: string; metadataHash: string };

type BatchRow = {
  scope: string;
  expectedVersion: string;
  dataHash: string;
  metadataHash: string;
  expectedHeadDataHash?: string;
};

type Requirement = {
  scope: string;
  expectedVersion: string;
  notDeleted: boolean;
  expectedDataHash?: string;
};

type FailedRequirement = {
  scope: string;
  reason: "absent" | "deleted" | "version-mismatch" | "data-hash-mismatch";
  expectedVersion: string;
};

export type GatewayCall =
  | { readonly kind: "read"; readonly scope: string }
  | { readonly kind: "list" }
  | {
      readonly kind: "post";
      readonly scope: string;
      readonly body: Record<string, unknown>;
    }
  | {
      readonly kind: "batch";
      readonly body: {
        rows: BatchRow[];
        requires: Requirement[];
      };
      readonly raw: string;
    };

export interface FakeGatewayOptions {
  readonly owner: string;
  /** A row is a tombstone (its `deletedAt` is set) when this says so. */
  readonly isTombstone: (version: Version) => boolean;
  /** Status of the batch route: 404 or 405 stand for a gateway without it. */
  readonly batchRoute?: "present" | 404 | 405;
  /** How the gateway answers a batch row it already holds. */
  readonly replay?: "stale" | "created";
  /**
   * The body of a failed condition: the final contract's (with a reason), the
   * batch prototype's, the single write's, or none.
   */
  readonly failureBody?: "final" | "batch" | "single" | "none";
  /**
   * A row that names the head's own version overwrites the head, as the real
   * gateway refreshes a pending row, unless the row's head fence refuses it.
   */
  readonly refresh?: boolean;
}

export function createFakeGateway(options: FakeGatewayOptions) {
  const versions = new Map<string, Version[]>();
  const scopeOfId = new Map<string, string>();
  const calls: GatewayCall[] = [];
  const spurious = new Set<string>();
  const failFences = new Set<string>();
  const stickyFences = new Set<string>();
  let batchRoute = options.batchRoute;
  const gateway = {
    calls,
    versions,
    /** Runs in every batch request, before the gateway looks at it. */
    beforeBatch: undefined as
      | undefined
      | ((body: GatewayCall & { kind: "batch" }) => Promise<void> | void),
    /** The gateway applies the next batch, then the reply is lost. */
    dropNextBatchReply: false,
    /** The next batch answers this scope's row as a conflict without writing. */
    refuseOnce(scope: string) {
      spurious.add(scope);
    },
    /** The next batch that names this scope as a condition fails it (version-mismatch). */
    failFenceOnce(scope: string) {
      failFences.add(scope);
    },
    /** The gateway loses or gains the batch route (a rollback, a deploy). */
    setBatchRoute(route: "present" | 404 | 405) {
      batchRoute = route;
    },
    /** Every batch that names this scope as a condition fails it. */
    failFenceAlways(scope: string) {
      stickyFences.add(scope);
    },
    /** The head of a scope changes content without a new version (a refresh). */
    replaceHead(scope: string, version: Version) {
      const rows = versions.get(scope)!;
      rows[rows.length - 1] = version;
    },
    write(scope: string, version: Version) {
      const rows = versions.get(scope) ?? [];
      rows.push(version);
      versions.set(scope, rows);
      scopeOfId.set(computeDataPointId(options.owner, scope), scope);
    },
    rowsOf: (scope: string) => versions.get(scope)?.length ?? 0,
    batches: () =>
      calls.filter(
        (call): call is GatewayCall & { kind: "batch" } =>
          call.kind === "batch",
      ),
    fetch: (async (input: string, init?: RequestInit) => {
      const url = new URL(input);
      const method = init?.method ?? "GET";
      const json = (status: number, body: unknown) =>
        new Response(JSON.stringify(body), { status });
      const rowJson = (scope: string) => {
        const rows = versions.get(scope)!;
        const head = rows[rows.length - 1]!;
        return {
          scope,
          expectedVersion: String(rows.length),
          dataHash: head.dataHash,
          metadataHash: head.metadataHash,
          ...(options.isTombstone(head) && { deletedAt: "2026-01-01" }),
        };
      };
      const failure = (failed: FailedRequirement) => {
        const { scope, reason, expectedVersion } = failed;
        const rows = versions.get(scope);
        const deleted = rows
          ? options.isTombstone(rows[rows.length - 1]!)
          : false;
        const latest = rows ? String(rows.length) : null;
        if (options.failureBody === "none") return { success: false };
        if (options.failureBody === "batch") {
          return {
            success: false,
            requires: { ok: false, scope, version: latest, deleted },
          };
        }
        return {
          error: "precondition_failed",
          requires: {
            ...(options.failureBody !== "single" && { reason }),
            scope,
            expectedVersion,
            latestVersion: latest,
            deleted,
          },
        };
      };
      /** The first condition that fails, in request order, and why. */
      const requirementFails = (
        requires: Requirement[],
      ): FailedRequirement | undefined => {
        for (const req of requires) {
          const rows = versions.get(req.scope);
          const fail = (reason: FailedRequirement["reason"]) => ({
            scope: req.scope,
            reason,
            expectedVersion: req.expectedVersion,
          });
          if (failFences.delete(req.scope) || stickyFences.has(req.scope)) {
            return fail("version-mismatch");
          }
          if (!rows) return fail("absent");
          const head = rows[rows.length - 1]!;
          if (req.notDeleted && options.isTombstone(head)) {
            return fail("deleted");
          }
          if (String(rows.length) !== req.expectedVersion) {
            return fail("version-mismatch");
          }
          if (
            req.expectedDataHash !== undefined &&
            req.expectedDataHash.toLowerCase() !== head.dataHash.toLowerCase()
          ) {
            return fail("data-hash-mismatch");
          }
        }
        return undefined;
      };

      if (method === "GET" && url.pathname === "/v1/data") {
        calls.push({ kind: "list" });
        return json(200, {
          data: { dataPoints: [...versions.keys()].map(rowJson) },
          pagination: { hasMore: false, nextCursor: null },
        });
      }
      if (method === "GET") {
        const scope = scopeOfId.get(url.pathname.split("/").pop()!);
        calls.push({ kind: "read", scope: scope ?? url.pathname });
        return scope && versions.has(scope)
          ? json(200, rowJson(scope))
          : json(404, {});
      }
      const raw = String(init?.body);
      const body = JSON.parse(raw);

      if (url.pathname === "/v1/data") {
        calls.push({ kind: "post", scope: body.scope, body });
        const rows = versions.get(body.scope) ?? [];
        if (Array.isArray(body.requires)) {
          const bad = requirementFails(body.requires);
          if (bad) {
            return json(409, failure(bad));
          }
        }
        if (Number(body.expectedVersion) !== rows.length + 1) {
          return json(409, { latestVersion: String(rows.length) });
        }
        gateway.write(body.scope, {
          dataHash: body.dataHash,
          metadataHash: body.metadataHash,
        });
        return json(201, { success: true });
      }

      // POST /v1/data/batch
      const call = { kind: "batch" as const, body, raw };
      calls.push(call);
      if (batchRoute === 404 || batchRoute === 405) {
        return json(batchRoute, { error: "not here" });
      }
      await gateway.beforeBatch?.(call);
      // As the gateway: 1 to 16 rows, or none when `requires` names something.
      const hasRequires =
        Array.isArray(body.requires) && body.requires.length > 0;
      if (
        !Array.isArray(body.rows) ||
        (body.rows.length === 0 && !hasRequires)
      ) {
        return json(400, {
          success: false,
          error:
            "rows must be an array of 1 to 16 entries (0 when requires is not empty)",
        });
      }
      const bad = requirementFails(body.requires ?? []);
      if (bad) return json(409, failure(bad));
      const results = body.rows.map((row: BatchRow) => {
        const rows = versions.get(row.scope) ?? [];
        const head = rows[rows.length - 1];
        if (spurious.delete(row.scope)) {
          return {
            scope: row.scope,
            status: 409,
            reason: "stale",
            latestVersion: String(rows.length),
            latestDataHash: head?.dataHash ?? null,
          };
        }
        const isReplay =
          Number(row.expectedVersion) === rows.length &&
          head?.dataHash === row.dataHash;
        if (isReplay && options.replay === "created") {
          return {
            scope: row.scope,
            status: 201,
            version: row.expectedVersion,
          };
        }
        const fence = row.expectedHeadDataHash;
        if (
          !isReplay &&
          fence !== undefined &&
          (head === undefined ||
            head.dataHash.toLowerCase() !== fence.toLowerCase())
        ) {
          return {
            scope: row.scope,
            status: 409,
            reason: "head-mismatch",
            latestVersion: String(rows.length),
            latestDataHash: head?.dataHash ?? null,
          };
        }
        if (Number(row.expectedVersion) === rows.length + 1) {
          gateway.write(row.scope, {
            dataHash: row.dataHash,
            metadataHash: row.metadataHash,
          });
          return {
            scope: row.scope,
            status: 201,
            version: row.expectedVersion,
          };
        }
        if (
          options.refresh &&
          !isReplay &&
          Number(row.expectedVersion) === rows.length
        ) {
          gateway.replaceHead(row.scope, {
            dataHash: row.dataHash,
            metadataHash: row.metadataHash,
          });
          return {
            scope: row.scope,
            status: 201,
            version: row.expectedVersion,
          };
        }
        return {
          scope: row.scope,
          status: 409,
          reason:
            Number(row.expectedVersion) > rows.length + 1 ? "gap" : "stale",
          latestVersion: String(rows.length),
          latestDataHash: head?.dataHash ?? null,
        };
      });
      if (gateway.dropNextBatchReply) {
        gateway.dropNextBatchReply = false;
        throw new TypeError("fetch failed");
      }
      return json(200, { success: true, results, requires: { ok: true } });
    }) as unknown as typeof fetch,
  };
  return gateway;
}
