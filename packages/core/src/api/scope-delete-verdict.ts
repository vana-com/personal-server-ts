/**
 * Did a per-scope owner delete (`DELETE /v1/data/:scope`) finish?
 *
 * The route answers with a receipt of its three steps (gateway tombstone,
 * storage blobs, local copy). What the steps add up to is part of the receipt's
 * meaning, so it is decided here once; a host that reads the receipt itself
 * will drift (a phone that reads "local copy gone" as "deleted" reports done
 * while the tombstone never landed). Rust and Dart hosts run the same answers
 * from `contracts/scope-delete-receipt.json`.
 *
 * ```
 * status ok, receipt for this scope, durable
 *   gateway ok | skipped(not-registered)
 *   ├─ storage ok, no blobs pending, local ok ───────────► durably-deleted
 *   └─ storage deferred | failed (keys are re-queued),
 *      local ok ───────────────────────────────────────────► deleted-cleanup-pending
 * a receipt for this scope, anything else ───────────────► incomplete
 * no receipt, or a receipt for another scope ────────────► unconfirmed
 * ```
 */
import { z } from "zod";

const stepSchema = z.object({
  status: z.enum(["ok", "skipped", "failed", "deferred"]),
  reason: z.string().optional(),
  error: z.string().optional(),
});

const receiptSchema = z.object({
  scope: z.string(),
  dataPointId: z.string().nullable(),
  durable: z.boolean(),
  pendingBlobDeletion: z.boolean(),
  steps: z.object({
    gateway: stepSchema,
    storage: stepSchema.extend({ blobsPending: z.number().optional() }),
    local: stepSchema.extend({ deletedCount: z.number().optional() }),
  }),
});

/** An error answer attaches the receipt (`DELETE_TOMBSTONE_FAILED`). */
const attachedReceiptSchema = z.object({
  error: z.object({ details: z.object({ result: receiptSchema }) }),
});

export type ScopeDeletionReceipt = z.infer<typeof receiptSchema>;

export type ScopeDeletionStepName = keyof ScopeDeletionReceipt["steps"];

export type ScopeDeletionVerdict =
  /** Tombstoned, and every blob and the local copy are gone. */
  | { kind: "durably-deleted" }
  /**
   * Tombstoned and erased locally; only remote ciphertext cleanup is queued.
   * The Personal Server drains that queue on its own sync cycles.
   */
  | { kind: "deleted-cleanup-pending" }
  /**
   * The receipt is for this scope and the delete did not finish. Retry is safe.
   * `local-copy-only`: no gateway tombstone (`durable: false`), so sync can
   * bring the data back. `unfinished`: `steps` names those that failed or
   * deferred, and may be empty when no step names the cause.
   */
  | { kind: "incomplete"; reason: "local-copy-only" }
  | {
      kind: "incomplete";
      reason: "unfinished";
      steps: readonly ScopeDeletionStepName[];
    }
  /** No readable receipt for this scope: nothing is known about the delete. */
  | { kind: "unconfirmed" };

/**
 * @param status  the HTTP status of the delete answer.
 * @param receipt the answer's JSON body: the receipt itself, or an error
 *   answer that attaches it as `error.details.result`. Anything else (a
 *   non-JSON body, a refusal, another scope's receipt) is `unconfirmed`.
 * @param scope   the scope that was asked to be deleted.
 */
export function decideScopeDeletion({
  status,
  receipt: body,
  scope,
}: {
  status: number;
  receipt: unknown;
  scope: string;
}): ScopeDeletionVerdict {
  const direct = receiptSchema.safeParse(body);
  const attached = attachedReceiptSchema.safeParse(body);
  const receipt = direct.success
    ? direct.data
    : attached.success
      ? attached.data.error.details.result
      : null;
  if (!receipt || receipt.scope !== scope) return { kind: "unconfirmed" };

  const { gateway, storage, local } = receipt.steps;
  const gatewayComplete =
    gateway.status === "ok" ||
    (gateway.status === "skipped" && gateway.reason === "not-registered");
  const ok = status >= 200 && status < 300;
  if (
    ok &&
    receipt.durable &&
    gatewayComplete &&
    storage.status === "ok" &&
    local.status === "ok" &&
    !receipt.pendingBlobDeletion &&
    (storage.blobsPending ?? 0) === 0
  ) {
    return { kind: "durably-deleted" };
  }
  if (
    ok &&
    receipt.durable &&
    gatewayComplete &&
    // "failed" storage keys are re-queued by the Personal Server like
    // "deferred" ones; the scope is already tombstoned and erased locally.
    (storage.status === "deferred" || storage.status === "failed") &&
    local.status === "ok"
  ) {
    return { kind: "deleted-cleanup-pending" };
  }
  if (!receipt.durable)
    return { kind: "incomplete", reason: "local-copy-only" };
  return {
    kind: "incomplete",
    reason: "unfinished",
    steps: (["gateway", "storage", "local"] as const).filter((name) => {
      const step = receipt.steps[name].status;
      return step === "failed" || step === "deferred";
    }),
  };
}
