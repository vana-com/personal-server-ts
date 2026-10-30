import type {
  DurableAdditionsService,
  AdditionsRecoveryDiagnostic,
} from "@opendatalabs/personal-server-ts-core/additions";
import type { PsLiteAdditionsTransport } from "./additions-transport.js";

export interface AdditionsWorkerInit {
  ownerAddress: string;
  network: string;
  gatewayUrl: string;
  storageEndpoint: string;
  masterKey: Uint8Array;
  byteBudget: number;
  timeBudgetMs: number;
  diagnostics?: boolean;
}
export type AdditionsOperation =
  | {
      method: "summarize";
      args: Parameters<DurableAdditionsService["summarize"]>;
    }
  | { method: "recordUpload"; scope: string };
export type HostMethod = Exclude<keyof PsLiteAdditionsTransport, "openSession">;
export type WorkerMessage =
  | { kind: "run"; init: AdditionsWorkerInit; operation: AdditionsOperation }
  | {
      kind: "response";
      id: number;
      result?: unknown;
      error?: string;
      spent: number;
      budgetExceeded?: boolean;
      publicationBlocked?: { scope: string; reason: string };
    };
export type HostMessage =
  | {
      kind: "request";
      id: number;
      method: HostMethod;
      args: unknown[];
      remaining: number;
      remainingMilliseconds?: number;
    }
  | { kind: "diagnostic"; event: AdditionsRecoveryDiagnostic }
  | { kind: "result"; result: unknown }
  | { kind: "error"; error: string };

/** Transfer binary payloads across the dedicated worker channel without cloning. */
export function additionsTransfers(value: unknown): Transferable[] {
  const buffers = new Set<ArrayBuffer>();
  function visit(item: unknown): void {
    if (item instanceof Uint8Array && item.buffer instanceof ArrayBuffer)
      buffers.add(item.buffer);
    else if (item instanceof ArrayBuffer) buffers.add(item);
    else if (Array.isArray(item)) item.forEach(visit);
    else if (item && typeof item === "object")
      Object.values(item).forEach(visit);
  }
  visit(value);
  return [...buffers];
}
