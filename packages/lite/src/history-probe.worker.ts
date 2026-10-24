import { z } from "zod";
import { keccak256, stringToHex } from "viem";
import {
  DataFileEnvelopeSchema,
  deriveMasterKey,
  deriveScopeKey,
  recoverServerOwner,
} from "@opendatalabs/vana-sdk/browser";
import {
  AdditionsBudget,
  AdditionsBudgetExceeded,
} from "@opendatalabs/personal-server-ts-core/additions";
import { decryptBoundedAdditions } from "./additions-crypto.js";

const hexHash = z.string().regex(/^0x[0-9a-fA-F]{64}$/);
const inputSchema = z.object({
  ownerAddress: z.string().regex(/^0x[0-9a-fA-F]{40}$/),
  ownerSignature: z.string().regex(/^0x[0-9a-fA-F]{130}$/),
  storageEndpoint: z.string().url(),
  candidates: z
    .array(
      z.object({
        scope: z.string().regex(/^[a-zA-Z0-9._-]{1,256}$/),
        expectedVersion: z.string().regex(/^[1-9][0-9]{0,63}$/),
        dataHash: hexHash,
        metadataHash: hexHash,
      }),
    )
    .min(1)
    .max(12),
});
/** Read-only candidate verification for an explicit Moksha recovery investigation.
 * It never repairs objects or accepts uncommitted plaintext as history. */
export type OriginalHistoryProbeInput = z.input<typeof inputSchema>;
export type OriginalHistoryProbeCode =
  | "read_failed"
  | "not_found"
  | "decrypt_failed"
  | "data_hash_mismatch"
  | "metadata_hash_mismatch"
  | "invalid_envelope"
  | "exact_commitment_match"
  | "budget_exceeded";
export type OriginalHistoryProbeMessage =
  | {
      kind: "candidate";
      scope: string;
      version: string;
      namespace: "legacy" | "moksha";
      code: OriginalHistoryProbeCode;
      size?: number;
      ciphertextHash?: string;
    }
  | { kind: "complete"; inspected: number }
  | { kind: "refused"; code: "invalid_input_or_owner" };
const worker = globalThis as unknown as {
  onmessage: ((event: MessageEvent<unknown>) => void) | null;
  postMessage(value: OriginalHistoryProbeMessage): void;
};
worker.onmessage = async ({ data }) => {
  worker.onmessage = null;
  let master: Uint8Array | undefined;
  try {
    const input = inputSchema.parse(data);
    const endpoint = new URL(input.storageEndpoint);
    if (
      (endpoint.origin !== "https://storage-dev.vana.org" &&
        !(
          endpoint.protocol === "http:" && endpoint.hostname === "127.0.0.1"
        )) ||
      endpoint.pathname !== "/" ||
      endpoint.search ||
      endpoint.hash ||
      endpoint.username ||
      endpoint.password
    )
      throw new Error();
    const owner = input.ownerAddress.toLowerCase();
    if (
      (
        await recoverServerOwner(input.ownerSignature as `0x${string}`)
      ).toLowerCase() !== owner
    )
      throw new Error();
    master = deriveMasterKey(input.ownerSignature as `0x${string}`);
    const budget = new AdditionsBudget(32 * 1024 * 1024, 120_000);
    let inspected = 0;
    outer: for (const candidate of input.candidates) {
      for (const namespace of ["legacy", "moksha"] as const) {
        if (budget.signal?.aborted || budget.remaining <= 0) break;
        let exhausted = false;
        let code: OriginalHistoryProbeCode = "read_failed";
        let size: number | undefined;
        let ciphertextHash: string | undefined;
        const signal = AbortSignal.any([
          budget.signal!,
          AbortSignal.timeout(10_000),
        ]);
        try {
          budget.charge();
          const prefix =
            namespace === "legacy" ? "v1/blobs" : "v1/chains/14800/blobs";
          const response = await fetch(
            `${endpoint.origin}/${prefix}/${owner}/${candidate.scope}/${candidate.expectedVersion}`,
            {
              method: "GET",
              credentials: "omit",
              redirect: "error",
              cache: "no-store",
              signal,
            },
          );
          if (!response.ok)
            code = response.status === 404 ? "not_found" : "read_failed";
          else {
            const reader = response.body!.getReader();
            const chunks: Uint8Array[] = [];
            let length = 0;
            try {
              while (true) {
                const part = await reader.read();
                if (part.done) break;
                length += part.value.length;
                budget.charge(part.value.length * 2);
                if (length > 2 * 1024 * 1024) throw new Error();
                chunks.push(part.value);
              }
            } catch (error) {
              await reader.cancel();
              throw error;
            }
            const encrypted = new Uint8Array(length);
            let offset = 0;
            for (const chunk of chunks) {
              encrypted.set(chunk, offset);
              offset += chunk.length;
            }
            size = length;
            ciphertextHash = keccak256(encrypted);
            code = "decrypt_failed";
            const password = Array.from(
              deriveScopeKey(master, candidate.scope),
              (byte) => byte.toString(16).padStart(2, "0"),
            ).join("");
            const plaintext = await decryptBoundedAdditions(
              encrypted,
              password,
              budget,
            );
            budget.charge(plaintext.byteLength);
            if (
              keccak256(plaintext).toLowerCase() !==
              candidate.dataHash.toLowerCase()
            )
              code = "data_hash_mismatch";
            else {
              code = "invalid_envelope";
              budget.charge(plaintext.byteLength * 3);
              const envelope = DataFileEnvelopeSchema.parse(
                JSON.parse(new TextDecoder().decode(plaintext)),
              );
              const metadataHash = keccak256(
                stringToHex(
                  JSON.stringify({
                    scope: candidate.scope,
                    collectedAt: envelope.collectedAt,
                    sizeBytes: length,
                  }),
                ),
              );
              code =
                envelope.scope === candidate.scope &&
                Number.isFinite(Date.parse(envelope.collectedAt)) &&
                metadataHash.toLowerCase() ===
                  candidate.metadataHash.toLowerCase()
                  ? "exact_commitment_match"
                  : "metadata_hash_mismatch";
            }
          }
        } catch (error) {
          if (
            error instanceof AdditionsBudgetExceeded ||
            budget.signal?.aborted ||
            signal.aborted
          )
            code = "budget_exceeded";
          exhausted =
            error instanceof AdditionsBudgetExceeded ||
            Boolean(budget.signal?.aborted);
        }
        inspected++;
        worker.postMessage({
          kind: "candidate",
          scope: candidate.scope,
          version: candidate.expectedVersion,
          namespace,
          code,
          size,
          ciphertextHash,
        });
        if (exhausted) break outer;
      }
    }
    worker.postMessage({ kind: "complete", inspected });
  } catch {
    worker.postMessage({ kind: "refused", code: "invalid_input_or_owner" });
  } finally {
    master?.fill(0);
  }
};
