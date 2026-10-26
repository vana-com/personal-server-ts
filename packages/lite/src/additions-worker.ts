import {
  AdditionsBudgetExceeded,
  createDurableAdditions,
  createVersionInventoryClient,
  type ByteBudget,
} from "@opendatalabs/personal-server-ts-core/additions";
import {
  createDataFileEnvelope,
  DataFileEnvelopeSchema,
  deriveScopeKey,
  encryptWithPassword,
} from "@opendatalabs/vana-sdk/browser";
import { NeedsFencedPublicationError } from "@opendatalabs/personal-server-ts-core/publication";
import { keccak256, stringToHex } from "viem";
import { decryptBoundedAdditions } from "./additions-crypto.js";
import { additionsTransfers } from "./additions-protocol.js";
import type {
  AdditionsWorkerInit,
  HostMessage,
  HostMethod,
  WorkerMessage,
} from "./additions-protocol.js";
import type { PsLiteAdditionsTransport } from "./additions-transport.js";

const worker = globalThis as unknown as {
  postMessage(message: HostMessage, transfer?: Transferable[]): void;
  onmessage: ((event: MessageEvent<WorkerMessage>) => void) | null;
};
let sequence = 0;
const pending = new Map<
  number,
  {
    resolve(value: unknown): void;
    reject(error: Error): void;
    budget?: ByteBudget;
  }
>();
function rpc(
  method: HostMethod,
  args: unknown[],
  budget?: ByteBudget,
): Promise<unknown> {
  budget?.charge();
  return new Promise((resolve, reject) => {
    const id = ++sequence;
    pending.set(id, { resolve, reject, budget });
    worker.postMessage(
      {
        kind: "request",
        id,
        method,
        args,
        remaining: budget?.remaining ?? 0,
        remainingMilliseconds: budget?.remainingMilliseconds,
      },
      additionsTransfers(args),
    );
  });
}
function hex(bytes: Uint8Array) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}
function createService(init: AdditionsWorkerInit) {
  // Responses are trusted messages from our own host module; all network JSON is
  // still decoded and schema-validated by the inventory client in this worker.
  const transport = async <K extends HostMethod>(
    method: K,
    args: unknown[],
    budget?: ByteBudget,
  ): Promise<Awaited<ReturnType<PsLiteAdditionsTransport[K]>>> =>
    (await rpc(method, args, budget)) as Awaited<
      ReturnType<PsLiteAdditionsTransport[K]>
    >;
  let activeBudget: ByteBudget | undefined;
  const inventory = createVersionInventoryClient({
    gatewayUrl: init.gatewayUrl,
    ownerAddress: init.ownerAddress,
    ownerSigner: {
      signRequest: (params) => transport("signRequest", [params], activeBudget),
    },
    boundedOwnerSigner: (params) =>
      transport("signRequest", [params], activeBudget),
    fetch: async (input, request) => {
      const url =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.href
            : input.url;
      const response = await transport(
        "fetch",
        [
          {
            url,
            method: request?.method,
            headers: [...new Headers(request?.headers)],
          },
        ],
        activeBudget,
      );
      return new Response(new Uint8Array(response.body), {
        status: response.status,
        headers: response.headers,
      });
    },
  });
  const reconciledScopes = new Set<string>();
  async function reconcilePending(scope: string, budget: ByteBudget) {
    if (reconciledScopes.has(scope)) return null;
    const pending = await transport("readPending", [scope], budget);
    if (!pending) {
      reconciledScopes.add(scope);
      return null;
    }
    let prior = pending;
    let snapshot = await inventory.list(scope, {
      budget,
      signal: budget.signal,
    });

    let slot = snapshot.versions.find(
      (row) => row.expectedVersion === prior.expectedVersion,
    );
    const replaced =
      slot &&
      (slot.dataHash !== prior.dataHash ||
        slot.metadataHash !== prior.metadataHash);
    if (slot && replaced && !["confirmed", "finalized"].includes(slot.status))
      throw new Error("Pending checkpoint replacement is not settled");
    if (!slot) {
      // The owner retries the exact bytes and resolves the current registry head.
      const published = await transport("publish", [prior], budget);
      prior = { ...prior, expectedVersion: published.expectedVersion };
      snapshot = await inventory.list(scope, {
        budget,
        signal: budget.signal,
      });
      slot = snapshot.versions.find(
        (row) => row.expectedVersion === prior.expectedVersion,
      );
    }
    if (
      !slot ||
      (!replaced &&
        (slot.dataHash !== prior.dataHash ||
          slot.metadataHash !== prior.metadataHash))
    )
      throw new Error("Interrupted checkpoint registration remains ambiguous");
    const proof = replaced ? slot : prior;
    let data: unknown;
    // The inventory parser verifies canonical tombstone hashes. A settled
    // deletion has no ciphertext; its second observation below is the proof.
    if (!replaced || !slot.isTombstone) {
      const ciphertext = await transport(
        "download",
        [`${scope}/${proof.expectedVersion}`],
        budget,
      );
      const plaintext = await decryptBoundedAdditions(
        ciphertext,
        hex(deriveScopeKey(init.masterKey, scope)),
        budget,
      );
      budget.charge(plaintext.byteLength * 4);
      const envelope = DataFileEnvelopeSchema.parse(
        JSON.parse(new TextDecoder().decode(plaintext)),
      );
      const metadataHash = keccak256(
        stringToHex(
          JSON.stringify({
            scope,
            collectedAt: envelope.collectedAt,
            sizeBytes: ciphertext.byteLength,
          }),
        ),
      );
      if (
        envelope.scope !== scope ||
        keccak256(plaintext) !== proof.dataHash ||
        metadataHash !== proof.metadataHash
      )
        throw new Error("Interrupted checkpoint commitment mismatch");
      data = envelope.data;
    }
    if (replaced) {
      // Other devices do not share our Web Lock. Authenticate their settled
      // winning bytes and recheck the slot before retiring this local intent.
      const latest = await inventory.list(scope, {
        budget,
        signal: budget.signal,
      });
      if (
        !latest.versions.some(
          (row) =>
            row.expectedVersion === proof.expectedVersion &&
            row.dataHash === proof.dataHash &&
            row.metadataHash === proof.metadataHash &&
            ["confirmed", "finalized"].includes(row.status),
        )
      )
        throw new Error(
          "Pending checkpoint replacement changed during verification",
        );
    }
    await transport("clearPending", [scope], budget);
    reconciledScopes.add(scope);
    return replaced ? null : { proof: prior, data };
  }
  // Budget objects never cross structured clone; each RPC receives the current
  // remaining allowance and the host's session-wide cancellation signal.
  const boundedInventory: typeof inventory = {
    page: async (scope, options) => {
      activeBudget = options?.budget;
      return inventory.page(scope, options);
    },
    list: async (scope, options) => {
      activeBudget = options?.budget;
      if (scope.startsWith("vana.system.") && options?.budget)
        await reconcilePending(scope, options.budget);
      return inventory.list(scope, options);
    },
    listScopes: async (options) => {
      activeBudget = options?.budget;
      return inventory.listScopes(options);
    },
  };
  return createDurableAdditions({
    ...init,
    inventory: boundedInventory,
    storageAdapter: {
      urlForKey: (key) => key,
      download: async () => {
        throw new Error("Unbounded download unavailable");
      },
      downloadBounded: async (key, budget) => {
        const bytes = await transport("download", [key], budget);
        budget.charge(bytes.byteLength * 2);
        return bytes;
      },
      upload: async () => {
        throw new Error("Unbounded upload unavailable");
      },
      delete: async () => false,
      exists: async () => false,
    },
    signer: {
      signAddData: async () => {
        throw new Error("Unbounded signing unavailable");
      },
    },
    gateway: {
      registerDataPoint: async () => {
        throw new Error("Unbounded publication unavailable");
      },
    },
    boundedWork: {
      async confirmed(scope, budget) {
        await transport("clearPending", [scope], budget);
      },
      decrypt: decryptBoundedAdditions,
      async publish(scope, data, budget) {
        activeBudget = budget;
        const prior = await reconcilePending(scope, budget);
        if (prior && JSON.stringify(prior.data) === JSON.stringify(data))
          return prior.proof;
        const snapshot = await inventory.list(scope, {
          budget,
          signal: budget.signal,
        });
        const expectedVersion = String(
          BigInt(snapshot.versions.at(-1)?.expectedVersion ?? "0") + 1n,
        );
        const envelope = createDataFileEnvelope(
          scope,
          new Date().toISOString(),
          data,
        );
        const plaintext = new TextEncoder().encode(JSON.stringify(envelope));
        budget.charge(plaintext.byteLength * 8);
        const encrypted = await encryptWithPassword(
          plaintext,
          hex(deriveScopeKey(init.masterKey, scope)),
        );
        budget.charge(encrypted.byteLength * 2);
        const prepared = {
          scope,
          expectedVersion,
          encrypted,
          dataHash: keccak256(plaintext),
          metadataHash: keccak256(
            stringToHex(
              JSON.stringify({
                scope,
                collectedAt: envelope.collectedAt,
                sizeBytes: encrypted.byteLength,
              }),
            ),
          ),
        };
        return transport("publish", [prepared], budget);
      },
    },
  });
}
worker.onmessage = (event) => {
  const message = event.data;
  if (message.kind === "response") {
    const request = pending.get(message.id);
    pending.delete(message.id);
    try {
      request?.budget?.recordSpent(message.spent);
      request?.budget?.charge();
      if (message.error)
        request?.reject(
          message.budgetExceeded
            ? new AdditionsBudgetExceeded(message.error)
            : message.publicationBlocked
              ? new NeedsFencedPublicationError(
                  message.publicationBlocked.scope,
                  message.publicationBlocked.reason,
                  false,
                )
              : new Error(message.error),
        );
      else request?.resolve(message.result);
    } catch (error) {
      const failure = error instanceof Error ? error : new Error(String(error));
      request?.reject(
        message.budgetExceeded || request?.budget?.signal?.aborted
          ? new AdditionsBudgetExceeded(failure.message)
          : failure,
      );
    }
    return;
  }
  void (async () => {
    try {
      const service = createService(message.init);
      const operation = message.operation;
      let result: unknown;
      switch (operation.method) {
        case "summarize":
          result = await service.summarize(...operation.args);
          break;
        case "recordUpload":
          result = await service.recordUpload({ scope: operation.scope });
          break;
      }
      worker.postMessage({ kind: "result", result });
    } catch (error) {
      worker.postMessage({
        kind: "error",
        error: error instanceof Error ? error.message : String(error),
      });
    }
  })();
};
