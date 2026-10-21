import {
  CreateOnlyUnavailableError,
  type StorageAdapter,
} from "./interface.js";
import { AdditionsBudget, readBoundedJson } from "../../additions/budget.js";

/** This advertisement is a storage contract, not an inference from a PUT receipt. */
export function supportsWriteOnce(value: unknown): boolean {
  if (!value || typeof value !== "object" || !("blobs" in value)) return false;
  const blobs = value.blobs;
  return (
    !!blobs &&
    typeof blobs === "object" &&
    "writeOnce" in blobs &&
    blobs.writeOnce === true
  );
}

/** Never test immutability by overwriting a real key. Old storage fails before PUT. */
export function withCreateOnlyUploads(
  adapter: StorageAdapter,
  endpoint: string,
): StorageAdapter {
  let supported = false;
  return {
    ...adapter,
    async uploadCreateOnly(key, bytes) {
      if (!supported) {
        try {
          const budget = new AdditionsBudget(16 * 1024, 5000);
          const response = await fetch(`${endpoint}/v1/capabilities`, {
            redirect: "error",
            cache: "no-store",
            signal: budget.signal,
          });
          if (!response.ok) {
            await response.body?.cancel();
            throw new CreateOnlyUnavailableError();
          }
          if (!supportsWriteOnce(await readBoundedJson(response, budget)))
            throw new CreateOnlyUnavailableError();
          supported = true;
        } catch {
          throw new CreateOnlyUnavailableError();
        }
      }
      return adapter.upload(key, bytes);
    },
  };
}
