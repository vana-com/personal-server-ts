import type { GatewayClient } from "@opendatalabs/vana-sdk/browser";

type RegisterParams = Parameters<GatewayClient["registerDataPoint"]>[0];
type RegisterResult = Awaited<ReturnType<GatewayClient["registerDataPoint"]>>;

/** What the upload path asks of the registry write: the SDK call plus a signal. */
export type CancellableRegistration = {
  registerDataPoint(
    params: RegisterParams,
    options?: { signal?: AbortSignal },
  ): Promise<RegisterResult>;
};

/**
 * The SDK gateway client sends `registerDataPoint` through the global `fetch`
 * and takes no signal, so a deadline cannot close a hung registry write.
 * This sends the same request (same body, same `Gateway error: <status>
 * <detail>` failure text that stale-version recovery parses) with the caller's
 * signal. Without a signal it defers to the SDK call unchanged.
 */
export function withCancellableRegistration<T extends GatewayClient>(
  client: T,
  gatewayUrl: string,
  fetchImpl: typeof fetch = (input, init) => fetch(input, init),
): T & CancellableRegistration {
  const base = gatewayUrl.replace(/\/+$/, "");
  return {
    ...client,
    async registerDataPoint(
      params: RegisterParams,
      options?: { signal?: AbortSignal },
    ): Promise<RegisterResult> {
      const signal = options?.signal;
      if (!signal) return client.registerDataPoint(params);
      const res = await fetchImpl(`${base}/v1/data`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Web3Signed ${params.signature}`,
        },
        body: JSON.stringify({
          ownerAddress: params.ownerAddress,
          scope: params.scope,
          dataHash: params.dataHash,
          metadataHash: params.metadataHash,
          expectedVersion: params.expectedVersion,
        }),
        signal,
      });
      const body = await res.json().catch(() => ({}));
      const record =
        body && typeof body === "object"
          ? (body as Record<string, unknown>)
          : {};
      if (!res.ok) {
        const detail =
          typeof record.error === "string" ? record.error : res.statusText;
        throw new Error(`Gateway error: ${res.status} ${detail}`);
      }
      const id = record.dataPointId ?? record.id;
      return {
        dataPointId: typeof id === "string" ? id : undefined,
        expectedVersion:
          typeof record.expectedVersion === "string"
            ? record.expectedVersion
            : undefined,
      } as RegisterResult;
    },
  };
}
