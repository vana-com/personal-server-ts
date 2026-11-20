import type { GatewayClient } from "@opendatalabs/vana-sdk/browser";

/** A registration refusal whose status and reason the SDK would otherwise discard. */
export class McpGrantRegistrationError extends Error {
  readonly retryable: boolean;
  constructor(
    public status: number,
    public body: unknown,
  ) {
    super(`Gateway registration refused (${status}): ${JSON.stringify(body)}`);
    this.name = "McpGrantRegistrationError";
    this.retryable =
      status === 409 ||
      (status === 503 &&
        /(?:settlement|revocation).*in flight/iu.test(JSON.stringify(body)));
  }
}

/**
 * The SDK treats registration 409 as success and drops 503 bodies. Connection
 * writers need the actual refusal to distinguish a lost CAS or settling grant.
 * Wrap SDK clients at construction; injected clients must reject failed writes.
 */
export function withStrictMcpGrantRegistration<
  T extends Pick<GatewayClient, "createGrant">,
>(gateway: T, gatewayUrl: string): T {
  return {
    ...gateway,
    async createGrant(params: Parameters<GatewayClient["createGrant"]>[0]) {
      const response = await fetch(
        `${gatewayUrl.replace(/\/$/u, "")}/v1/grants`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Web3Signed ${params.signature}`,
          },
          body: JSON.stringify(params),
        },
      );
      const body: unknown = await response.json().catch(() => ({}));
      if (!response.ok)
        throw new McpGrantRegistrationError(response.status, body);
      const grantId =
        body && typeof body === "object" && "grantId" in body
          ? body.grantId
          : undefined;
      return { grantId: typeof grantId === "string" ? grantId : undefined };
    },
  };
}
