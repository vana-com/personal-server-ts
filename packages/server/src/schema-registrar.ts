import type {
  RegisteredSchema,
  SchemaRegistrarPort,
} from "@opendatalabs/personal-server-ts-core/ports";
import type { ServerSigner } from "@opendatalabs/personal-server-ts-core/signing";
import type { Logger } from "pino";

/**
 * Definition used for scopes that carry unstructured/binary data. Nothing in
 * this stack fetches the definitionUrl — it only needs to be a stable string —
 * but consuming builders may dereference it, so it points at a permissive doc.
 */
export const NO_SCHEMA_NAME = "No Schema";
export const NO_SCHEMA_DEFINITION_URL =
  "https://schemas.vana.org/no-schema/v1.json";
export const NO_SCHEMA_DIALECT = "none";

export interface SchemaRegistrarDeps {
  gatewayUrl: string;
  signer: ServerSigner;
  logger?: Logger;
}

interface SchemaRegistrationResponseBody {
  id?: string;
  schemaId?: string;
  data?: { id?: string; schemaId?: string };
}

function extractSchemaId(
  body: SchemaRegistrationResponseBody,
): string | undefined {
  return (
    body.schemaId ??
    body.id ??
    body.data?.schemaId ??
    body.data?.id ??
    undefined
  );
}

/**
 * Registers (idempotently, by scope) a permissive "no-schema" schema with the
 * gateway via POST /v1/schemas, signing an EIP-712 SchemaRegistration message.
 *
 * The gateway requires the EIP-712 signer to equal the registered ownerAddress
 * (no server-delegation branch for schemas), so the schema is owned by the
 * server signing account.
 */
export function createSchemaRegistrar(
  deps: SchemaRegistrarDeps,
): SchemaRegistrarPort {
  const base = deps.gatewayUrl.replace(/\/+$/, "");

  return {
    async registerNoSchema(scope: string): Promise<RegisteredSchema> {
      const ownerAddress = deps.signer.address;
      const message = {
        ownerAddress,
        name: NO_SCHEMA_NAME,
        definitionUrl: NO_SCHEMA_DEFINITION_URL,
        scope,
        dialect: NO_SCHEMA_DIALECT,
      };
      const signature = await deps.signer.signSchemaRegistration(message);

      const res = await fetch(`${base}/v1/schemas`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Web3Signed ${signature}`,
        },
        body: JSON.stringify(message),
      });

      if (!res.ok) {
        const detail = await res.text().catch(() => res.statusText);
        throw new Error(`Schema registration failed: ${res.status} ${detail}`);
      }

      const body = (await res
        .json()
        .catch(() => ({}))) as SchemaRegistrationResponseBody;
      const schemaId = extractSchemaId(body);
      if (!schemaId) {
        throw new Error(
          `Schema registration for "${scope}" did not return a schemaId`,
        );
      }

      deps.logger?.info(
        { scope, schemaId },
        "Registered no-schema schema with gateway",
      );
      return { schemaId, definitionUrl: NO_SCHEMA_DEFINITION_URL };
    },
  };
}
