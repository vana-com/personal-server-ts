import { afterEach, describe, expect, it, vi } from "vitest";
import type { ServerSigner } from "@opendatalabs/personal-server-ts-core/signing";
import {
  createSchemaRegistrar,
  NO_SCHEMA_DEFINITION_URL,
  NO_SCHEMA_DIALECT,
} from "./schema-registrar.js";

function mockSigner(): ServerSigner {
  return {
    address: "0x1111111111111111111111111111111111111111",
    signFileRegistration: vi.fn(),
    signGrantRegistration: vi.fn(),
    signGrantRevocation: vi.fn(),
    signSchemaRegistration: vi.fn().mockResolvedValue("0xdeadbeef"),
  };
}

describe("createSchemaRegistrar", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("signs and POSTs a no-schema registration, returning the schemaId", async () => {
    const signer = mockSigner();
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ data: { schemaId: "0xnoschema" } }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    const registrar = createSchemaRegistrar({
      gatewayUrl: "https://gw.example/",
      signer,
    });

    const result = await registrar.registerNoSchema("documents.pdf");

    expect(result).toEqual({
      schemaId: "0xnoschema",
      definitionUrl: NO_SCHEMA_DEFINITION_URL,
    });

    // Signed message carries the signer address as ownerAddress + scope.
    expect(signer.signSchemaRegistration).toHaveBeenCalledWith({
      ownerAddress: signer.address,
      name: expect.any(String),
      definitionUrl: NO_SCHEMA_DEFINITION_URL,
      scope: "documents.pdf",
      dialect: NO_SCHEMA_DIALECT,
    });

    // POSTs to /v1/schemas with the EIP-712 signature as a Web3Signed header.
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe("https://gw.example/v1/schemas");
    expect(init?.method).toBe("POST");
    expect((init?.headers as Record<string, string>).Authorization).toBe(
      "Web3Signed 0xdeadbeef",
    );
    expect(JSON.parse(init?.body as string)).toMatchObject({
      ownerAddress: signer.address,
      scope: "documents.pdf",
    });
  });

  it("accepts a top-level schemaId in the response", async () => {
    const signer = mockSigner();
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ schemaId: "0xtop" }), { status: 200 }),
    );
    const registrar = createSchemaRegistrar({
      gatewayUrl: "https://gw.example",
      signer,
    });
    await expect(registrar.registerNoSchema("a.b")).resolves.toMatchObject({
      schemaId: "0xtop",
    });
  });

  it("throws when the gateway rejects the registration", async () => {
    const signer = mockSigner();
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("server configuration error", { status: 500 }),
    );
    const registrar = createSchemaRegistrar({
      gatewayUrl: "https://gw.example",
      signer,
    });
    await expect(registrar.registerNoSchema("a.b")).rejects.toThrow(
      /Schema registration failed: 500/,
    );
  });

  it("throws when no schemaId is returned", async () => {
    const signer = mockSigner();
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ data: {} }), { status: 200 }),
    );
    const registrar = createSchemaRegistrar({
      gatewayUrl: "https://gw.example",
      signer,
    });
    await expect(registrar.registerNoSchema("a.b")).rejects.toThrow(
      /did not return a schemaId/,
    );
  });
});
