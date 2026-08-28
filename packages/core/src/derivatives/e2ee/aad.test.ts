import { describe, expect, it } from "vitest";
import { requestFieldAad, responseFieldAad } from "./aad.js";

/** Fixed inputs from spec/e2ee-v2-test-vectors.md. */
const VECTOR = {
  algo: "x25519-aes-256-gcm-hkdf-sha256",
  model: "demo-model",
  nonce: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  ts: 1750000000,
};

const decode = (bytes: Uint8Array) => new TextDecoder().decode(bytes);

describe("E2EE v2 associated data (spec test vectors)", () => {
  it("request field AAD for messages.0.content is byte-exact", () => {
    expect(decode(requestFieldAad(VECTOR, "messages.0.content"))).toBe(
      '{"algo":"x25519-aes-256-gcm-hkdf-sha256","field":"messages.0.content","model":"demo-model","nonce":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","purpose":"aci.e2ee.request.v2","ts":1750000000}',
    );
  });

  it("response field AAD for choices.0.message.content is byte-exact", () => {
    expect(
      decode(
        responseFieldAad(VECTOR, "choices.0.message.content", "chatcmpl-123"),
      ),
    ).toBe(
      '{"algo":"x25519-aes-256-gcm-hkdf-sha256","field":"choices.0.message.content","id":"chatcmpl-123","model":"demo-model","nonce":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","purpose":"aci.e2ee.response.v2","ts":1750000000}',
    );
  });

  it("binds the model byte-exact and the timestamp as an integer", () => {
    const aad = decode(
      requestFieldAad(
        { ...VECTOR, model: " Demo-Model " },
        "messages.1.content",
      ),
    );
    expect(aad).toContain('"model":" Demo-Model "');
    expect(aad).toContain('"ts":1750000000}');
    expect(aad).toContain('"field":"messages.1.content"');
  });

  it("uses an empty id when the response has none", () => {
    expect(
      decode(responseFieldAad(VECTOR, "choices.0.message.content", "")),
    ).toContain('"id":""');
  });
});
