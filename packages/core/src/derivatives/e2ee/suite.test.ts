import { describe, expect, it } from "vitest";
import { requestFieldAad, responseFieldAad } from "./aad.js";
import {
  E2eeCipherError,
  bytesToHex,
  decryptField,
  encryptField,
  generateX25519KeyPair,
  hexToBytes,
  importX25519PrivateKey,
  parseX25519PublicKey,
} from "./suite.js";

/**
 * Deterministic vectors on top of the spec's fixed inputs (service seed
 * 32 x 0x03, nonce 00..1f, ts 1750000000, model demo-model, response id
 * chatcmpl-123), produced with an independent implementation (Python
 * `cryptography`: X25519 + HKDF-SHA256(salt none, info aci.e2ee.v2.x25519)
 * + AES-256-GCM). Ephemeral seeds: request 32 x 0x01, response 32 x 0x04;
 * client seed 32 x 0x02; AES-GCM nonces 00..0b and 10..1b.
 */
const SERVICE_SEED = new Uint8Array(32).fill(3);
const SERVICE_PUB =
  "5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22";
const CLIENT_SEED = new Uint8Array(32).fill(2);
const CLIENT_PUB =
  "ce8d3ad1ccb633ec7b70c17814a5c76ecd029685050d344745ba05870e587d59";
const EPH_REQUEST_SEED = new Uint8Array(32).fill(1);
const EPH_REQUEST_PUB =
  "a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209";
const EPH_RESPONSE_SEED = new Uint8Array(32).fill(4);
const EPH_RESPONSE_PUB =
  "ac01b2209e86354fb853237b5de0f4fab13c7fcbf433a61c019369617fecf10b";
const CONTEXT = {
  algo: "x25519-aes-256-gcm-hkdf-sha256",
  model: "demo-model",
  nonce: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  ts: 1750000000,
};
const REQUEST_WIRE =
  "a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209000102030405060708090a0b1475356879c63e49d8cdfa05d46b5f70aedf5b3fb8d21bdf1c49d6";
const RESPONSE_WIRE =
  "ac01b2209e86354fb853237b5de0f4fab13c7fcbf433a61c019369617fecf10b101112131415161718191a1bc5de70d4e594670e9e13eb97638f159d1ccd383fc9dea1253f42932b28b86f55f684cb19da6c2736381d01bd8c49405e05";

const seq = (from: number, length: number) =>
  Uint8Array.from({ length }, (_, i) => from + i);

describe("x25519-aes-256-gcm-hkdf-sha256 suite", () => {
  it("encrypts a request field byte for byte like the independent vector", async () => {
    const wire = await encryptField({
      plaintext: "hello, e2ee",
      recipientPublicKey: hexToBytes(SERVICE_PUB),
      aad: requestFieldAad(CONTEXT, "messages.0.content"),
      ephemeral: await importX25519PrivateKey(
        EPH_REQUEST_SEED,
        hexToBytes(EPH_REQUEST_PUB),
      ),
      nonce: seq(0, 12),
    });
    expect(wire).toBe(REQUEST_WIRE);
    // Wire layout: ephemeral pub (32) || nonce (12) || ciphertext || tag (16).
    expect(wire.slice(0, 64)).toBe(EPH_REQUEST_PUB);
    expect(wire.slice(64, 88)).toBe("000102030405060708090a0b");
    expect(wire.length).toBe((32 + 12 + "hello, e2ee".length + 16) * 2);
  });

  it("decrypts the vector request ciphertext as the service (spec seed 32 x 0x03)", async () => {
    const service = await importX25519PrivateKey(
      SERVICE_SEED,
      hexToBytes(SERVICE_PUB),
    );
    await expect(
      decryptField({
        wire: REQUEST_WIRE,
        privateKey: service.privateKey,
        aad: requestFieldAad(CONTEXT, "messages.0.content"),
      }),
    ).resolves.toBe("hello, e2ee");
  });

  it("encrypts and decrypts a response field to the client key like the vector", async () => {
    const wire = await encryptField({
      plaintext: '{"answer":"42","evidence":"none"}',
      recipientPublicKey: hexToBytes(CLIENT_PUB),
      aad: responseFieldAad(
        CONTEXT,
        "choices.0.message.content",
        "chatcmpl-123",
      ),
      ephemeral: await importX25519PrivateKey(
        EPH_RESPONSE_SEED,
        hexToBytes(EPH_RESPONSE_PUB),
      ),
      nonce: seq(16, 12),
    });
    expect(wire).toBe(RESPONSE_WIRE);
    const client = await importX25519PrivateKey(
      CLIENT_SEED,
      hexToBytes(CLIENT_PUB),
    );
    await expect(
      decryptField({
        wire: RESPONSE_WIRE.toUpperCase(),
        privateKey: client.privateKey,
        aad: responseFieldAad(
          CONTEXT,
          "choices.0.message.content",
          "chatcmpl-123",
        ),
      }),
    ).resolves.toBe('{"answer":"42","evidence":"none"}');
  });

  it("uses a fresh ephemeral key and nonce per field", async () => {
    const recipient = await generateX25519KeyPair();
    const aad = requestFieldAad(CONTEXT, "messages.0.content");
    const a = await encryptField({
      plaintext: "same",
      recipientPublicKey: recipient.publicKey,
      aad,
    });
    const b = await encryptField({
      plaintext: "same",
      recipientPublicKey: recipient.publicKey,
      aad,
    });
    expect(a).not.toBe(b);
    expect(a.slice(0, 64)).not.toBe(b.slice(0, 64));
    expect(a.slice(64, 88)).not.toBe(b.slice(64, 88));
    for (const wire of [a, b]) {
      await expect(
        decryptField({ wire, privateKey: recipient.privateKey, aad }),
      ).resolves.toBe("same");
    }
  });

  it("rejects a ciphertext moved to another field, request or timestamp", async () => {
    const service = await importX25519PrivateKey(
      SERVICE_SEED,
      hexToBytes(SERVICE_PUB),
    );
    const cases = [
      requestFieldAad(CONTEXT, "messages.1.content"),
      requestFieldAad(
        { ...CONTEXT, nonce: "ff".repeat(32) },
        "messages.0.content",
      ),
      requestFieldAad({ ...CONTEXT, ts: CONTEXT.ts + 1 }, "messages.0.content"),
      requestFieldAad({ ...CONTEXT, model: "other" }, "messages.0.content"),
      responseFieldAad(CONTEXT, "messages.0.content", ""),
    ];
    for (const aad of cases) {
      await expect(
        decryptField({
          wire: REQUEST_WIRE,
          privateKey: service.privateKey,
          aad,
        }),
      ).rejects.toThrow(E2eeCipherError);
    }
  });

  it("rejects malformed wire values without leaking anything but a reason", async () => {
    const service = await importX25519PrivateKey(
      SERVICE_SEED,
      hexToBytes(SERVICE_PUB),
    );
    const aad = requestFieldAad(CONTEXT, "messages.0.content");
    await expect(
      decryptField({ wire: "not hex", privateKey: service.privateKey, aad }),
    ).rejects.toThrow("ciphertext is not hex");
    await expect(
      decryptField({
        wire: "00".repeat(59),
        privateKey: service.privateKey,
        aad,
      }),
    ).rejects.toThrow("ciphertext is too short");
    const flipped =
      REQUEST_WIRE.slice(0, -2) +
      (parseInt(REQUEST_WIRE.slice(-2), 16) ^ 1).toString(16).padStart(2, "0");
    await expect(
      decryptField({ wire: flipped, privateKey: service.privateKey, aad }),
    ).rejects.toThrow("authentication failed");
  });

  it("parses public keys as 32 bytes of hex with an optional 0x prefix", () => {
    expect(bytesToHex(parseX25519PublicKey(`0x${SERVICE_PUB}`))).toBe(
      SERVICE_PUB,
    );
    expect(bytesToHex(parseX25519PublicKey(SERVICE_PUB.toUpperCase()))).toBe(
      SERVICE_PUB,
    );
    expect(() => parseX25519PublicKey(SERVICE_PUB.slice(2))).toThrow(
      E2eeCipherError,
    );
    expect(() => parseX25519PublicKey("zz".repeat(32))).toThrow(
      E2eeCipherError,
    );
  });
});
