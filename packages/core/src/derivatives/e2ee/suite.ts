/**
 * E2EE v2 cipher suite `x25519-aes-256-gcm-hkdf-sha256` on WebCrypto only
 * (X25519 deriveBits, HKDF-SHA256, AES-256-GCM, getRandomValues), so the
 * same code runs in Node 22+ and in the browser (PS-Lite). No Node-only
 * import lives in this directory.
 *
 * Wire format of one encrypted field value (spec section 4), lowercase hex:
 *
 *   ephemeral_public_key (32) || aes_gcm_nonce (12) || ciphertext || tag (16)
 *
 *   key = HKDF-SHA256(salt = none, ikm = X25519(ephemeral, recipient),
 *                     info = "aci.e2ee.v2.x25519", len = 32)
 *
 * A fresh ephemeral key and AES-GCM nonce per field; the AAD is the JCS
 * bytes built in aad.ts.
 */

export const E2EE_ALGO_X25519 = "x25519-aes-256-gcm-hkdf-sha256";
export const E2EE_HKDF_INFO_X25519 = "aci.e2ee.v2.x25519";

const X25519_PUBLIC_KEY_BYTES = 32;
const AES_GCM_NONCE_BYTES = 12;
const AES_GCM_TAG_BYTES = 16;

export interface E2eeKeyPair {
  privateKey: CryptoKey;
  /** Raw 32-byte X25519 public key. */
  publicKey: Uint8Array;
}

export class E2eeCipherError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "E2eeCipherError";
  }
}

function subtle(): SubtleCrypto {
  const api = globalThis.crypto?.subtle;
  if (!api) throw new E2eeCipherError("WebCrypto is not available");
  return api;
}

export function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

export function hexToBytes(hex: string): Uint8Array {
  const clean =
    hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) {
    throw new E2eeCipherError("malformed hex");
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Spec section 4: hex with an optional `0x` prefix, 32 bytes for X25519. */
export function parseX25519PublicKey(hex: string): Uint8Array {
  const bytes = hexToBytes(hex);
  if (bytes.length !== X25519_PUBLIC_KEY_BYTES) {
    throw new E2eeCipherError("X25519 public key must be 32 bytes");
  }
  return bytes;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/** Copy into a plain ArrayBuffer (WebCrypto rejects some typed-array views). */
function toBuffer(bytes: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(out).set(bytes);
  return out;
}

export async function generateX25519KeyPair(): Promise<E2eeKeyPair> {
  const pair = (await subtle().generateKey({ name: "X25519" }, false, [
    "deriveBits",
  ])) as CryptoKeyPair;
  const raw = await subtle().exportKey("raw", pair.publicKey);
  return { privateKey: pair.privateKey, publicKey: new Uint8Array(raw) };
}

/**
 * Import a private key from its 32-byte seed. Only for tests and tooling
 * that need a deterministic key; production keys come from generate.
 */
export async function importX25519PrivateKey(
  seed: Uint8Array,
  publicKey: Uint8Array,
): Promise<E2eeKeyPair> {
  const b64u = (bytes: Uint8Array) =>
    btoa(String.fromCharCode(...bytes))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  const privateKey = await subtle().importKey(
    "jwk",
    { kty: "OKP", crv: "X25519", d: b64u(seed), x: b64u(publicKey) },
    { name: "X25519" },
    false,
    ["deriveBits"],
  );
  return { privateKey, publicKey };
}

async function deriveFieldKey(
  privateKey: CryptoKey,
  peerPublicKey: Uint8Array,
  usage: "encrypt" | "decrypt",
): Promise<CryptoKey> {
  const api = subtle();
  const peer = await api.importKey(
    "raw",
    toBuffer(peerPublicKey),
    { name: "X25519" },
    false,
    [],
  );
  const shared = await api.deriveBits(
    { name: "X25519", public: peer },
    privateKey,
    X25519_PUBLIC_KEY_BYTES * 8,
  );
  const ikm = await api.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  return api.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(0),
      info: new TextEncoder().encode(E2EE_HKDF_INFO_X25519),
    },
    ikm,
    { name: "AES-GCM", length: 256 },
    false,
    [usage],
  );
}

export interface EncryptFieldInput {
  plaintext: string;
  recipientPublicKey: Uint8Array;
  aad: Uint8Array;
  /** Test hooks: a fixed ephemeral key / nonce make the output reproducible. */
  ephemeral?: E2eeKeyPair;
  nonce?: Uint8Array;
}

/** One field value -> lowercase hex wire value. */
export async function encryptField(input: EncryptFieldInput): Promise<string> {
  const ephemeral = input.ephemeral ?? (await generateX25519KeyPair());
  const nonce = input.nonce ?? randomBytes(AES_GCM_NONCE_BYTES);
  if (nonce.length !== AES_GCM_NONCE_BYTES) {
    throw new E2eeCipherError("AES-GCM nonce must be 12 bytes");
  }
  const key = await deriveFieldKey(
    ephemeral.privateKey,
    input.recipientPublicKey,
    "encrypt",
  );
  const sealed = await subtle().encrypt(
    {
      name: "AES-GCM",
      iv: toBuffer(nonce),
      additionalData: toBuffer(input.aad),
      tagLength: AES_GCM_TAG_BYTES * 8,
    },
    key,
    new TextEncoder().encode(input.plaintext),
  );
  return bytesToHex(concat(ephemeral.publicKey, nonce, new Uint8Array(sealed)));
}

export interface DecryptFieldInput {
  /** Hex wire value (either case, optional 0x). */
  wire: string;
  privateKey: CryptoKey;
  aad: Uint8Array;
}

/** Hex wire value -> plaintext; throws E2eeCipherError on any failure. */
export async function decryptField(input: DecryptFieldInput): Promise<string> {
  let bytes: Uint8Array;
  try {
    bytes = hexToBytes(input.wire);
  } catch {
    throw new E2eeCipherError("ciphertext is not hex");
  }
  const minimum =
    X25519_PUBLIC_KEY_BYTES + AES_GCM_NONCE_BYTES + AES_GCM_TAG_BYTES;
  if (bytes.length < minimum) {
    throw new E2eeCipherError("ciphertext is too short");
  }
  const ephemeralPublicKey = bytes.subarray(0, X25519_PUBLIC_KEY_BYTES);
  const nonce = bytes.subarray(
    X25519_PUBLIC_KEY_BYTES,
    X25519_PUBLIC_KEY_BYTES + AES_GCM_NONCE_BYTES,
  );
  const sealed = bytes.subarray(X25519_PUBLIC_KEY_BYTES + AES_GCM_NONCE_BYTES);
  let key: CryptoKey;
  try {
    key = await deriveFieldKey(input.privateKey, ephemeralPublicKey, "decrypt");
  } catch {
    throw new E2eeCipherError("key agreement failed");
  }
  let opened: ArrayBuffer;
  try {
    opened = await subtle().decrypt(
      {
        name: "AES-GCM",
        iv: toBuffer(nonce),
        additionalData: toBuffer(input.aad),
        tagLength: AES_GCM_TAG_BYTES * 8,
      },
      key,
      toBuffer(sealed),
    );
  } catch {
    throw new E2eeCipherError("authentication failed");
  }
  return new TextDecoder().decode(opened);
}
