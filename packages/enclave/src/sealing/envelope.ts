/**
 * Sealing envelope for a user's master signature.
 *
 *   secret ──AES-256-GCM(contentKey, AAD=userPsId/epoch)──> iv, ciphertext, tag
 *   contentKey ──AES-256-GCM(sealingKey, AAD=userPsId/epoch)──> wrappedContentKey
 *   sealingKey = dstack key at users/{userPsId}/secrets/master-signature/v{epoch}
 *
 * Only the envelope persists. Any node under the same app_id re-derives the
 * sealing key and unwraps. AAD binds both layers to userPsId and epoch, so an
 * envelope from a previous epoch fails authentication. The content-key layer
 * makes a vendor exit a re-wrap of 32 bytes, not a re-encryption of the secret.
 */

import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import type { DstackClient } from "../dstack/client.js";
import {
  SEALING_PURPOSE,
  sealingPath,
  type UserPsId,
} from "../identity/paths.js";

export const SEALED_ENVELOPE_VERSION = 1;

const CIPHER = "aes-256-gcm";
const CONTENT_KEY_BYTES = 32;
const GCM_IV_BYTES = 12;
const GCM_TAG_BYTES = 16;
const ENCODING = "base64";
const AAD_SEPARATOR = "/";

/** One AES-GCM ciphertext; fields are base64. */
export interface AesGcmBox {
  iv: string;
  ciphertext: string;
  tag: string;
}

export interface SealedEnvelope extends AesGcmBox {
  v: typeof SEALED_ENVELOPE_VERSION;
  wrappedContentKey: AesGcmBox;
}

export class UnsealError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UnsealError";
  }
}

export async function seal(
  client: DstackClient,
  id: UserPsId,
  epoch: number,
  secret: Uint8Array,
): Promise<SealedEnvelope> {
  const aad = sealingAad(id, epoch);
  const contentKey = randomBytes(CONTENT_KEY_BYTES);
  const { key: sealingKey } = await client.deriveKey(
    sealingPath(id, epoch),
    SEALING_PURPOSE,
  );

  const box = encrypt(contentKey, secret, aad);
  const wrappedContentKey = encrypt(sealingKey, contentKey, aad);
  contentKey.fill(0);

  return { v: SEALED_ENVELOPE_VERSION, wrappedContentKey, ...box };
}

export async function unseal(
  client: DstackClient,
  id: UserPsId,
  epoch: number,
  envelope: SealedEnvelope,
): Promise<Uint8Array> {
  if (envelope.v !== SEALED_ENVELOPE_VERSION) {
    throw new UnsealError(`unsupported envelope version ${envelope.v}`);
  }

  const aad = sealingAad(id, epoch);
  const { key: sealingKey } = await client.deriveKey(
    sealingPath(id, epoch),
    SEALING_PURPOSE,
  );

  const contentKey = decrypt(sealingKey, envelope.wrappedContentKey, aad);
  const secret = decrypt(contentKey, envelope, aad);
  contentKey.fill(0);

  return secret;
}

export function sealingAad(id: UserPsId, epoch: number): Buffer {
  return Buffer.from(`${id}${AAD_SEPARATOR}${epoch}`, "utf8");
}

function encrypt(
  key: Uint8Array,
  plaintext: Uint8Array,
  aad: Buffer,
): AesGcmBox {
  const iv = randomBytes(GCM_IV_BYTES);
  const cipher = createCipheriv(CIPHER, key, iv, {
    authTagLength: GCM_TAG_BYTES,
  });
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);

  return {
    iv: iv.toString(ENCODING),
    ciphertext: ciphertext.toString(ENCODING),
    tag: cipher.getAuthTag().toString(ENCODING),
  };
}

// GCM verifies the tag over ciphertext and AAD before releasing plaintext;
// a wrong key, a tampered byte, or a different userPsId all land here.
function decrypt(key: Uint8Array, box: AesGcmBox, aad: Buffer): Buffer {
  const decipher = createDecipheriv(
    CIPHER,
    key,
    Buffer.from(box.iv, ENCODING),
    {
      authTagLength: GCM_TAG_BYTES,
    },
  );
  decipher.setAAD(aad);
  decipher.setAuthTag(Buffer.from(box.tag, ENCODING));

  try {
    return Buffer.concat([
      decipher.update(Buffer.from(box.ciphertext, ENCODING)),
      decipher.final(),
    ]);
  } catch {
    throw new UnsealError("authentication failed");
  }
}
