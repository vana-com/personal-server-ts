// Out-of-line bodies (stream-sync `log.ts`, "Bodies out of line"). A record
// whose body is larger than one object the writer PUTs (its part target) is
// not carried in the segment or the snapshot part: its canonical JSON is cut
// into pieces of at most that target, each encrypted and stored under the log
// scope by the Keccak-256 of its clear bytes, and the upsert names the pieces.
// The reader fetches them, checks every piece against its hash and the whole
// body against its SHA-256, and gets the upsert back as if it had been inline.
//
// The pieces are content-addressed and never deleted, as segments are. A body
// this device resolved is remembered with its pieces, so a compaction that
// folds it into a snapshot part names the same pieces and uploads nothing.
// The memory is keyed by the body object, which a fold carries over when it
// copies the upsert.

import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "@noble/hashes/utils";
import {
  bodyPieceBlobName,
  canonicalJson,
  isPlainObject,
  keccakHex,
  utf8,
  type JsonObject,
  type LogBodyRef,
  type LogUpsert,
  type LogUpsertByRef,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { keccakOf } from "../stream-sync/crypto-port.js";
import type { LocalSyncDeps } from "./deps.js";

/** One piece of an out-of-line body, encrypted, by its blob name in the log scope. */
export interface BodyPiece {
  readonly name: string;
  readonly cipher: Uint8Array;
}

/** Bodies this device resolved, by the body object, with the pieces that hold them. */
const known = new WeakMap<JsonObject, LogBodyRef>();

/**
 * `ops` with every upsert whose body is longer than `targetBytes` named out
 * of line, and the pieces to upload before the object that names them. An
 * upsert this device resolved from pieces names the same pieces again, with
 * nothing to upload: they are in storage.
 */
export async function putBodiesOutOfLine<T extends { readonly kind: string }>(
  deps: Pick<LocalSyncDeps, "keys" | "streamCrypto">,
  scope: string,
  ops: readonly T[],
  targetBytes: number,
): Promise<{
  readonly ops: (T | LogUpsertByRef)[];
  readonly pieces: BodyPiece[];
}> {
  const out: (T | LogUpsertByRef)[] = [];
  const pieces: BodyPiece[] = [];
  for (const op of ops) {
    if (op.kind !== "upsert") {
      out.push(op);
      continue;
    }
    const upsert = op as unknown as LogUpsert;
    let body = known.get(upsert.value);
    if (!body) {
      // A UTF-16 unit is at most three UTF-8 bytes: a body this short fits.
      if (JSON.stringify(upsert.value).length * 3 <= targetBytes) {
        out.push(op);
        continue;
      }
      const bytes = utf8(canonicalJson(upsert.value));
      if (bytes.length <= targetBytes) {
        out.push(op);
        continue;
      }
      const hashes: `0x${string}`[] = [];
      for (let at = 0; at < bytes.length; at += targetBytes) {
        const clear = bytes.subarray(at, at + targetBytes);
        const hash = await keccakHex(keccakOf(deps.streamCrypto), clear);
        hashes.push(hash);
        pieces.push({
          name: bodyPieceBlobName(hash),
          cipher: await deps.keys.encryptPart(scope, clear),
        });
      }
      body = {
        sha256: bytesToHex(sha256(bytes)),
        bytes: bytes.length,
        pieces: hashes,
      };
    }
    const { kind: _kind, value: _value, ...rest } = upsert;
    out.push({ ...rest, kind: "upsert-ref", body });
  }
  return { ops: out, pieces };
}

const decoder = new TextDecoder("utf-8", { fatal: true });

/**
 * `ops` with every out-of-line body fetched and checked. Throws when a piece
 * is missing or any check fails: the object that names it is not applied.
 */
export async function resolveBodies<T extends { readonly kind: string }>(
  deps: Pick<LocalSyncDeps, "blobs" | "keys" | "streamCrypto">,
  scope: string,
  ops: readonly T[],
): Promise<Exclude<T, LogUpsertByRef>[]> {
  type Resolved = Exclude<T, LogUpsertByRef>;
  if (!ops.some((op) => op.kind === "upsert-ref")) return ops as Resolved[];
  const out: Resolved[] = [];
  for (const op of ops) {
    if (op.kind !== "upsert-ref") {
      out.push(op as Resolved);
      continue;
    }
    const { kind: _kind, body, ...rest } = op as unknown as LogUpsertByRef;
    const value = await fetchBody(deps, scope, body);
    const upsert: LogUpsert = { ...rest, kind: "upsert", value };
    known.set(value, body);
    out.push(upsert as unknown as Resolved);
  }
  return out;
}

async function fetchBody(
  deps: Pick<LocalSyncDeps, "blobs" | "keys" | "streamCrypto">,
  scope: string,
  body: LogBodyRef,
): Promise<JsonObject> {
  const clear = await Promise.all(
    body.pieces.map(async (hash) => {
      const cipher = await deps.blobs.get(
        `${scope}/${bodyPieceBlobName(hash)}`,
      );
      if (cipher === null)
        throw new Error("apply: missing a piece of an out-of-line body");
      const piece = await deps.keys.decrypt(scope, cipher);
      if ((await keccakHex(keccakOf(deps.streamCrypto), piece)) !== hash)
        throw new Error("apply: an out-of-line body piece fails its hash");
      return piece;
    }),
  );
  const length = clear.reduce((n, piece) => n + piece.length, 0);
  if (length !== body.bytes)
    throw new Error("apply: an out-of-line body has the wrong length");
  const bytes = new Uint8Array(length);
  let at = 0;
  for (const piece of clear) {
    bytes.set(piece, at);
    at += piece.length;
  }
  if (bytesToHex(sha256(bytes)) !== body.sha256)
    throw new Error("apply: an out-of-line body fails its SHA-256");
  let text: string;
  let value: unknown;
  try {
    text = decoder.decode(bytes);
    value = JSON.parse(text);
  } catch {
    throw new Error("apply: an out-of-line body is not UTF-8 JSON");
  }
  // The hash the merge compares (`upsertAfter`) is of the canonical form.
  if (!isPlainObject(value) || canonicalJson(value) !== text)
    throw new Error("apply: an out-of-line body is not a canonical object");
  return value;
}
