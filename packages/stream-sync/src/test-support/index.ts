import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import type { Sha256 } from "../hash.js";
import { ReferenceStore } from "../reference-host.js";
import type { VectorFile } from "../conformance.js";
import type { JsonObject } from "../json.js";
import type { StampedRecord } from "../records.js";

/** A SHA-256 port that does not use Web Crypto, to prove the port is injectable. */
export const nodeSha256: Sha256 = async (data) =>
  new Uint8Array(createHash("sha256").update(data).digest());

export const VECTOR_NAMES = [
  "canonical-json",
  "overlay",
  "split",
  "plan",
  "assemble",
  "connection-files",
] as const;

export function loadVectors(): VectorFile[] {
  return VECTOR_NAMES.map(
    (name) =>
      JSON.parse(
        readFileSync(
          new URL(`../../vectors/${name}.json`, import.meta.url),
          "utf8",
        ),
      ) as VectorFile,
  );
}

export function newStore(): ReferenceStore {
  return new ReferenceStore(nodeSha256);
}

/** A promise with its resolver, for pausing a host at a chosen point. */
export function gate(): { promise: Promise<void>; open: () => void } {
  let open!: () => void;
  const promise = new Promise<void>((resolve) => {
    open = resolve;
  });
  return { promise, open };
}

/** Stamp plain records with one observation time. */
export function stamped(
  records: readonly JsonObject[],
  observedAt: number,
): StampedRecord[] {
  return records.map((record) => ({ record, observedAt }));
}
