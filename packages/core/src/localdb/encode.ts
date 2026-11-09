import type { JsonValue } from "@opendatalabs/personal-server-ts-stream-sync";
import type { LocalSyncDeps } from "./deps.js";

/**
 * Extra fields a head carries beside its parts (pending r5.2: the first-seen
 * checkpoint, "history-checkpoint"). Opaque here: encode copies them into the
 * head unchanged. Absent today.
 */
export type HeadExtras = Readonly<Record<string, JsonValue>>;

/** One uploaded (or already present) part of a head. */
export interface EncodedPart {
  readonly prefix: string;
  readonly seq: number;
  readonly partHash: string;
  readonly bytes: number;
  readonly count: number;
  /** Blob name `g<gen>-p-<sha256>`. */
  readonly blobName: string;
}

/**
 * C.2 step 4: encode the changed prefixes of one stream from `records`
 * `ORDER BY pk_hash` (one prefix per query), as format-2 frames in parts of
 * at most `partTargetBytes`, STREAM-encrypted, and upload each part that does
 * not exist. Under replace (H), leave out rows below `replaceBelow`. Identical
 * rows give an identical part, so a repeat run makes zero PUTs.
 */
export async function encodePrefixes(
  deps: LocalSyncDeps,
  input: {
    readonly connectionId: string;
    readonly stream: string;
    readonly scope: string;
    readonly generation: number;
    readonly changedPrefixes: readonly string[];
    readonly upToSeq: number;
    readonly replaceBelow?: { readonly o: number; readonly r: string };
    readonly headExtras?: HeadExtras;
  },
): Promise<readonly EncodedPart[]> {
  void deps;
  void input;
  throw new Error("PS-2: not built");
}
