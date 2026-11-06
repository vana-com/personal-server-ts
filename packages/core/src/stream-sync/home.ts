/**
 * The storage home of one stream-sync writer: spools, host entries, saved
 * checkpoints and receipts for exactly one owner on exactly one network.
 *
 * A writer takes a `StreamSyncHome`, never bare `StreamSyncFiles`, and the
 * only way to make a home is `bindStreamSyncHome`. That function hands the
 * host the home's id and asks it for the files, so a host cannot point two
 * owners or two networks at one location without ignoring `id`. Recovery and
 * checkpoint planning then only ever see this home's entries.
 *
 * One live writer per home is the host's duty (a Web Lock in the browser, a
 * lock file on disk): a second writer would take the first one's collecting
 * runs for abandoned ones.
 */

import { sha256 } from "@noble/hashes/sha2";
import type { StreamSyncFiles } from "./ports.js";

declare const bound: unique symbol;

export interface StreamSyncHome {
  /** Brand: only `bindStreamSyncHome` makes one. */
  readonly [bound]: true;
  readonly ownerAddress: `0x${string}`;
  readonly network: string;
  /** Stable, opaque name of this (owner, network): a host's location key. */
  readonly id: string;
  readonly files: StreamSyncFiles;
}

/** The network a gateway deployment names: `vana:<chainId>:<origin>`. */
export function streamSyncNetwork(gateway: {
  readonly chainId: number;
  readonly url: string;
}): string {
  return `vana:${gateway.chainId}:${new URL(gateway.url).origin}`;
}

/**
 * 128 bits of SHA-256 over the lower-cased owner and the network, in hex. No
 * raw address or URL appears in a storage name or a log line.
 */
export function streamSyncHomeId(input: {
  readonly ownerAddress: string;
  readonly network: string;
}): string {
  const text = `stream-sync-home-v1\n${input.ownerAddress.toLowerCase()}\n${input.network}`;
  return Array.from(sha256(new TextEncoder().encode(text)).slice(0, 16), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
}

export function bindStreamSyncHome(input: {
  readonly ownerAddress: `0x${string}`;
  readonly network: string;
  /** Files stored at a location derived from `id` (and only from it). */
  readonly open: (id: string) => StreamSyncFiles;
}): StreamSyncHome {
  const id = streamSyncHomeId(input);
  return {
    ownerAddress: input.ownerAddress,
    network: input.network,
    id,
    files: input.open(id),
  } as StreamSyncHome;
}
