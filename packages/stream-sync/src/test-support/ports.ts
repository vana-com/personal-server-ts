import { createHash, createHmac } from "node:crypto";
import { keccak_256 } from "@noble/hashes/sha3";
import type { Keccak256, NamespaceHmac, Sha256 } from "../bytes.js";

interface NodePorts {
  readonly sha256: Sha256;
  readonly keccak256: Keccak256;
  readonly namespaceHmac: (kNs: Uint8Array) => NamespaceHmac;
}

/** Test ports: node:crypto SHA-256 and HMAC, @noble/hashes Keccak-256. */
export const nodePorts: NodePorts = {
  sha256: async (data) =>
    new Uint8Array(createHash("sha256").update(data).digest()),
  keccak256: async (data) => keccak_256(data),
  namespaceHmac: (kNs) => async (message) =>
    new Uint8Array(createHmac("sha256", kNs).update(message).digest()),
};

export const { sha256, keccak256 } = nodePorts;
export const testHmac = nodePorts.namespaceHmac(
  Uint8Array.from({ length: 32 }, (_, i) => i),
);

/** Deterministic PRNG (mulberry32) for property tests. */
export function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function pick<T>(random: () => number, items: readonly T[]): T {
  return items[Math.floor(random() * items.length)]!;
}

export function int(random: () => number, max: number): number {
  return Math.floor(random() * max);
}
