/**
 * §2.1 names.
 *
 *   stream scope:  pdpp.<c>~<ns>.<s>
 *   control scope: pdpp.<c>~<ns>
 *   head blob:     h-<keccak-256 hex of the clear head>
 *   part blob:     g<generation>-p-<sha-256 hex of the clear part>
 *
 * `c` is the manifest connector key; builders refuse `~` and `.`, and parse still reads a name with a dotted `c`, so a name an older client stored stays readable. `ns` is 16
 * lowercase hex characters, or empty for identity-less connectors. Parse
 * takes `c` up to the first `~`, then `ns` = `([0-9a-f]{16})?`, then the end
 * (control scope) or `.` and a non-empty `s` (stream scope). A scope over 256
 * UTF-8 bytes is a permanent error. Old raw names `pdpp.<c>.<s>` have no `~`
 * and never parse as either kind.
 */

import { HEX16, HEX64, NAME_LIMIT_BYTES, utf8Length } from "./bytes.js";
import { InvalidNameError } from "./errors.js";

export const SCOPE_PREFIX = "pdpp.";

export type ParsedScope =
  | {
      readonly kind: "stream";
      readonly connector: string;
      readonly ns: string;
      readonly stream: string;
    }
  | {
      readonly kind: "control";
      readonly connector: string;
      readonly ns: string;
    };

export type ParsedBlobName =
  | { readonly kind: "head"; readonly keccak: string }
  | {
      readonly kind: "part";
      readonly generation: number;
      readonly sha256: string;
    };

const CONNECTOR = /^[^.~]+$/;

function checkConnector(connector: string): void {
  if (!CONNECTOR.test(connector)) {
    throw new InvalidNameError(
      `connector key must be non-empty and contain no "~" or ".": ${JSON.stringify(connector)}`,
    );
  }
}

function checkNs(ns: string): void {
  if (ns !== "" && !HEX16.test(ns)) {
    throw new InvalidNameError(
      `ns must be empty or 16 lowercase hex characters: ${JSON.stringify(ns)}`,
    );
  }
}

function checkLength(name: string): string {
  if (utf8Length(name) > NAME_LIMIT_BYTES) {
    throw new InvalidNameError(
      `scope is longer than ${NAME_LIMIT_BYTES} bytes: ${JSON.stringify(name)}`,
    );
  }
  return name;
}

export function controlScope(connector: string, ns: string): string {
  checkConnector(connector);
  checkNs(ns);
  return checkLength(`${SCOPE_PREFIX}${connector}~${ns}`);
}

export function streamScope(
  connector: string,
  ns: string,
  stream: string,
): string {
  checkConnector(connector);
  checkNs(ns);
  if (stream === "") throw new InvalidNameError("stream name is empty");
  return checkLength(`${SCOPE_PREFIX}${connector}~${ns}.${stream}`);
}

/** `null` for any name that is not a stream-sync scope. */
export function parseScope(name: string): ParsedScope | null {
  if (!name.startsWith(SCOPE_PREFIX)) return null;
  if (utf8Length(name) > NAME_LIMIT_BYTES) return null;
  const rest = name.slice(SCOPE_PREFIX.length);
  const tilde = rest.indexOf("~");
  if (tilde <= 0) return null;
  const connector = rest.slice(0, tilde);
  let tail = rest.slice(tilde + 1);
  let ns = "";
  const candidate = tail.slice(0, 16);
  if (HEX16.test(candidate)) {
    ns = candidate;
    tail = tail.slice(16);
  }
  if (tail === "") return { kind: "control", connector, ns };
  if (tail[0] !== "." || tail.length === 1) return null;
  return { kind: "stream", connector, ns, stream: tail.slice(1) };
}

export function headBlobName(keccakHex: string): string {
  const hex = keccakHex.startsWith("0x") ? keccakHex.slice(2) : keccakHex;
  if (!HEX64.test(hex)) {
    throw new InvalidNameError(
      `head hash is not 64 lowercase hex characters: ${keccakHex}`,
    );
  }
  return `h-${hex}`;
}

export function partBlobName(generation: number, sha256Hex: string): string {
  checkGeneration(generation);
  if (!HEX64.test(sha256Hex)) {
    throw new InvalidNameError(
      `part hash is not 64 lowercase hex characters: ${sha256Hex}`,
    );
  }
  return `g${generation}-p-${sha256Hex}`;
}

const HEAD_BLOB = /^h-([0-9a-f]{64})$/;
const PART_BLOB = /^g([1-9][0-9]*)-p-([0-9a-f]{64})$/;

/** `null` for any name that is not a head or part blob name. */
export function parseBlobName(name: string): ParsedBlobName | null {
  const head = HEAD_BLOB.exec(name);
  if (head) return { kind: "head", keccak: head[1]! };
  const part = PART_BLOB.exec(name);
  if (!part) return null;
  const generation = Number(part[1]);
  if (!Number.isSafeInteger(generation)) return null;
  return { kind: "part", generation, sha256: part[2]! };
}

export function checkGeneration(generation: number): void {
  if (!Number.isSafeInteger(generation) || generation < 1) {
    throw new InvalidNameError(
      `generation must be a positive safe integer, got ${String(generation)}`,
    );
  }
}
