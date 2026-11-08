/**
 * §2.1 names.
 *
 *   stream scope:  pdpp.<c>~<ns>.<s>
 *   control scope: pdpp.<c>~<ns>
 *   head blob:     h-<keccak-256 hex of the clear head>
 *   part blob:     g<generation>-p-<sha-256 hex of the clear part>
 *
 * `c` is the manifest connector key. The builders refuse a `c` that contains
 * `.` or `~`; the physical parser takes `c` up to the first `~` (vectors/v1.json
 * pins `pdpp.a.b~` as connector `a.b`), and a dotted physical name never maps to
 * a logical read name. `ns` is 16 lowercase hex characters, or empty for
 * identity-less connectors. After `c`, parse reads `ns` = `([0-9a-f]{16})?`,
 * then the end (control scope) or `.` and a non-empty `s` (stream scope). A scope over 256
 * UTF-8 bytes is a permanent error. Old raw names `pdpp.<c>.<s>` have no `~`
 * and never parse as either physical kind. Logical read names use a separate
 * builder/parser below; the first dot after the prefix separates `c` from `s`.
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

function checkConnector(connector: string): void {
  if (connector === "" || connector.includes("~") || connector.includes(".")) {
    throw new InvalidNameError(
      `connector key must be non-empty and contain no "." or "~": ${JSON.stringify(connector)}`,
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

/**
 * Logical read names have no namespace: `pdpp.<c>.<s>`. A stream may contain
 * dots, but a connector may not, so splitting at the first dot is lossless.
 * Physical-only stream names containing `~` cannot be logical read names.
 * Route-specific path/whitespace checks belong to the route, not this codec.
 */
const LOGICAL_STREAM_SCOPE = /^pdpp\.([^.~]+)\.([^~]+)$/;

export function logicalStreamScope(connector: string, stream: string): string {
  checkConnector(connector);
  if (stream === "" || stream.includes("~")) {
    throw new InvalidNameError(
      "logical stream name must be non-empty and contain no '~'",
    );
  }
  return `${SCOPE_PREFIX}${connector}.${stream}`;
}

export function parseLogicalStreamScope(
  name: string,
): { connector: string; stream: string } | null {
  const match = LOGICAL_STREAM_SCOPE.exec(name);
  return match ? { connector: match[1]!, stream: match[2]! } : null;
}

/** Also catches malformed names containing `~`, which must never reach the SDK. */
export function isPhysicalScope(name: string): boolean {
  return name.includes("~");
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
