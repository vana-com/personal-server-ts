import { DEFAULT_ROOT_PATH } from "./defaults.js";

/**
 * Browser-safe compatibility helper: leaves host paths unchanged.
 * A host with a filesystem performs its own home-directory expansion.
 */
export function expandHomePath(input: string): string {
  return input;
}

/**
 * Returns the configured root path (or the portable default), still unexpanded.
 * The host resolves it to an absolute path when that is supported.
 */
export function resolveRootPath(input?: string): string {
  return expandHomePath(input ?? DEFAULT_ROOT_PATH);
}
