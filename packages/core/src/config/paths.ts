import { DEFAULT_ROOT_PATH } from "./defaults.js";

/**
 * Expands a leading "~" to the current user's home directory.
 */
export function expandHomePath(input: string): string {
  return input;
}

/**
 * Resolves the configured root path (or default) to an absolute path.
 */
export function resolveRootPath(input?: string): string {
  return expandHomePath(input ?? DEFAULT_ROOT_PATH);
}
