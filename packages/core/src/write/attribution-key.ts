/**
 * Reserved key inside the envelope's `data` record for builder attribution.
 * Mirrors the `$binary` marker convention (contracts/binary.ts). Kept in its
 * own module so browser-safe code (the legacy disclosure decision) can name it
 * without importing the signing machinery.
 */
export const WRITER_ATTRIBUTION_KEY = "$writtenBy" as const;
