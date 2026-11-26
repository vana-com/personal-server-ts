/**
 * Read-time rewrites of reference values in served record `data`
 * (spec-core §4 "Binary data (blob_ref)" and "Cross-stream references").
 */

/** A §4 `resource_ref`: `{ source_id, stream, record_id }`. */
export function isResourceRef(value: unknown): value is {
  source_id: string;
  stream: string;
  record_id: unknown;
} {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    return false;
  const ref = value as Record<string, unknown>;
  return (
    typeof ref.source_id === "string" &&
    typeof ref.stream === "string" &&
    (typeof ref.record_id === "string" ||
      (Array.isArray(ref.record_id) &&
        ref.record_id.every((part) => typeof part === "string")))
  );
}

/** A §4 `blob_ref`: an object naming a `blob_id`. */
export function isBlobRef(
  value: unknown,
): value is { blob_id: string } & Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    typeof (value as { blob_id?: unknown }).blob_id === "string"
  );
}

/**
 * Serve every `resource_ref` in its redacted form.
 *
 * spec-core §4: the RS serves the resolved form "only when the target is in
 * the referencing record's source and is authorized under the requesting
 * token"; "Otherwise it serves the redacted form, which has exactly
 * `source_id`, `stream`, and `redacted: true`", and "never drops the field
 * that holds it" (§9 RS item 23). This RS does not resolve targets, so every
 * top-level reference is redacted for client and owner tokens alike. The
 * redacted form does not depend on the target, so it never changes between
 * horizons and needs no sync re-return. Nested references are not detected:
 * Core places a reference in a top-level field of `data`.
 */
export function redactResourceRefs(
  data: Record<string, unknown>,
): Record<string, unknown> {
  let out: Record<string, unknown> | undefined;
  for (const [field, value] of Object.entries(data)) {
    if (!isResourceRef(value)) continue;
    out ??= { ...data };
    out[field] = {
      source_id: value.source_id,
      stream: value.stream,
      redacted: true,
    };
  }
  return out ?? data;
}

/**
 * Add `fetch_url` to every top-level `blob_ref`. "A `blob_id` is unique only
 * within one instance, so the `fetch_url` carries the blob's `instance_id`"
 * (spec-core §4; §8 "Get a blob").
 */
export function withBlobFetchUrls(
  data: Record<string, unknown>,
  instance: string,
  blobBase: string,
): Record<string, unknown> {
  let out: Record<string, unknown> | undefined;
  for (const [field, value] of Object.entries(data)) {
    if (!isBlobRef(value)) continue;
    out ??= { ...data };
    out[field] = {
      ...value,
      fetch_url: `${blobBase}/${encodeURIComponent(value.blob_id)}?instance_id=${encodeURIComponent(instance)}`,
    };
  }
  return out ?? data;
}
