/**
 * A pure coverage check for a latest legacy body and its canonical projection.
 * Entity arrays use stable keys. Same-time comparisons retain relative order;
 * newer canonical state may reorder or, with proof, delete entities.
 * Diagnostics contain paths and counts, never entity keys or field values.
 */
import type { ProjectionOmission } from "../legacy-projection/types.js";
import { LEGACY_COVERAGE_EXCEPTIONS } from "./legacy-scope-coverage-exceptions.js";

export interface LegacyCoverageSchema {
  type?: string | readonly string[];
  properties?: Record<string, LegacyCoverageSchema>;
  items?: LegacyCoverageSchema;
  schema?: LegacyCoverageSchema;
}

export interface LegacyCoverageOptions {
  /** Scope being compared. */
  scope?: string;
  /** Raw-value-backed omissions emitted by this exact canonical projection. */
  projectionOmissions?: readonly ProjectionOmission[];
  /** JSON paths to entity arrays; [] marks each array element, e.g. $.posts[].comments. */
  entityKeys?: Readonly<Record<string, readonly string[]>>;
  /** Legacy payload schema. An `id` or `uuid` item field supplies a key. */
  schema?: LegacyCoverageSchema;
  /** Maximum canonical/legacy byte ratio before payload growth can refuse takeover. Default 1.5. */
  maxPayloadRatio?: number;
  /** Minimum extra bytes required before payload growth can refuse takeover. Default 256 KiB. */
  maxExtraBytes?: number;
  /** True only when the canonical state is known to follow the legacy head. */
  canonicalNewer?: boolean;
  /** True only with accepted completion proof for a replacement newer than the legacy head. */
  allowProvenDeletion?: boolean;
}

export type LegacyCoverageReason =
  | "no_stable_key"
  | "missing_entity"
  | "missing_field"
  | "field_mismatch"
  | "type_mismatch"
  | "timestamp_format"
  | "identity_mismatch"
  | "creation_mismatch"
  | "array_order"
  | "payload_growth"
  | "missing_raw_blob"
  | "projection_unavailable";

export interface LegacyCoverageVerdict {
  comparisonCase: "same_time" | "canonical_newer";
  covered: boolean;
  reason: LegacyCoverageReason | null;
  /** Counts include accepted proven deletions, which do not block coverage. */
  reasonCounts: Record<LegacyCoverageReason, number>;
  /** Reviewed legacy defects and provenance-backed omissions used in this evaluation. */
  appliedExceptions: {
    path: string;
    reason: string;
    authority: "canonical";
  }[];
  missingEntityCount: number;
  mismatchedFieldPaths: string[];
  legacyBytes: number;
  canonicalBytes: number;
  byteDelta: number;
}

type JsonObject = Record<string, unknown>;

const METADATA_FIELDS = new Set([
  "fetched_at",
  "collectedAt",
  "collected_at",
  "synced_at",
]);
const CREATION_FIELDS = new Set([
  "created_at",
  "createdAt",
  "createdTime",
  "creationTime",
  "create_time",
  "creationDate",
  "dateCreated",
  "creation_time",
]);

function jsonType(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value === "object" ? "object" : typeof value;
}

function timestampFormat(value: unknown): string {
  if (typeof value === "number") return "epoch_number";
  if (typeof value !== "string") return jsonType(value);
  if (/^\d{4}-\d{2}-\d{2}$/.test(value)) return "date_only";
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(value)) return "iso_datetime";
  return "other_string";
}

function isTimestampLikeValue(value: unknown): boolean {
  const format = timestampFormat(value);
  return format === "iso_datetime" || format === "date_only";
}

function sameIsoInstantAtMillisecond(
  legacy: unknown,
  canonical: unknown,
): boolean {
  if (
    timestampFormat(legacy) !== "iso_datetime" ||
    timestampFormat(canonical) !== "iso_datetime"
  ) {
    return false;
  }
  const legacyMilliseconds = Date.parse(legacy as string);
  const canonicalMilliseconds = Date.parse(canonical as string);
  return (
    Number.isFinite(legacyMilliseconds) &&
    Number.isFinite(canonicalMilliseconds) &&
    legacyMilliseconds === canonicalMilliseconds
  );
}

function isTimestampField(field: string): boolean {
  return /(?:^date$|Date$|_date$|^time$|Time$|_time$|At$|_at$|timestamp|Timestamp$)/.test(
    field,
  );
}

function isCreationField(field: string): boolean {
  return (
    CREATION_FIELDS.has(field) ||
    /(?:^|_)created(?:_at|_on|_time|_date)?$/.test(field) ||
    /Created(?:At|On|Time|Date)?$/.test(field)
  );
}

function isIdentityField(field: string): boolean {
  return field === "id" || field === "uuid" || /(?:Id|_id)$/.test(field);
}

function object(value: unknown): value is JsonObject {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function stableKey(value: unknown, fields: readonly string[]): string | null {
  if (!object(value) || fields.length === 0) return null;
  const parts: (string | number | boolean)[] = [];
  for (const field of fields) {
    const part = value[field];
    if (
      (typeof part !== "string" &&
        typeof part !== "number" &&
        typeof part !== "boolean") ||
      part === "" ||
      (typeof part === "number" && !Number.isFinite(part))
    ) {
      return null;
    }
    parts.push(part);
  }
  return JSON.stringify(parts);
}

function schemaKeys(
  schema: LegacyCoverageSchema | undefined,
): readonly string[] {
  const properties = schema?.items?.properties;
  if (properties?.id) return ["id"];
  if (properties?.uuid) return ["uuid"];
  return [];
}

/** Compare JSON payloads, not file envelopes: metadata is outside the coverage rule. */
export function compareLegacyCoverage(
  legacyPayload: unknown,
  canonicalPayload: unknown,
  options: LegacyCoverageOptions = {},
): LegacyCoverageVerdict {
  const legacyBytes = new TextEncoder().encode(
    JSON.stringify(legacyPayload),
  ).length;
  const canonicalBytes = new TextEncoder().encode(
    JSON.stringify(canonicalPayload),
  ).length;
  const byteDelta = canonicalBytes - legacyBytes;
  const comparisonCase = options.canonicalNewer
    ? "canonical_newer"
    : "same_time";
  const deletionAllowed =
    options.canonicalNewer === true && options.allowProvenDeletion === true;
  const paths = new Set<string>();
  const appliedExceptions = new Map<
    string,
    LegacyCoverageVerdict["appliedExceptions"][number]
  >();
  const blockedReasons = new Set<LegacyCoverageReason>();
  const reasonCounts: Record<LegacyCoverageReason, number> = {
    no_stable_key: 0,
    missing_entity: 0,
    missing_field: 0,
    field_mismatch: 0,
    type_mismatch: 0,
    timestamp_format: 0,
    identity_mismatch: 0,
    creation_mismatch: 0,
    array_order: 0,
    payload_growth: 0,
    missing_raw_blob: 0,
    projection_unavailable: 0,
  };
  let missingEntityCount = 0;

  function mark(
    reason: LegacyCoverageReason,
    path?: string,
    blocks = true,
    count = 1,
  ): void {
    reasonCounts[reason] += count;
    if (blocks) blockedReasons.add(reason);
    if (path) paths.add(path);
  }

  function compare(
    legacy: unknown,
    canonical: unknown,
    path: string,
    arrayPath: string,
    schema: LegacyCoverageSchema | undefined,
    field: string | undefined = undefined,
    identityFields: readonly string[] = [],
    entityPath?: string,
    entityKey?: string | number | boolean,
  ): void {
    if (jsonType(legacy) !== jsonType(canonical)) {
      mark("type_mismatch", path);
      return;
    }
    if (Array.isArray(legacy)) {
      // Equal JSON types above establish that canonical is an array.
      if (!Array.isArray(canonical)) return;
      const entityFields =
        options.entityKeys?.[arrayPath] ?? schemaKeys(schema);
      if (
        legacy.length === 0 ||
        legacy.some((item) => item !== null && typeof item === "object")
      ) {
        // There are no old entity keys to lose from an empty array. Newer
        // entities are additions under the same rule as a nonempty array.
        if (legacy.length === 0) {
          if (entityFields.length > 0) return;
        } else {
          const fields = entityFields;
          if (fields.length === 0) {
            mark("no_stable_key", path);
            return;
          }
          const legacyKeys = new Set<string>();
          const canonicalPositions = new Map<string, number>();
          for (const item of legacy) {
            const key = stableKey(item, fields);
            if (key === null || legacyKeys.has(key)) {
              mark("no_stable_key", path);
              return;
            }
            legacyKeys.add(key);
          }
          for (const [index, item] of canonical.entries()) {
            const key = stableKey(item, fields);
            if (key === null) continue;
            if (canonicalPositions.has(key)) {
              mark("no_stable_key", path);
              return;
            }
            canonicalPositions.set(key, index);
          }
          let lastPosition = -1;
          for (const [index, item] of legacy.entries()) {
            const key = stableKey(item, fields);
            // Every legacy key was checked above.
            const position = canonicalPositions.get(key!);
            if (position === undefined) {
              missingEntityCount += 1;
              mark("missing_entity", undefined, !deletionAllowed);
              continue;
            }
            if (!options.canonicalNewer && position < lastPosition)
              mark("array_order", path);
            lastPosition = position;
            compare(
              item,
              canonical[position],
              `${path}[${index}]`,
              `${arrayPath}[]`,
              schema?.items,
              undefined,
              fields,
              `${arrayPath}[]`,
              fields.length === 1 &&
                object(item) &&
                (typeof item[fields[0]!] === "string" ||
                  typeof item[fields[0]!] === "number" ||
                  typeof item[fields[0]!] === "boolean")
                ? (item[fields[0]!] as string | number | boolean)
                : undefined,
            );
          }
          return;
        }
      }

      if (legacy.length === 0) {
        if (!options.canonicalNewer && canonical.length > 0)
          mark("array_order", path);
        return;
      }

      // Scalar values have no identity key, so newer state must retain the
      // legacy multiset. Same-time state must retain the exact sequence.
      const encoded = (value: unknown): string => {
        const timestampLike =
          (field !== undefined && isTimestampField(field)) ||
          isTimestampLikeValue(value);
        if (timestampLike && timestampFormat(value) === "iso_datetime") {
          const milliseconds = Date.parse(value as string);
          if (Number.isFinite(milliseconds))
            return `iso_datetime:${milliseconds}`;
        }
        return JSON.stringify(value);
      };
      const available = canonical.map(encoded);
      const expected = legacy.map(encoded);
      const expectedTypes = new Set(legacy.map(jsonType));
      if (canonical.some((value) => !expectedTypes.has(jsonType(value)))) {
        mark("type_mismatch", path);
        return;
      }
      if (
        field !== undefined &&
        isTimestampField(field) &&
        canonical.some((value) => {
          const expectedFormats = new Set(legacy.map(timestampFormat));
          return !expectedFormats.has(timestampFormat(value));
        })
      ) {
        mark("timestamp_format", path);
        return;
      }
      // Value corrections cannot replace missing slots or waive cardinality.
      if (canonical.length < legacy.length) {
        const missing = legacy.length - canonical.length;
        missingEntityCount += missing;
        mark("missing_entity", path, true, missing);
        return;
      }
      if (!options.canonicalNewer && canonical.length !== legacy.length) {
        mark("array_order", path);
        return;
      }
      const counts = new Map<string | undefined, number>();
      for (const item of available)
        counts.set(item, (counts.get(item) ?? 0) + 1);
      let missingValues = 0;
      let hadMissingValue = false;
      for (const [index, item] of expected.entries()) {
        const count = counts.get(item) ?? 0;
        if (count !== 0) {
          counts.set(item, count - 1);
          continue;
        }
        hadMissingValue = true;
        missingValues += 1;
        const legacyValue = legacy[index];
        const hasTypeMismatch = canonical.some(
          (value) => jsonType(value) !== jsonType(legacyValue),
        );
        const hasTimestampFormatMismatch = canonical.some(
          (value) =>
            jsonType(value) === jsonType(legacyValue) &&
            ((field !== undefined && isTimestampField(field)) ||
              isTimestampLikeValue(legacyValue) ||
              isTimestampLikeValue(value)) &&
            timestampFormat(value) !== timestampFormat(legacyValue),
        );
        if (hasTypeMismatch) {
          mark("type_mismatch", path);
          missingValues -= 1;
        } else if (hasTimestampFormatMismatch) {
          mark("timestamp_format", path);
          missingValues -= 1;
        } else if (field && isCreationField(field)) {
          const normalizedPath = path.replace(/\[\d+\]/g, "[]");
          const exception = LEGACY_COVERAGE_EXCEPTIONS.find(
            (entry) =>
              entry.scope === options.scope && entry.path === normalizedPath,
          );
          const canonicalValue = canonical[index];
          if (
            exception &&
            canonicalValue !== undefined &&
            canonicalValue !== null &&
            canonicalValue !== "" &&
            jsonType(canonicalValue) === jsonType(legacyValue) &&
            timestampFormat(canonicalValue) === timestampFormat(legacyValue)
          ) {
            appliedExceptions.set(normalizedPath, {
              path: exception.path,
              reason: exception.reason,
              authority: exception.authority,
            });
          } else {
            mark("creation_mismatch", path);
          }
          missingValues -= 1;
        }
      }
      if (hadMissingValue) {
        missingEntityCount += missingValues;
        // A scalar has no stable entity identity. Completion proof cannot
        // distinguish a deleted value from a changed value in this array.
        if (missingValues > 0)
          mark("missing_entity", path, true, missingValues);
        return;
      }
      if (options.canonicalNewer) return;
      if (
        expected.length !== available.length ||
        expected.some((item, index) => item !== available[index])
      )
        mark("array_order", path);
      return;
    }

    if (object(legacy)) {
      // Equal JSON types above establish that canonical is an object.
      if (!object(canonical)) return;
      for (const [field, value] of Object.entries(legacy)) {
        if (METADATA_FIELDS.has(field)) continue;
        const childPath = `${path}.${field}`;
        if (!Object.hasOwn(canonical, field)) {
          // Omission evidence names a path relative to its entity. Match the
          // full relative path so evidence for `timestamp` cannot excuse a
          // nested `contributors.timestamp` on the same entity.
          const schemaPath = `${arrayPath}.${field}`;
          const omission =
            entityPath !== undefined && schemaPath.startsWith(`${entityPath}.`)
              ? options.projectionOmissions?.find(
                  (entry) =>
                    entry.entityPath === entityPath &&
                    entry.entityKey === entityKey &&
                    entry.fieldPath === schemaPath.slice(entityPath.length + 1),
                )
              : undefined;
          if (omission) {
            appliedExceptions.set(schemaPath, {
              path: schemaPath,
              reason: omission.reason,
              authority: "canonical",
            });
          } else {
            mark("missing_field", childPath);
          }
          continue;
        }
        compare(
          value,
          canonical[field],
          childPath,
          `${arrayPath}.${field}`,
          schema?.properties?.[field],
          field,
          identityFields,
          entityPath,
          entityKey,
        );
      }
      return;
    }

    const timestampField =
      field !== undefined &&
      (isTimestampField(field) ||
        isCreationField(field) ||
        isTimestampLikeValue(legacy) ||
        isTimestampLikeValue(canonical));
    if (
      timestampField &&
      timestampFormat(legacy) !== timestampFormat(canonical)
    ) {
      mark("timestamp_format", path);
      return;
    }
    if (
      Object.is(legacy, canonical) ||
      (timestampField && sameIsoInstantAtMillisecond(legacy, canonical))
    ) {
      return;
    }
    if (field && (identityFields.includes(field) || isIdentityField(field))) {
      mark("identity_mismatch", path);
    } else if (field && isCreationField(field)) {
      const normalizedPath = path.replace(/\[\d+\]/g, "[]");
      const exception = LEGACY_COVERAGE_EXCEPTIONS.find(
        (entry) =>
          entry.scope === options.scope && entry.path === normalizedPath,
      );
      if (
        exception &&
        canonical !== undefined &&
        canonical !== null &&
        canonical !== ""
      ) {
        appliedExceptions.set(normalizedPath, {
          path: exception.path,
          reason: exception.reason,
          authority: exception.authority,
        });
        return;
      }
      mark("creation_mismatch", path);
    } else if (!options.canonicalNewer) {
      mark("field_mismatch", path);
    }
  }

  const schema = options.schema?.schema ?? options.schema;
  compare(legacyPayload, canonicalPayload, "$", "$", schema);
  if (
    canonicalBytes > legacyBytes * (options.maxPayloadRatio ?? 1.5) &&
    byteDelta > (options.maxExtraBytes ?? 256 * 1024)
  ) {
    mark("payload_growth");
  }
  const reason =
    (
      [
        "no_stable_key",
        "missing_entity",
        "type_mismatch",
        "timestamp_format",
        "identity_mismatch",
        "creation_mismatch",
        "field_mismatch",
        "missing_field",
        "array_order",
        "payload_growth",
      ] as const
    ).find((candidate) => blockedReasons.has(candidate)) ?? null;
  return {
    comparisonCase,
    covered: reason === null,
    reason,
    reasonCounts,
    appliedExceptions: [...appliedExceptions.values()],
    missingEntityCount,
    mismatchedFieldPaths: [...paths],
    legacyBytes,
    canonicalBytes,
    byteDelta,
  };
}
