/**
 * P5: validate canonical record `data` against the stream schema of the
 * configured, digest-verified declaration.
 *
 * The schema is the one the registry already serves in §8 stream metadata,
 * resolved by `(instance, stream)`, so writes are checked against the same
 * document the owner consented against. There is no second catalog.
 *
 * §5 fixes the dialect at JSON Schema 2020-12, and `parseDeclaration` refuses
 * any other `$schema` and any remote `$ref` before a declaration is retained.
 * So every schema that reaches this module is compiled as 2020-12. `format`
 * stays an annotation (the 2020-12 default), and an unknown keyword is an
 * annotation too, so validation does not depend on which formats or
 * extensions this build happens to know.
 */

import { Ajv2020, type ValidateFunction } from "ajv/dist/2020.js";
import type {
  RecordDataValidator,
  StreamDeclarationRegistry,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";

/**
 * A validator for every stream the registry declares.
 *
 * A stream whose declaration carries no schema is not checked: a
 * private-shape declaration states no shape to check against. A schema this
 * build cannot compile rejects every upsert of that stream, because an
 * unchecked write would store data the declaration may not permit.
 */
export function createRecordDataValidator(
  declarations: StreamDeclarationRegistry,
): RecordDataValidator {
  const ajv = new Ajv2020({
    allErrors: false,
    strict: false,
    validateFormats: false,
    // Two sources may reuse one `$id`; each schema is compiled on its own.
    addUsedSchema: false,
  });
  const compiled = new WeakMap<object, ValidateFunction | string>();

  function validatorFor(
    schema: Record<string, unknown>,
  ): ValidateFunction | string {
    let entry = compiled.get(schema);
    if (entry === undefined) {
      try {
        entry = ajv.compile(schema);
      } catch (err) {
        entry = `schema_unavailable: ${err instanceof Error ? err.message : String(err)}`;
      }
      compiled.set(schema, entry);
    }
    return entry;
  }

  return (stream, instance, data) => {
    const schema = declarations.forInstance(instance, stream)?.schema;
    if (!schema) return null;
    const validate = validatorFor(schema);
    if (typeof validate === "string") return validate;
    if (validate(data)) return null;
    // `allErrors: false` stops at the first failing keyword, so the reason
    // is the same for the same data and schema on every call.
    const [error] = validate.errors ?? [];
    const path = error ? redactedPath(schema, error.instancePath) : "(root)";
    return `schema_violation: ${path} ${error?.message ?? "does not match the declared schema"}`;
  };
}

/**
 * The failing instance path, with every segment the schema does not name
 * replaced by `*`.
 *
 * Under `additionalProperties` or `patternProperties` a path segment is a key
 * taken from the record data, such as an email address, and reasons reach
 * logs. So a segment is shown only when it is a key of `properties` at that
 * point in the schema, or an index into an array schema. Once the walk cannot
 * follow the schema (a combinator, a non-local `$ref`), every later segment
 * is redacted. The instance root is shown as `(root)`.
 */
function redactedPath(schema: Record<string, unknown>, instancePath: string) {
  if (instancePath === "") return "(root)";
  const segments = instancePath
    .slice(1)
    .split("/")
    .map((s) => s.replace(/~1/g, "/").replace(/~0/g, "~"));
  let node: unknown = schema;
  const shown: string[] = [];
  for (const segment of segments) {
    const current = resolveLocalRef(schema, node);
    const properties = current?.properties as
      Record<string, unknown> | undefined;
    const isArray =
      current !== undefined &&
      (current.type === "array" ||
        "items" in current ||
        "prefixItems" in current);
    if (properties && Object.hasOwn(properties, segment)) {
      shown.push(segment.replace(/~/g, "~0").replace(/\//g, "~1"));
      node = properties[segment];
    } else if (isArray && /^(0|[1-9][0-9]*)$/.test(segment)) {
      shown.push(segment);
      const prefix = current.prefixItems as unknown[] | undefined;
      const index = Number(segment);
      node = prefix && index < prefix.length ? prefix[index] : current.items;
    } else {
      shown.push("*");
      // A data key under `additionalProperties` still has a known schema,
      // unless a `patternProperties` entry could apply instead.
      node =
        current && !("patternProperties" in current)
          ? current.additionalProperties
          : undefined;
    }
  }
  return `/${shown.join("/")}`;
}

function resolveLocalRef(
  root: Record<string, unknown>,
  node: unknown,
): Record<string, unknown> | undefined {
  for (let depth = 0; depth < 32; depth++) {
    if (!node || typeof node !== "object" || Array.isArray(node)) {
      return undefined;
    }
    const ref = (node as Record<string, unknown>).$ref;
    if (typeof ref !== "string") return node as Record<string, unknown>;
    if (!ref.startsWith("#")) return undefined;
    node = ref
      .slice(1)
      .split("/")
      .filter((s) => s !== "")
      .map((s) => decodeURIComponent(s).replace(/~1/g, "/").replace(/~0/g, "~"))
      .reduce<unknown>(
        (at, key) =>
          at && typeof at === "object"
            ? (at as Record<string, unknown>)[key]
            : undefined,
        root,
      );
  }
  return undefined;
}
