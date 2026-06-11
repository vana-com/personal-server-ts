/**
 * The no-schema registrar now lives in core so the in-browser PS-Lite runtime
 * can register schemas for binary uploads too (see
 * `packages/core/src/api/schema-registrar.ts`). Re-exported here for backwards
 * compatibility with existing server imports.
 */
export {
  createSchemaRegistrar,
  NO_SCHEMA_DEFINITION_URL,
  NO_SCHEMA_DIALECT,
  NO_SCHEMA_NAME,
  type SchemaRegistrarDeps,
} from "@opendatalabs/personal-server-ts-core/api";
