/**
 * The declared shape of a question's answer.
 *
 * Without one an answer is free text, so a builder can ask for anything the
 * prompt saw and get it back verbatim in a string field. A registration may
 * instead declare, up front, the fields its answer is made of; the compute
 * step then instructs the model to answer in that shape and validates the
 * reply against it, so a 1-5 score is a number between 1 and 5 and not a
 * field the raw conversations can be poured into. The declaration is part
 * of what the owner approves, which is also what makes a later recompute
 * the same promise: a new version matches the shape the old one did.
 *
 * The grammar is deliberately tiny and flat: a list of named fields with a
 * primitive type and a couple of constraints, no nesting and no free-text
 * keys. Everything a builder can put in it is bounded (see the limits
 * below), so a shape cannot be used to smuggle a second prompt past the
 * 8000-character cap on the question text.
 */

import { z } from "zod";
import { DerivativeQuestionInvalidError } from "../errors/catalog.js";

export type AnswerFieldType =
  "string" | "number" | "integer" | "boolean" | "enum";

export const MAX_ANSWER_SHAPE_FIELDS = 16;
export const MAX_ANSWER_FIELD_NAME_CHARS = 64;
/** Also the cap on a declared `maxLength`, and the default when none is. */
export const MAX_ANSWER_STRING_CHARS = 4_000;
export const MAX_ANSWER_ENUM_VALUES = 32;
export const MAX_ANSWER_ENUM_VALUE_CHARS = 64;

/** Field names are identifiers: they go into the prompt verbatim. */
const FIELD_NAME = /^[A-Za-z][A-Za-z0-9_]*$/;

/**
 * One field of the answer. `required` and (for strings) `maxLength` are
 * always resolved, so the stored shape says exactly what is enforced even
 * when the registration left them out.
 */
export interface AnswerShapeField {
  name: string;
  type: AnswerFieldType;
  required: boolean;
  /** `string` only; defaults to MAX_ANSWER_STRING_CHARS. */
  maxLength?: number;
  /** `number` and `integer` only. */
  min?: number;
  max?: number;
  /** `enum` only; 1 to MAX_ANSWER_ENUM_VALUES distinct values. */
  values?: string[];
}

export interface AnswerShape {
  fields: AnswerShapeField[];
}

const FIELD_TYPES: readonly AnswerFieldType[] = [
  "string",
  "number",
  "integer",
  "boolean",
  "enum",
];

/** Keys accepted on a field, by type. Anything else is refused. */
const KEYS_BY_TYPE: Record<AnswerFieldType, readonly string[]> = {
  string: ["name", "type", "required", "maxLength"],
  number: ["name", "type", "required", "min", "max"],
  integer: ["name", "type", "required", "min", "max"],
  boolean: ["name", "type", "required"],
  enum: ["name", "type", "required", "values"],
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function invalid(message: string, details: Record<string, unknown>): never {
  throw new DerivativeQuestionInvalidError(message, {
    field: "answerShape",
    ...details,
  });
}

function parseFieldName(value: unknown, index: number): string {
  if (typeof value !== "string" || value === "") {
    invalid(`answerShape.fields[${index}].name must be a non-empty string`, {
      index,
    });
  }
  if (value.length > MAX_ANSWER_FIELD_NAME_CHARS) {
    invalid(
      `answerShape.fields[${index}].name is ${value.length} characters; the maximum is ${MAX_ANSWER_FIELD_NAME_CHARS}`,
      { index, max: MAX_ANSWER_FIELD_NAME_CHARS },
    );
  }
  if (!FIELD_NAME.test(value)) {
    invalid(
      `answerShape.fields[${index}].name must start with a letter and hold only letters, digits and underscores`,
      { index },
    );
  }
  return value;
}

function parseBound(
  value: unknown,
  index: number,
  key: "min" | "max",
  integer: boolean,
): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    invalid(`answerShape.fields[${index}].${key} must be a finite number`, {
      index,
      key,
    });
  }
  if (integer && !Number.isSafeInteger(value)) {
    invalid(
      `answerShape.fields[${index}].${key} must be a safe integer for an integer field`,
      { index, key },
    );
  }
  return value;
}

function parseEnumValues(value: unknown, index: number): string[] {
  if (!Array.isArray(value) || value.length === 0) {
    invalid(
      `answerShape.fields[${index}].values must be a non-empty array of strings`,
      { index },
    );
  }
  if (value.length > MAX_ANSWER_ENUM_VALUES) {
    invalid(
      `answerShape.fields[${index}].values lists ${value.length} values; the maximum is ${MAX_ANSWER_ENUM_VALUES}`,
      { index, max: MAX_ANSWER_ENUM_VALUES },
    );
  }
  const values: string[] = [];
  for (const entry of value) {
    if (typeof entry !== "string" || entry === "") {
      invalid(
        `answerShape.fields[${index}].values must hold non-empty strings`,
        { index },
      );
    }
    if (entry.length > MAX_ANSWER_ENUM_VALUE_CHARS) {
      invalid(
        `answerShape.fields[${index}].values holds a ${entry.length} character value; the maximum is ${MAX_ANSWER_ENUM_VALUE_CHARS}`,
        { index, max: MAX_ANSWER_ENUM_VALUE_CHARS },
      );
    }
    // Enum values are the one place a builder writes free text into the
    // prompt. Line breaks would let a value pose as its own instruction
    // line in the shape description, so they are refused outright.
    if (/[\n\r\t]/.test(entry)) {
      invalid(
        `answerShape.fields[${index}].values must not hold line breaks or tabs`,
        { index },
      );
    }
    if (values.includes(entry)) {
      invalid(
        `answerShape.fields[${index}].values lists the same value twice`,
        { index },
      );
    }
    values.push(entry);
  }
  return values;
}

function parseField(value: unknown, index: number): AnswerShapeField {
  if (!isRecord(value)) {
    invalid(`answerShape.fields[${index}] must be an object`, { index });
  }
  const name = parseFieldName(value.name, index);
  if (
    typeof value.type !== "string" ||
    !FIELD_TYPES.includes(value.type as AnswerFieldType)
  ) {
    invalid(
      `answerShape.fields[${index}].type must be one of ${FIELD_TYPES.join(", ")}`,
      { index },
    );
  }
  const type = value.type as AnswerFieldType;
  const allowed = KEYS_BY_TYPE[type];
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) {
      invalid(
        `answerShape.fields[${index}] does not accept "${key}" on a ${type} field`,
        { index, key: key.slice(0, MAX_ANSWER_FIELD_NAME_CHARS) },
      );
    }
  }
  // A declared field is part of the promise, so it is required unless the
  // registration says otherwise.
  let required = true;
  if (value.required !== undefined && value.required !== null) {
    if (typeof value.required !== "boolean") {
      invalid(`answerShape.fields[${index}].required must be a boolean`, {
        index,
      });
    }
    required = value.required;
  }
  const field: AnswerShapeField = { name, type, required };
  if (type === "string") {
    let maxLength = MAX_ANSWER_STRING_CHARS;
    if (value.maxLength !== undefined && value.maxLength !== null) {
      if (
        typeof value.maxLength !== "number" ||
        !Number.isSafeInteger(value.maxLength) ||
        value.maxLength < 1 ||
        value.maxLength > MAX_ANSWER_STRING_CHARS
      ) {
        invalid(
          `answerShape.fields[${index}].maxLength must be an integer between 1 and ${MAX_ANSWER_STRING_CHARS}`,
          { index, max: MAX_ANSWER_STRING_CHARS },
        );
      }
      maxLength = value.maxLength;
    }
    field.maxLength = maxLength;
  }
  if (type === "number" || type === "integer") {
    const integer = type === "integer";
    if (value.min !== undefined && value.min !== null) {
      field.min = parseBound(value.min, index, "min", integer);
    }
    if (value.max !== undefined && value.max !== null) {
      field.max = parseBound(value.max, index, "max", integer);
    }
    if (
      field.min !== undefined &&
      field.max !== undefined &&
      field.min > field.max
    ) {
      invalid(`answerShape.fields[${index}].min is greater than its max`, {
        index,
      });
    }
  }
  if (type === "enum") {
    field.values = parseEnumValues(value.values, index);
  }
  return field;
}

/**
 * Validate the optional `answerShape` of a registration body. Absent (or
 * null, like `model`) means free text, the original behavior.
 */
export function parseAnswerShapeInput(value: unknown): AnswerShape | null {
  if (value === undefined || value === null) return null;
  if (!isRecord(value)) {
    invalid("answerShape must be an object with a fields array", {});
  }
  for (const key of Object.keys(value)) {
    if (key !== "fields") {
      invalid(`answerShape does not accept "${key}"`, {
        key: key.slice(0, MAX_ANSWER_FIELD_NAME_CHARS),
      });
    }
  }
  if (!Array.isArray(value.fields) || value.fields.length === 0) {
    invalid("answerShape.fields must be a non-empty array", {});
  }
  if (value.fields.length > MAX_ANSWER_SHAPE_FIELDS) {
    invalid(
      `answerShape.fields lists ${value.fields.length} fields; the maximum is ${MAX_ANSWER_SHAPE_FIELDS}`,
      { max: MAX_ANSWER_SHAPE_FIELDS },
    );
  }
  const fields: AnswerShapeField[] = [];
  const names = new Set<string>();
  value.fields.forEach((entry, index) => {
    const field = parseField(entry, index);
    if (names.has(field.name)) {
      invalid(`answerShape.fields names "${field.name}" twice`, { index });
    }
    names.add(field.name);
    fields.push(field);
  });
  return { fields };
}

export type CompiledAnswerShape = z.ZodType<Record<string, unknown>>;

/**
 * Compile the declaration to the zod schema the reply is checked against.
 * The object STRIPS unknown keys rather than refusing them: a model that
 * adds chatter next to the declared fields still produces a valid answer,
 * and the extra key never reaches the record.
 */
export function compileAnswerShape(shape: AnswerShape): CompiledAnswerShape {
  const entries: Record<string, z.ZodType> = {};
  for (const field of shape.fields) {
    let schema: z.ZodType;
    switch (field.type) {
      case "string":
        schema = z.string().max(field.maxLength ?? MAX_ANSWER_STRING_CHARS);
        break;
      case "number":
      case "integer": {
        // zod rejects NaN and Infinity for `number` already, so the bounds
        // are the only thing left to apply.
        let numeric = field.type === "integer" ? z.int() : z.number();
        if (field.min !== undefined) numeric = numeric.min(field.min);
        if (field.max !== undefined) numeric = numeric.max(field.max);
        schema = numeric;
        break;
      }
      case "boolean":
        schema = z.boolean();
        break;
      case "enum":
        schema = z.enum(field.values ?? []);
        break;
    }
    entries[field.name] = field.required ? schema : schema.nullish();
  }
  return z.object(entries) as CompiledAnswerShape;
}

export type AnswerShapeValidation =
  | { ok: true; value: Record<string, unknown> }
  | { ok: false; issues: string[] };

/**
 * Check one candidate answer object against a compiled shape. On success
 * the value is rebuilt in declaration order with the optional fields the
 * model left out (or nulled) dropped, so the stored value has one form.
 */
export function validateAnswerShape(
  shape: AnswerShape,
  compiled: CompiledAnswerShape,
  candidate: unknown,
): AnswerShapeValidation {
  const parsed = compiled.safeParse(candidate);
  if (!parsed.success) {
    return {
      ok: false,
      // zod's messages state the constraint ("expected int", "<=5") and
      // never echo the received value, so they are safe to hand back to
      // the model in the corrective turn.
      issues: parsed.error.issues.map((issue) => {
        const path = issue.path.join(".");
        return path ? `${path}: ${issue.message}` : issue.message;
      }),
    };
  }
  const value: Record<string, unknown> = {};
  for (const field of shape.fields) {
    const entry = parsed.data[field.name];
    if (entry === undefined || entry === null) continue;
    value[field.name] = entry;
  }
  return { ok: true, value };
}

function describeField(field: AnswerShapeField): string {
  const requirement = field.required ? "required" : "optional";
  switch (field.type) {
    case "string":
      return `"${field.name}": string, at most ${field.maxLength ?? MAX_ANSWER_STRING_CHARS} characters (${requirement})`;
    case "number":
    case "integer": {
      const kind = field.type === "integer" ? "integer" : "number";
      const range =
        field.min !== undefined && field.max !== undefined
          ? ` between ${field.min} and ${field.max}`
          : field.min !== undefined
            ? ` of at least ${field.min}`
            : field.max !== undefined
              ? ` of at most ${field.max}`
              : "";
      return `"${field.name}": ${kind}${range} (${requirement})`;
    }
    case "boolean":
      return `"${field.name}": true or false (${requirement})`;
    case "enum":
      return `"${field.name}": exactly one of ${(field.values ?? [])
        .map((entry) => JSON.stringify(entry))
        .join(", ")} (${requirement})`;
  }
}

/** The shape as prompt lines, one per field, in declaration order. */
export function describeAnswerShape(shape: AnswerShape): string[] {
  return shape.fields.map((field) => `  ${describeField(field)}`);
}

/**
 * The human-readable rendering kept in the record's `answer` string. The
 * structured value next to it is authoritative; this is what a reader that
 * only knows the old free-text field sees.
 */
export function renderShapedAnswer(
  shape: AnswerShape,
  value: Record<string, unknown>,
): string {
  return shape.fields
    .filter((field) => value[field.name] !== undefined)
    .map((field) => `${field.name}: ${String(value[field.name])}`)
    .join("\n");
}

/** Deep copy, so a stored shape is never aliased by a view or a caller. */
export function cloneAnswerShape(
  shape: AnswerShape | null,
): AnswerShape | null {
  if (!shape) return null;
  return {
    fields: shape.fields.map((field) => ({
      ...field,
      ...(field.values ? { values: [...field.values] } : {}),
    })),
  };
}
