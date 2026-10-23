/**
 * The one boundary where untrusted owner-choice input becomes the structures
 * the resolver reads.
 *
 * Choices arrive as JSON (an approval body) or are built from a query string.
 * Either way they are keyed by stream names, which are data. This turns them
 * into copies whose maps have no prototype and whose members are checked, or
 * says why it cannot. Nothing downstream needs to defend against a `null` map,
 * a wrong member type, an inherited `constructor` or a lone surrogate.
 */

import { isWellFormedJson } from "./named.js";
import type { OwnerChoices } from "./resolve.js";

export type OwnerChoiceInput =
  | {
      ok: true;
      ownerChoices: OwnerChoices | undefined;
      instanceChoices: Record<string, string[]> | undefined;
    }
  | { ok: false; message: string };

const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const isStrings = (value: unknown): value is string[] =>
  Array.isArray(value) && value.every((entry) => typeof entry === "string");

/** A prototype-free copy, so `__proto__` is an ordinary key. */
function mapOf<T>(
  source: Record<string, unknown>,
  accept: (value: unknown) => value is T,
): Record<string, T> | undefined {
  const copy: Record<string, T> = Object.create(null);
  for (const [name, value] of Object.entries(source)) {
    if (!accept(value)) return undefined;
    copy[name] = value;
  }
  return copy;
}

function isTimeRange(
  value: unknown,
): value is { since?: string; until?: string } {
  return (
    isObject(value) &&
    (value.since === undefined || typeof value.since === "string") &&
    (value.until === undefined || typeof value.until === "string")
  );
}

export function normalizeOwnerChoiceInput(input: {
  ownerChoices?: unknown;
  instanceChoices?: unknown;
}): OwnerChoiceInput {
  const { ownerChoices, instanceChoices } = input;
  if (!isWellFormedJson(ownerChoices) || !isWellFormedJson(instanceChoices)) {
    return {
      ok: false,
      message: "owner choice names and values must be well-formed Unicode",
    };
  }

  let instances: Record<string, string[]> | undefined;
  if (instanceChoices !== undefined) {
    const copy = isObject(instanceChoices)
      ? mapOf(instanceChoices, isStrings)
      : undefined;
    if (!copy)
      return {
        ok: false,
        message: "instance_choices must map stream names to lists of handles",
      };
    instances = copy;
  }

  if (ownerChoices === undefined) {
    return { ok: true, ownerChoices: undefined, instanceChoices: instances };
  }
  if (!isObject(ownerChoices)) {
    return { ok: false, message: "owner choices must be an object" };
  }

  // Unknown members are left to the profile's own validation; only the
  // members this module's readers touch are checked here.
  const normalized: OwnerChoices = { ...ownerChoices };
  for (const key of ["declined_streams", "approved_streams"] as const) {
    if (ownerChoices[key] !== undefined && !isStrings(ownerChoices[key]))
      return { ok: false, message: `${key} must be a list of stream names` };
  }
  if (ownerChoices.fields !== undefined) {
    const copy = isObject(ownerChoices.fields)
      ? mapOf(ownerChoices.fields, isStrings)
      : undefined;
    if (!copy)
      return {
        ok: false,
        message: "fields must map stream names to lists of field names",
      };
    normalized.fields = copy;
  }
  if (ownerChoices.time_ranges !== undefined) {
    const copy = isObject(ownerChoices.time_ranges)
      ? mapOf(ownerChoices.time_ranges, isTimeRange)
      : undefined;
    if (!copy)
      return {
        ok: false,
        message: "time_ranges must map stream names to since/until bounds",
      };
    normalized.time_ranges = copy;
  }
  return { ok: true, ownerChoices: normalized, instanceChoices: instances };
}
