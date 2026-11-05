import { InvalidObservationTimeError, InvalidRecordError } from "./errors.js";
import { isPlainObject, type JsonObject } from "./json.js";

/**
 * A record together with the time its run observed it, in milliseconds since
 * the epoch. The time is metadata: it lives beside the record in the file and
 * never inside the record body, so the body stays exactly what the source gave.
 */
export interface StampedRecord {
  readonly record: JsonObject;
  readonly observedAt: number;
}

/** One completed collection run: its records and when it collected them. */
export interface Run {
  readonly records: readonly JsonObject[];
  readonly observedAt: number;
}

export function checkObservedAt(value: unknown, where: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new InvalidObservationTimeError(
      `${where} observation time must be a non-negative integer of milliseconds`,
    );
  }
  return value;
}

/** Give every record of a run the run's observation time. */
export function stampRun(run: Run): StampedRecord[] {
  const observedAt = checkObservedAt(run.observedAt, "run");
  return run.records.map((record) => ({ record, observedAt }));
}

export function plainRecords(stamped: readonly StampedRecord[]): JsonObject[] {
  return stamped.map((entry) => entry.record);
}

export function checkStamped(
  entry: unknown,
  source: "base" | "run",
  index: number,
): StampedRecord {
  if (!isPlainObject(entry) || !isPlainObject(entry["record"])) {
    throw new InvalidRecordError(
      `${source} record ${index} is not a stamped JSON object`,
    );
  }
  checkObservedAt(entry["observedAt"], `${source} record ${index}`);
  return entry as unknown as StampedRecord;
}
