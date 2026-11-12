/**
 * Opt-in timing marks for finding where a slow stream-sync call waits.
 *
 * Off by default: with no sink set, `mark` does nothing. A host sets one sink
 * (the server writes lines to a file under its logs directory). Each mark is
 * one JSON line with a wall-clock time, so lines from different modules sort
 * into one timeline.
 */
type Fields = Readonly<Record<string, string | number | boolean | null>>;

let sink: ((line: string) => void) | null = null;

export function setTimingSink(next: ((line: string) => void) | null): void {
  sink = next;
}

export function timingEnabled(): boolean {
  return sink !== null;
}

export function mark(event: string, fields: Fields = {}): void {
  if (!sink) return;
  try {
    sink(JSON.stringify({ t: new Date().toISOString(), event, ...fields }));
  } catch {
    // A diagnostic must never change the behavior it observes.
  }
}

/** Run `work`, marking its start, its end with the elapsed time, or its error. */
export async function timed<T>(
  event: string,
  fields: Fields,
  work: () => Promise<T>,
): Promise<T> {
  if (!sink) return work();
  const started = Date.now();
  mark(`${event}.start`, fields);
  try {
    const result = await work();
    mark(`${event}.end`, { ...fields, ms: Date.now() - started });
    return result;
  } catch (error) {
    mark(`${event}.error`, {
      ...fields,
      ms: Date.now() - started,
      error: (error instanceof Error ? error.message : String(error)).slice(
        0,
        160,
      ),
    });
    throw error;
  }
}
