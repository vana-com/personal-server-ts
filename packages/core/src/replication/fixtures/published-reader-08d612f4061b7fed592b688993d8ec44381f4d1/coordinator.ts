/**
 * Test adapter copied from the pinned reader's coordinator abortable helper.
 * The fixture does not load the old coordinator's unrelated worker graph.
 */
export function abortable<T>(
  signal: AbortSignal,
  start: () => Promise<T>,
): Promise<T> {
  if (signal.aborted)
    return Promise.reject(
      signal.reason ?? new DOMException("aborted", "AbortError"),
    );
  return new Promise<T>((resolve, reject) => {
    const onAbort = () =>
      reject(signal.reason ?? new DOMException("aborted", "AbortError"));
    signal.addEventListener("abort", onAbort, { once: true });
    start().then(
      (value) => {
        signal.removeEventListener("abort", onAbort);
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener("abort", onAbort);
        reject(error);
      },
    );
  });
}
