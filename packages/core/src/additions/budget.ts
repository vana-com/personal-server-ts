/** Shared accounting for one owner-wide recovery, including derived documents. */
export class AdditionsBudgetExceeded extends Error {}

export interface ByteBudget {
  readonly signal?: AbortSignal;
  readonly remaining: number;
  readonly remainingMilliseconds?: number;
  charge(bytes?: number): void;
  /** Book an already-completed host receipt even when its deadline expired. */
  recordSpent(bytes: number): void;
}

export class AdditionsBudget implements ByteBudget {
  private used = 0;
  private exhausted = false;
  private readonly deadline: number;
  readonly signal: AbortSignal | undefined;
  constructor(
    private readonly bytes = Infinity,
    milliseconds?: number,
    signal?: AbortSignal,
    private readonly parent?: AdditionsBudget,
  ) {
    if (bytes < 0 || (!Number.isFinite(bytes) && bytes !== Infinity))
      throw new RangeError("Invalid additions byte budget");
    this.deadline = performance.now() + (milliseconds ?? Infinity);
    const timeout =
      milliseconds === undefined
        ? undefined
        : AbortSignal.timeout(milliseconds);
    this.signal =
      signal && timeout
        ? AbortSignal.any([signal, timeout])
        : (signal ?? timeout);
  }
  get remainingMilliseconds() {
    return Math.max(0, this.deadline - performance.now());
  }
  get remaining() {
    return Math.max(0, this.bytes - this.used);
  }
  charge(bytes = 0) {
    this.signal?.throwIfAborted();
    if (performance.now() >= this.deadline) this.exhausted = true;
    if (
      this.exhausted ||
      !Number.isSafeInteger(bytes) ||
      bytes < 0 ||
      bytes > this.remaining
    ) {
      this.exhausted = true;
      throw new AdditionsBudgetExceeded("Additions byte budget exhausted");
    }
    this.used += bytes;
    this.parent?.charge(bytes);
  }
  recordSpent(bytes: number) {
    if (!Number.isSafeInteger(bytes) || bytes < 0) {
      this.exhausted = true;
      throw new AdditionsBudgetExceeded("Invalid additions spent-byte receipt");
    }
    const overflow = bytes > this.remaining;
    // These bytes were actually consumed remotely. Cancellation must not erase
    // them, and every ancestor must observe the receipt before deadline checks.
    this.used += bytes;
    this.parent?.recordSpent(bytes);
    if (overflow) {
      this.exhausted = true;
      throw new AdditionsBudgetExceeded(
        "Additions byte receipt exceeds allowance",
      );
    }
  }
}

/** Cancel the actual response stream on overflow/abort, including absent or lying lengths. */
export async function readBoundedResponse(
  response: Response,
  budget: ByteBudget,
): Promise<Uint8Array> {
  budget.charge();
  const body = response.body;
  if (!body) return new Uint8Array();
  const reader = body.getReader();
  const abort = () => {
    void reader.cancel(budget.signal?.reason).catch(() => {});
  };
  budget.signal?.addEventListener("abort", abort, { once: true });
  try {
    budget.charge();
    const length = response.headers.get("content-length");
    if (
      length !== null &&
      (!/^\d+$/.test(length) || Number(length) > budget.remaining)
    )
      budget.charge(budget.remaining + 1);
    const chunks: Uint8Array[] = [];
    let size = 0;
    while (true) {
      const { done, value } = await reader.read();
      budget.charge();
      if (done) break;
      budget.charge(value.byteLength);
      size += value.byteLength;
      chunks.push(value);
    }
    // Charge the contiguous copy as well as the incoming chunks.
    budget.charge(size);
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return bytes;
  } catch (error) {
    await reader.cancel(error).catch(() => {});
    throw error;
  } finally {
    budget.signal?.removeEventListener("abort", abort);
    reader.releaseLock();
  }
}

export async function readBoundedJson(
  response: Response,
  budget?: ByteBudget,
): Promise<unknown> {
  if (!budget) return response.json();
  const bytes = await readBoundedResponse(response, budget);
  // UTF-16 decoding and JSON object materialization need room too. This bounds
  // input work, not a hard JS heap estimate for arbitrary engine object layouts.
  budget.charge(bytes.byteLength * 3);
  const result: unknown = JSON.parse(new TextDecoder().decode(bytes));
  budget.charge();
  return result;
}
