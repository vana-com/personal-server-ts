/** Own cleanup before calling code that can acquire resources and throw. */
export class DisposalScope {
  private readonly steps: (() => void | Promise<void>)[] = [];
  private stopping?: Promise<void>;

  defer(step: () => void | Promise<void>): void {
    if (this.stopping) throw new Error("Scope is already disposed");
    this.steps.push(step);
  }

  dispose(): Promise<void> {
    return (this.stopping ??= Promise.resolve().then(async () => {
      const errors: unknown[] = [];
      for (const step of this.steps.reverse()) {
        try {
          await step();
        } catch (error) {
          errors.push(
            ...(error instanceof AggregateError ? error.errors : [error]),
          );
        }
      }
      this.steps.length = 0;
      if (errors.length)
        throw new AggregateError(errors, "Resource disposal failed");
    }));
  }

  async fail(error: unknown): Promise<never> {
    try {
      await this.dispose();
    } catch (cleanup) {
      throw new AggregateError(
        [error, ...(cleanup as AggregateError).errors],
        "Startup and disposal failed",
        { cause: error },
      );
    }
    throw error;
  }
}

/** Synchronous resources use the same attempt-every-step contract. */
export function disposeAll(steps: (() => void)[]): void {
  const errors: unknown[] = [];
  for (const step of steps) {
    try {
      step();
    } catch (error) {
      errors.push(
        ...(error instanceof AggregateError ? error.errors : [error]),
      );
    }
  }
  if (errors.length)
    throw new AggregateError(errors, "Resource disposal failed");
}
