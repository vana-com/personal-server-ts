import { expect, it } from "vitest";
import { DisposalScope } from "./lifecycle.js";

it("disposes in reverse order, attempts every step, and shares concurrent disposal", async () => {
  const scope = new DisposalScope();
  const calls: number[] = [];
  scope.defer(() => {
    calls.push(1);
    throw new Error("first");
  });
  scope.defer(async () => {
    calls.push(2);
    throw new Error("second");
  });
  const stopping = scope.dispose();
  expect(scope.dispose()).toBe(stopping);
  await expect(stopping).rejects.toMatchObject({
    errors: [new Error("second"), new Error("first")],
  });
  expect(calls).toEqual([2, 1]);
});
