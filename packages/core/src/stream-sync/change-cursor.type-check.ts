// Compile-time proof that a change-feed cursor has no order. `tsc --build`
// fails here if `ChangeCursor` is ever loosened to a `string` or a `number`:
// each line below must be a type error, and an unused `@ts-expect-error` is
// one. Nothing calls this function.
import type { ChangeCursor } from "./ports.js";

export function aCursorHasNoOrder(a: ChangeCursor, b: ChangeCursor): void {
  // @ts-expect-error no ordering
  void (a < b);
  // @ts-expect-error no ordering
  void (a >= b);
  // @ts-expect-error no arithmetic
  void (a + 1);
  // @ts-expect-error no arithmetic
  void (a - b);
  // @ts-expect-error not a number or a decimal string
  void BigInt(a);
  // @ts-expect-error not a string
  void a.length;
  // @ts-expect-error not a string
  void `${a}`;
  // @ts-expect-error a bare string is not a cursor
  const fromString: ChangeCursor = "12";
  // @ts-expect-error a number is not a cursor
  const fromNumber: ChangeCursor = 12;
  void fromString;
  void fromNumber;
  // Equality is what a cursor allows.
  void (a === b);
}
