import { expect, it } from "vitest";
import { resolveLocalInstance } from "./identity.js";
import { identity } from "./fixtures.js";

it("maps one logical connection to explicit device-local handles without merging accounts", () => {
  expect(
    resolveLocalInstance(identity, [
      { ...identity, localInstanceId: "desktop-handle" },
    ]),
  ).toBe("desktop-handle");
  expect(
    resolveLocalInstance(identity, [
      { ...identity, localInstanceId: "phone-handle" },
    ]),
  ).toBe("phone-handle");
  expect(
    resolveLocalInstance({ ...identity, connectionId: "independent" }, [
      { ...identity, localInstanceId: "desktop-handle" },
    ]),
  ).toBeUndefined();
  expect(
    resolveLocalInstance({ ...identity, owner: "other-owner" }, [
      { ...identity, localInstanceId: "desktop-handle" },
    ]),
  ).toBeUndefined();
  expect(() =>
    resolveLocalInstance(identity, [
      { ...identity, localInstanceId: "one" },
      { ...identity, localInstanceId: "two" },
    ]),
  ).toThrow("ambiguous");
  expect(() =>
    resolveLocalInstance(identity, [
      { ...identity, localInstanceId: "one" },
      { ...identity, connectionId: "independent", localInstanceId: "one" },
    ]),
  ).toThrow("independent");
});
