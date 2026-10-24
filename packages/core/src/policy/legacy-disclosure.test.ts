import { describe, expect, it } from "vitest";
import { GrantRequiredError } from "../errors/catalog.js";
import { authorizeLegacyRead } from "./legacy-disclosure.js";

const NATIVE = {
  $pdpp: {
    version: 1,
    sourceId: "https://registry.pdpp.dev/sources/oura",
    declaration: { source: "oura", version: "1", digest: "sha256:x" },
    stream: {
      name: "activity",
      scope: "oura.activity",
      primaryKey: ["id"],
      semantics: "mutable_state",
    },
    record: { key: { id: "a" }, op: "upsert" },
  },
};

const stored = (envelope: { data: unknown; producer?: unknown }) => () =>
  authorizeLegacyRead("grantee", { kind: "stored-envelope", envelope });

describe("authorizeLegacyRead: a chain grant reads the legacy form of a covered scope", () => {
  it("serves a real legacy file", () => {
    expect(stored({ data: { days: [] } })).not.toThrow();
  });

  it.each(["pdpp-projector", "pdpp-import-projection"])(
    "serves a legacy-format projection stamped %s",
    (producer) => {
      expect(stored({ data: { days: [] }, producer })).not.toThrow();
    },
  );

  it("refuses canonical PDPP data in its own form, stamped or not", () => {
    expect(stored({ data: { id: "a", ...NATIVE } })).toThrow(
      GrantRequiredError,
    );
    expect(
      stored({ data: { id: "a", ...NATIVE }, producer: "pdpp-projector" }),
    ).toThrow(GrantRequiredError);
  });

  it("refuses malformed native metadata, even under a projection stamp", () => {
    expect(
      stored({ data: { $pdpp: "claimed" }, producer: "pdpp-projector" }),
    ).toThrow(GrantRequiredError);
  });

  it("refuses a derivative of PDPP data", () => {
    expect(
      stored({ data: { answer: 1 }, producer: "pdpp-derivative" }),
    ).toThrow(GrantRequiredError);
  });

  it("leaves the owner unchanged", () => {
    expect(() =>
      authorizeLegacyRead("owner", {
        kind: "stored-envelope",
        envelope: { data: { id: "a", ...NATIVE } },
      }),
    ).not.toThrow();
  });

  describe("the early refusal on the index row", () => {
    const early =
      (entry: { pdppOrigin?: boolean; producer?: string | null }) => () =>
        authorizeLegacyRead("grantee", { kind: "indexed-version", entry });

    it("lets a legacy row and a projection row through to the bytes", () => {
      expect(early({ pdppOrigin: false, producer: null })).not.toThrow();
      expect(
        early({ pdppOrigin: true, producer: "pdpp-projector" }),
      ).not.toThrow();
      expect(
        early({ pdppOrigin: true, producer: "pdpp-import-projection" }),
      ).not.toThrow();
    });

    it("refuses a PDPP row that is not a projection", () => {
      expect(early({ pdppOrigin: true, producer: null })).toThrow(
        GrantRequiredError,
      );
      expect(early({ pdppOrigin: true, producer: "pdpp-derivative" })).toThrow(
        GrantRequiredError,
      );
    });
  });

  describe("an input to the projection of a covered scope", () => {
    const input = (envelope: { data: unknown; producer?: unknown }) => () =>
      authorizeLegacyRead("grantee", { kind: "projection-input", envelope });

    it("accepts legacy data, canonical PDPP data and a projection body", () => {
      expect(input({ data: { records: [] } })).not.toThrow();
      expect(input({ data: { id: "a", ...NATIVE } })).not.toThrow();
      expect(
        input({ data: { days: [] }, producer: "pdpp-projector" }),
      ).not.toThrow();
    });

    it("refuses a derivative, a non-owner publication and malformed metadata", () => {
      expect(
        input({ data: { answer: 1 }, producer: "pdpp-derivative" }),
      ).toThrow(GrantRequiredError);
      expect(input({ data: { $pdpp: "claimed" } })).toThrow(GrantRequiredError);
    });

    it.each(["pdpp-projector", "pdpp-import-projection"])(
      "refuses malformed native metadata under a %s stamp, and accepts valid metadata under it",
      (producer) => {
        expect(input({ data: { $pdpp: "claimed" }, producer })).toThrow(
          GrantRequiredError,
        );
        expect(input({ data: { $pdpp: { version: "1" } }, producer })).toThrow(
          GrantRequiredError,
        );
        expect(input({ data: { id: "a", ...NATIVE }, producer })).not.toThrow();
      },
    );
  });
});
