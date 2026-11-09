import { describe, expect, it } from "vitest";
import {
  accountModeOf,
  legacyRetireSwitched,
  type AccountModeReader,
} from "./switch.js";

const modeOf = (answers: Record<string, "switched" | "unswitched">) =>
  ({
    read: (owner: string) => answers[owner] ?? "unknown",
  }) satisfies AccountModeReader;

describe("legacyRetireSwitched asks the account-mode authority (SWITCH_READS_FLAG)", () => {
  it("is true only for the owner the authority says is switched", () => {
    const mode = modeOf({ "0xa": "switched", "0xb": "unswitched" });
    expect(legacyRetireSwitched(mode, "0xa")).toBe(true);
    expect(legacyRetireSwitched(mode, "0xb")).toBe(false);
    expect(legacyRetireSwitched(mode, "0xc")).toBe(false); // unknown
  });

  it("follows the authority when its answer changes, not a config flag", () => {
    const answers: Record<string, "switched" | "unswitched"> = {
      "0xa": "unswitched",
    };
    const mode = modeOf(answers);
    expect(legacyRetireSwitched(mode, "0xa")).toBe(false);
    answers["0xa"] = "switched";
    expect(legacyRetireSwitched(mode, "0xa")).toBe(true);
  });
});

describe("the owner reaches the authority in lowercase (OWNER_NOT_LOWERCASED)", () => {
  it("asks for a checksum-cased owner by its lowercase form, in both entry points", () => {
    const asked: string[] = [];
    const mode: AccountModeReader = {
      read: (owner) => {
        asked.push(owner);
        return owner === "0xab" ? "switched" : "unknown"; // exact match
      },
    };
    expect(accountModeOf(mode, "0xAB")).toBe("switched");
    expect(legacyRetireSwitched(mode, "0xAB")).toBe(true);
    expect(asked).toEqual(["0xab", "0xab"]);
  });
});
