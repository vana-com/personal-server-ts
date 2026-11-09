import { describe, expect, it } from "vitest";
import { createModeAuthority } from "./authority.js";
import { legacyFlagEvidence } from "./flag-evidence.js";
import { createMemoryModeRecordStore } from "./memory-record-store.js";

const OWNER = "0x1111111111111111111111111111111111111111";

describe("the old spawn-time flag as evidence", () => {
  const flags = [
    undefined,
    {},
    { write: false },
    { write: true },
    { write: true, refuseLegacyWrites: true },
    { write: false, refuseLegacyWrites: false },
  ];

  // FLAG_MINTS_OFF
  it("never says Off, whatever the flags hold", () => {
    for (const flag of flags) {
      const input = legacyFlagEvidence(flag, OWNER, 1_000);
      expect(input.state, JSON.stringify(flag)).toBe("unknown");
      expect(input.rawStatus).toBeNull();
    }
  });

  // FLAG_MINTS_OFF
  it("leaves the owner unknown when it is the only evidence", async () => {
    for (const flag of flags) {
      const authority = createModeAuthority({
        store: createMemoryModeRecordStore(),
        bootId: "b",
      });
      await authority.ready;
      await authority.submitEvidence(
        legacyFlagEvidence(flag, OWNER, Date.now()),
      );
      expect(authority.read(OWNER).kind, JSON.stringify(flag)).toBe("refuse");
      expect(authority.admit(OWNER, "op").kind).toBe("refuse");
    }
  });
});
