import { describe, expect, it } from "vitest";
import type { DeleteBlockReason } from "../localdb/delete-status.js";
import {
  GATEWAY_ALREADY_DELETED_CODES,
  GATEWAY_REFUSAL_CODES,
  isGatewayAlreadyDeletedCode,
  isGatewayAnswerCode,
  isGatewayRefusalCode,
} from "./gateway-refusal.js";

describe("the gateway's terminal answers to a tombstone", () => {
  it("has one list: each code is a refusal, an answer the parser reads and a block reason", () => {
    // Compiles only while every refusal code is a block reason.
    const reasons: DeleteBlockReason[] = [...GATEWAY_REFUSAL_CODES];
    expect(reasons.length).toBeGreaterThan(0);
    for (const code of GATEWAY_REFUSAL_CODES) {
      expect(isGatewayRefusalCode(code)).toBe(true);
      expect(isGatewayAnswerCode(code)).toBe(true);
    }
    expect(isGatewayRefusalCode("needs_another_device")).toBe(false);
    expect(isGatewayRefusalCode(undefined)).toBe(false);
  });

  it("keeps the already-deleted answer (data-gateway #212) apart from the refusals, and unnamed until the gateway names it", () => {
    // Empty on purpose: the code name is not fixed, and none is guessed.
    expect(GATEWAY_ALREADY_DELETED_CODES).toEqual([]);
    expect(isGatewayAlreadyDeletedCode("anything")).toBe(false);
    expect(isGatewayAnswerCode("anything")).toBe(false);
  });
});
