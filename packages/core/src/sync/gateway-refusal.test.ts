import { describe, expect, it } from "vitest";
import type { DeleteBlockReason } from "../localdb/delete-status.js";
import {
  GATEWAY_ALREADY_DELETED_CODES,
  GATEWAY_HEAD_ABSENT_CODES,
  GATEWAY_REFUSAL_CODES,
  isGatewayAlreadyDeletedCode,
  isGatewayAnswerCode,
  isGatewayHeadAbsentCode,
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

  it("keeps the already-deleted answer apart from the refusals: the scope is retired already", () => {
    expect(GATEWAY_ALREADY_DELETED_CODES).toEqual([
      "owner_stream_head_already_deleted",
    ]);
    for (const code of GATEWAY_ALREADY_DELETED_CODES) {
      expect(isGatewayAlreadyDeletedCode(code)).toBe(true);
      expect(isGatewayAnswerCode(code)).toBe(true);
      expect(isGatewayRefusalCode(code)).toBe(false);
    }
    expect(isGatewayAlreadyDeletedCode("anything")).toBe(false);
    expect(isGatewayAnswerCode("anything")).toBe(false);
  });

  it("keeps the head-absent answer apart from both: nothing was registered to retire, and no retry is blocked by it", () => {
    expect(GATEWAY_HEAD_ABSENT_CODES).toEqual(["owner_stream_head_absent"]);
    for (const code of GATEWAY_HEAD_ABSENT_CODES) {
      expect(isGatewayHeadAbsentCode(code)).toBe(true);
      expect(isGatewayRefusalCode(code)).toBe(false);
      expect(isGatewayAlreadyDeletedCode(code)).toBe(false);
    }
    expect(isGatewayHeadAbsentCode("owner_stream_sync_required")).toBe(false);
    expect(isGatewayHeadAbsentCode(undefined)).toBe(false);
  });
});
