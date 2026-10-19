import { describe, it, expect } from "vitest";
import { PdppError } from "./pdpp-catalog.js";

describe("PdppError", () => {
  it("derives status and type from the code per spec §8", () => {
    const err = new PdppError("cursor_expired", "too old");
    expect(err.status).toBe(410);
    expect(err.type).toBe("gone_error");
  });

  it("serializes to the exact spec §8 error shape", () => {
    const err = new PdppError("grant_stream_not_allowed", "nope", {
      param: "expand[0]",
    });
    const body = err.toJSON("req_123");
    expect(body).toEqual({
      error: {
        type: "permission_error",
        code: "grant_stream_not_allowed",
        message: "nope",
        param: "expand[0]",
        request_id: "req_123",
      },
    });
  });

  it("omits param when not provided", () => {
    const err = new PdppError("not_found", "missing");
    const body = err.toJSON("req_1");
    expect(body.error).not.toHaveProperty("param");
  });
});
