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

  it("keeps current reads and history failures distinguishable at the same status", () => {
    const read = new PdppError("STREAM_READ_UNAVAILABLE", "Read unavailable");
    const history = new PdppError(
      "STREAM_HISTORY_UNAVAILABLE",
      "History unavailable",
    );
    expect([read.status, history.status]).toEqual([503, 503]);
    expect([
      read.toJSON("read-test").error.code,
      history.toJSON("history-test").error.code,
    ]).toEqual(["STREAM_READ_UNAVAILABLE", "STREAM_HISTORY_UNAVAILABLE"]);
  });

  it("uses the supplied request ID on each serialization", () => {
    const error = new PdppError("not_found", "Not found");
    const first = error.toJSON("first-test");
    const second = error.toJSON("second-test");
    expect(first.error.request_id).toBe("first-test");
    expect(second.error.request_id).toBe("second-test");
  });

  it("keeps errors serializable with a generated ID when correlation is missing", () => {
    const error = new PdppError("not_found", "Not found");
    const ids = [undefined, "", "   "].map(
      (requestId) => error.toJSON(requestId).error.request_id,
    );
    expect(ids.every((id) => /^[0-9a-f-]{36}$/i.test(id))).toBe(true);
    expect(new Set(ids).size).toBe(3);
  });

  it("treats inherited object keys as unknown codes", () => {
    for (const code of ["constructor", "toString", "__proto__"]) {
      expect(() => new PdppError(code as never, "x")).toThrow(RangeError);
      const overridden = new PdppError(code as never, "x", { status: 418 });
      expect(overridden.status).toBe(418);
      expect(overridden.type).toBe("api_error");
    }
    expect(new PdppError("not_found", "missing").status).toBe(404);
  });

  it("always uses the catalog status for a known code", () => {
    const err = new PdppError("not_found", "missing", { status: 500 });
    expect(err.status).toBe(404);
    expect(err.type).toBe("not_found_error");
  });

  it("accepts only an integer HTTP error status for an unknown code", () => {
    for (const status of [399, 600, 200, 503.5, Number.NaN, 0, -1]) {
      expect(
        () => new PdppError("future_code" as never, "x", { status }),
      ).toThrow(RangeError);
    }
    for (const status of [400, 503, 599]) {
      expect(
        new PdppError("future_code" as never, "x", { status }).status,
      ).toBe(status);
    }
  });
});
