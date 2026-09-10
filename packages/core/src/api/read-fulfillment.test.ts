import { describe, expect, it, vi } from "vitest";
import {
  READ_FULFILLMENT_NONE,
  reportPersonalServerReadDenial,
  reportPersonalServerReadFulfillment,
  type PersonalServerReadFulfillment,
  type PersonalServerReadReporterDeps,
} from "./index.js";

const SERVED: PersonalServerReadFulfillment = {
  builder: "0x1111111111111111111111111111111111111111",
  grantId: "grant-1",
  logId: "log-1",
  outcome: "served",
  scope: "instagram.profile",
  servedAt: "2026-09-09T00:00:00.000Z",
  source: "mcp",
};

const DENIED: PersonalServerReadFulfillment = {
  ...SERVED,
  builder: "0x2222222222222222222222222222222222222222",
  denyReason: "scope_not_granted",
  grantId: READ_FULFILLMENT_NONE,
  logId: "log-2",
  outcome: "denied",
  tool: "read_scope",
};

function deps(
  reporter: PersonalServerReadReporterDeps["readFulfillmentReporter"],
): PersonalServerReadReporterDeps & { warn: ReturnType<typeof vi.fn> } {
  const warn = vi.fn();
  return { logger: { warn }, readFulfillmentReporter: reporter, warn };
}

describe("read fulfillment reporting", () => {
  it("reports a served read", () => {
    const report = vi.fn().mockResolvedValue(undefined);
    reportPersonalServerReadFulfillment(deps({ report }), SERVED);
    expect(report).toHaveBeenCalledWith(SERVED);
  });

  it("skips reads that have no real grant", () => {
    const report = vi.fn().mockResolvedValue(undefined);
    reportPersonalServerReadFulfillment(deps({ report }), {
      ...SERVED,
      grantId: "owner",
    });
    expect(report).not.toHaveBeenCalled();
  });

  it("reports a denial through reportDenied, not report", () => {
    const report = vi.fn().mockResolvedValue(undefined);
    const reportDenied = vi.fn().mockResolvedValue(undefined);
    reportPersonalServerReadDenial(deps({ report, reportDenied }), DENIED);
    expect(reportDenied).toHaveBeenCalledWith(DENIED);
    expect(report).not.toHaveBeenCalled();
  });

  it("reports a denial even though the grant id is none", () => {
    const reportDenied = vi.fn().mockResolvedValue(undefined);
    reportPersonalServerReadDenial(
      deps({ report: vi.fn(), reportDenied }),
      DENIED,
    );
    expect(reportDenied).toHaveBeenCalledTimes(1);
  });

  it("drops denials when the reporter cannot record them", () => {
    expect(() =>
      reportPersonalServerReadDenial(deps({ report: vi.fn() }), DENIED),
    ).not.toThrow();
  });

  it("swallows a rejected report and warns", async () => {
    const context = deps({
      report: vi.fn().mockRejectedValue(new Error("gateway down")),
    });
    reportPersonalServerReadFulfillment(context, SERVED);
    await Promise.resolve();
    await Promise.resolve();
    expect(context.warn).toHaveBeenCalled();
  });

  it("swallows a synchronous throw from reportDenied", () => {
    const context = deps({
      report: vi.fn(),
      reportDenied: vi.fn(() => {
        throw new Error("boom");
      }),
    });
    expect(() => reportPersonalServerReadDenial(context, DENIED)).not.toThrow();
    expect(context.warn).toHaveBeenCalled();
  });
});
