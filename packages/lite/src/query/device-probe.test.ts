/**
 * What the device probe has to hold before it is worth carrying to hardware.
 *
 * A probe is only useful if a human can trust the block it pastes back, so the
 * properties under test are the ones that make the block trustworthy: the four
 * field names design §19.18 named are present and spelled the way §19.18
 * spells them; every field degrades to a *recorded* answer rather than an
 * exception; and the verdict never claims a capability that was not measured.
 *
 * These run the real WASM engine, as `quickjs-sandbox.test.ts` does, because a
 * fake would assert only that the author believed something. They run under
 * Node, which is **not** a WebView — nothing here is evidence about iOS or
 * Android, and the mobile surfaces stay UNVERIFIED (§19.18).
 */

import { describe, expect, it } from "vitest";

import {
  DEVICE_PROBE_NAME,
  formatDeviceProbeReport,
  runDeviceProbe,
} from "./device-probe.js";
import { MAX_STACK_BYTES } from "./quickjs-sandbox.js";

describe("the mobile WASM device probe", () => {
  it("emits the four fields §19.18 says settle the question", async () => {
    const report = await runDeviceProbe();

    // Spelled exactly as §19.18 spells them. A renamed field makes a
    // pasted-back report unanswerable against the design doc.
    expect(report).toHaveProperty("moduleLoad");
    expect(report).toHaveProperty("egressGlobalsPresent");
    expect(report).toHaveProperty("mechanics");
    expect(report.opfs).toHaveProperty("writable");
  });

  it("loads the engine with no second fetch, and times it", async () => {
    // The single-file variant inlines the module as base64, which is the whole
    // reason the probe can run on a WebView origin that cannot serve headers.
    // If this ever needs a network fetch, it will fail here first.
    const report = await runDeviceProbe();
    expect(report.moduleLoad.ok).toBe(true);
    expect(report.moduleLoad.ms).toBeTypeOf("number");
  });

  it("finds no egress globals in the VM", async () => {
    const report = await runDeviceProbe();
    expect(report.egressGlobalsPresent).toEqual([]);
  });

  it("re-asserts the three mechanics the sandbox is built on", async () => {
    const report = await runDeviceProbe();
    expect(report.mechanics).not.toBeNull();
    expect(report.mechanics?.stackLimitAt8MbFailsEval).toBe(true);
    expect(report.mechanics?.memoryLimitRaisesRatherThanNull).toBe(true);
    expect(report.mechanics?.hostErrorReturnValueDoesNotThrow).toBe(true);
    expect(report.mechanics?.maxStackBytes).toBe(MAX_STACK_BYTES);
  });

  it("records a missing capability instead of throwing", async () => {
    // Node has no OPFS. The probe's value is that it still answers the other
    // three fields — a probe that dies on the first absent capability leaves a
    // device trip with one reading instead of four.
    const report = await runDeviceProbe();
    expect(report.opfs.getDirectoryPresent).toBe(false);
    expect(report.opfs.writable).toBe(false);
    expect(report.opfs.error).toBeTypeOf("string");
    expect(report.moduleLoad.ok).toBe(true);
  });

  it("never reports a pass when a field was not measured", async () => {
    const report = await runDeviceProbe();
    // OPFS is unmeasurable here, so the verdict must not read as a pass.
    expect(report.verdict.startsWith("PASS")).toBe(false);
  });

  it("fences the report so it can be lifted out of a device log", async () => {
    const report = await runDeviceProbe();
    const text = formatDeviceProbeReport(report);
    expect(text).toContain("===QUICKJS-PROBE-BEGIN");
    expect(text).toContain("===QUICKJS-PROBE-END");
    // Round-trips: the fenced middle is the report, unmodified.
    const body = text.split("\n").slice(1, -1).join("\n");
    expect(JSON.parse(body)).toEqual(report);
    expect(JSON.parse(body).probe).toBe(DEVICE_PROBE_NAME);
  });
});
