/**
 * Browser entry for the mobile WASM device probe.
 *
 * Bundled to a single self-contained IIFE by `npm run bundle-device-probe`,
 * which is the form the Flutter shell can serve: the QuickJS engine is
 * base64-inlined by `@jitl/quickjs-singlefile-browser-release-sync`, so the
 * page makes **no second request** for a `.wasm` file. That matters on exactly
 * the two surfaces this probe exists for — iOS, whose in-process origin cannot
 * emit a response header at all (design §19.17, `origin_host.dart:19-29`), and
 * Android's asset loader, where a wrong MIME type is a silent failure.
 *
 * Deliberately **not** re-exported from `./index.ts`. This file exists to be
 * bundled, not to be imported by the runtime, and keeping it off the package's
 * public surface keeps the probe out of every consumer's module graph.
 *
 * The global is the shell's convention: `assets/probe/probe.js` attaches
 * `globalThis.VANAPROBE` and Dart drives it by name. This attaches
 * `globalThis.VANAQUERYPROBE` the same way.
 */

import {
  DEVICE_PROBE_NAME,
  DEVICE_PROBE_VERSION,
  formatDeviceProbeReport,
  runDeviceProbe,
  type DeviceProbeReport,
} from "./device-probe.js";

export interface VanaQueryProbeGlobal {
  readonly name: typeof DEVICE_PROBE_NAME;
  readonly version: number;
  run(): Promise<DeviceProbeReport>;
  format(report: DeviceProbeReport): string;
}

const api: VanaQueryProbeGlobal = {
  name: DEVICE_PROBE_NAME,
  version: DEVICE_PROBE_VERSION,
  run: runDeviceProbe,
  format: formatDeviceProbeReport,
};

(globalThis as { VANAQUERYPROBE?: VanaQueryProbeGlobal }).VANAQUERYPROBE = api;

// A load failure has to be visible from a device log with no debugger
// attached, and the host page has no other way to tell "script never ran" from
// "script ran and found nothing".
if (typeof console !== "undefined") {
  console.log(`[${DEVICE_PROBE_NAME}] attached v${DEVICE_PROBE_VERSION}`);
}
