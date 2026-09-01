# Mobile WASM: the probe is landed, the run is deferred

**Status: UNVERIFIED on iOS WKWebView and on Android WebView.** Nothing in this
document is a measurement on either. It exists so that the measurement becomes a
single page load for whoever next holds a phone, and so that nobody reads the
desktop results as coverage they are not.

Written 2026-08-31, against `feat/query-layer` at `286e065`. It closes no open
item in `260828-query-layer-implementation-plan.md` §6 and edits nothing in
`260828-query-layer-design.md`.

## 1. Why it is unverified, precisely

Design §19.18 records the query layer's QuickJS-on-WASM execution path as
**measured, working** on desktop Chrome (Blink/V8) and desktop Safari
(WebKit/JSC) — a full N=3 benchmark on the first, a capability probe on the
second — and as **UNVERIFIED** on both mobile surfaces. Its reasons, not
restated but reused:

- iOS WKWebView: "Same engine family as the Safari row, which is real evidence —
  but not the same JIT policy, memory regime or OPFS behaviour."
- Android WebView: "No evidence of any kind was obtainable here. No emulator, no
  adb, no Flutter toolchain on this machine."

And the fact underneath both: `apps/mobile-shell` contained **no reference to
`WebAssembly` anywhere** — in Dart or in `ps_bundle` — except a
`'wasm': 'application/wasm'` MIME mapping at `lib/shell/asset_resolver.dart:97`.
WASM had never executed there. That was still true when this work started; it is
what the probe changes.

Two further reasons apply to _this_ session specifically and are the reason the
run is deferred rather than done:

1. **No Flutter toolchain.** `flutter` and `dart` are not on `PATH`. The shell
   cannot be built, so the probe cannot be installed, so it cannot be run.
2. **No iOS build or device path.** `xcrun devicectl` is absent (`unable to find
utility "devicectl"`), so even a built app could not be installed or launched
   on a phone from here. `adb` exists at the Homebrew path `run-android.sh`
   expects, but no device was attached and no APK could be produced without
   Flutter.

The decision on record is **land the probe, defer the run**. Do not read a green
desktop row as a mobile row, and do not let "the engine is the same family" stand
in for a measurement — §19.18 already declined to, on three specific grounds.

## 2. The four fields

Design §19.18, "Cross-platform: what is measured, and what is not":

> **What would settle it**, precisely: build `.bench/probe.ts` into
> `apps/mobile-shell/assets/ps/`, load it in the Flutter shell on one real iOS
> device and one real Android device, and read the four fields it already emits —
> `moduleLoad`, `egressGlobalsPresent`, `mechanics`, `opfs.writable`. That is a
> single page load per device and it answers the whole condition. It needs
> hardware this machine does not have.

So the four fields, quoted from §19.18, are:

| field                  | the question it answers                                                                                                                                                                                                                            |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `moduleLoad`           | Does the WASM engine instantiate in this WebView at all, and how long does it take? On iOS this is also the Lockdown Mode question, which disables WebAssembly outright.                                                                           |
| `egressGlobalsPresent` | The containment claim. §19.18: "Not denied: absent, because QuickJS never created them." Expected `[]`; any name here voids the claim on that engine.                                                                                              |
| `mechanics`            | The three version-specific QuickJS behaviours the sandbox is built on. `quickjs-sandbox.test.ts` asserts them against **Node's** WASM build; a WebView's WASM is not that build, so they are re-asked rather than assumed.                         |
| `opfs.writable`        | §19.17 recorded the mobile host defaulting to IndexedDB because "WKWebView can advertise OPFS while failing its first real write", and `isOpfsAvailable()` only feature-detects `getDirectory`. So this is a **real** write, not a presence check. |

### One correction to §19.18's instruction

`.bench/` was a scratch directory in the session that wrote §19.18 and **did not
survive** — `.bench/probe.ts` is in neither repo and in no commit
(`git log --all -S egressGlobalsPresent` reaches only the design doc). So "the
four fields it already emits" describes a file that no longer exists. The probe
below is that probe, rewritten in the package the fields belong to, with the four
field names spelled exactly as §19.18 spells them, because a pasted-back report
is only useful if it answers the question in the words it was asked in.

The one device probe that _does_ already exist in `apps/mobile-shell` —
`assets/probe/probe.js`, driven by `lib/probe/origin_probe.dart` — measures
secure context, `crypto.subtle` against a known vector, IndexedDB, localStorage,
quota and fetch fidelity, and it already performs the real OPFS
`createWritable()` write. It has no WASM or QuickJS section of any kind. It is
left exactly as it was.

## 3. What was wired, and where

Two repos, because the code and the host live apart.

### `personal-server-ts` (committed on `feat/query-layer`)

| file                                            | what it is                                                                                                                                                                                                   |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `packages/lite/src/query/device-probe.ts`       | The probe. Emits the four fields. Never throws — every failure is a recorded field, because a probe that dies on the first missing capability answers one field and leaves three unknown.                    |
| `packages/lite/src/query/device-probe-entry.ts` | Browser entry; attaches `globalThis.VANAQUERYPROBE`, mirroring the shell's own `VANAPROBE` convention. Deliberately **not** re-exported from `query/index.ts`, so it stays off the package's public surface. |
| `packages/lite/src/query/device-probe.test.ts`  | Runs the real engine under Node. Asserts the four field names, the three mechanics, and that a missing capability is recorded rather than thrown.                                                            |
| `packages/lite/package.json`                    | `bundle-device-probe`: one esbuild IIFE, `--target=safari16,chrome108` — the same target `ps_bundle/build.mjs` uses. Not part of `build`; the published package does not grow.                               |

### `apps/mobile-shell` — which repo it is in

**`unity-surfaces`**, at
`/Users/kahtaf/Documents/workspace_vana/unity-surfaces/apps/mobile-shell`. Not in
this repo. Every file below is therefore **UNCOMMITTED** and left for review;
nothing was committed in `unity-surfaces`.

| file                                  | change                                                                                                                                                                                                     |
| ------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `assets/ps/query-probe.html`          | **new.** Measurement-only host page at the PS origin, loading the probe bundle. Registers its error listener before the bundle tag and in the capture phase, exactly as `index.html` learned to.           |
| `lib/probe/quickjs_device_probe.dart` | **new.** `QuickJsDeviceProbe`: headless WebView at `Origins.ps` + `/query-probe.html`, calls `window.VANAQUERYPROBE.run()`, returns the report as a map.                                                   |
| `lib/w1/w1_suite.dart`                | `runQuickJsDeviceProbe(PsHost)`, emitting a `quickjs-device-probe` block through the suite's existing `emit`, so it lands in the device log **and** in `reportText`, which the Copy button already copies. |
| `lib/ui/shell_page.dart`              | `_includeQuickJsProbe` (`--dart-define=W1_QUICKJS`, default on) and the call, placed **outside** the PS-Lite try/catch: a failed network stage says nothing about whether WASM runs.                       |
| `test/ps/query_probe_page.test.mjs`   | **new.** Six Node tests mirroring `ps_host_page.test.mjs`: script ordering from the parse, capturing listener, and that an uninstalled bundle names itself instead of timing out.                          |
| `.gitignore`                          | ignores the generated `assets/ps/vana-quickjs-device-probe.js`, next to the existing `ps-lite-bundle.js` rule.                                                                                             |

`pubspec.yaml` needed no change: `assets/ps/` is already a declared asset
directory, so both new files are bundled.

### Three mechanism choices, and why they are not inventions

**Served, not injected.** `assets/probe/probe.js` is injected and never served —
"that keeps the shell honest about its own claim". The probe bundle cannot follow
it: at **1,130,204 bytes** it exceeds Android's ~1 MB Binder transaction limit on
the `evaluateJavascript` method channel. §19.18's own instruction was to _build it
into `assets/ps/`_, which is the served path, and that is what this does.

**At the PS origin, in its own document.** `opfs.writable` is an origin-scoped
answer, and the partition that matters is the one that would carry the vault.
`assets/ps` is already that origin's document root on both platforms, so no new
origin, scheme or port is introduced — origins here are on-disk storage identity
(`lib/shell/origins.dart`), and adding one to run a measurement would be the wrong
trade. It is a second document rather than the vault page because that page boots
the real runtime.

**After `PsHost.start()`.** On iOS `Origins.ps` is a fixed-port loopback origin
served by the `InAppLocalhostServer` that `PsHost` owns. The probe starts no
server of its own — there must never be two on that port — so it requires
`psHost.isRunning` and throws a legible `StateError` rather than a bare
connection error if it is not.

## 4. Will it load there? The mechanics, honestly

### Resolved by construction

**No `.wasm` request is made.** `loadQuickJsModule` uses
`@jitl/quickjs-singlefile-browser-release-sync`, which base64-inlines the engine
and instantiates it from an ArrayBuffer. So:

- **MIME type is not in the path.** `asset_resolver.dart:97`'s
  `'wasm': 'application/wasm'` is never exercised. This matters most on iOS,
  where the serving layer cannot emit a response header at all (§19.17,
  `origin_host.dart:19-29`).
- **Streaming compilation is not used.** `WebAssembly.instantiateStreaming`
  requires a `Response` with the right content type; nothing here calls it, so
  its availability is not a question the probe has to answer.
- **There is nothing for a `connect-src` policy to allow.** §19.18 chose this
  variant for exactly this reason, after every one of the first five benchmark
  runs failed on the separate-file variant's fetch.

**CSP is not currently in the path either** — and that is a fact with a sharp
edge. Neither `assets/ps/index.html` nor the new `query-probe.html` carries a
`<meta http-equiv>` policy; iOS cannot set a header and Android sets only
`Cache-Control` (`origin_host.dart:163`). So today there is no `script-src` to
satisfy. **The moment anyone adds one** — which is what plan §6's
`connect-src 'none'` item would require — **`wasm-unsafe-eval` becomes load-bearing
and its absence stops the query layer dead, silently.** Recorded here against
that item; not resolved, and §6 is left as it stands.

### Verified only on desktop

The served-page wiring — page loads bundle, bundle attaches the global, `run()`
returns all four fields populated — was exercised in **desktop Chrome 151 at
`http://localhost:8767`**, which is the same origin _shape_ iOS uses. All four
fields came back populated and `opfs.writable` was `true`.

**That is a check of this wiring, not a mobile measurement, and not a new
platform claim** — §19.18 already had desktop Chrome measured. It is recorded
because it separates "the probe is written" from "the probe runs when served",
and nothing more.

### Blockers, named

1. **No Flutter toolchain, no iOS device path on this machine.** The blocker that
   defers the run. See §1.
2. **The Dart is not compile-checked.** There is no `dart analyze` here. The four
   `.dart` changes follow the surrounding files' idioms exactly
   (`HeadlessOriginProbe` for the WebView, `ProbeClient` for the JSON-in/JSON-out
   bridge) but they have not been through the analyzer. **Run
   `flutter analyze` and `flutter test` in `apps/mobile-shell` before trusting
   them.** The six new `.mjs` tests do pass (`npm test`: 72/72, up from 66).
3. **The product path cannot carry QuickJS yet, and a green probe will not change
   that.** `ps_bundle/package.json` pins
   `@opendatalabs/personal-server-ts-lite@1.5.0`, and `ps_bundle/build.mjs`
   throws unless the lockfile pins exactly `1.5.0` with registry integrity. The
   query layer is unreleased — it is on `feat/query-layer` (PR #237). So
   `ps-lite-bundle.js` contains no QuickJS today. **The probe is unaffected**,
   because it is built independently from this repo and copied in; but shipping
   the query layer on mobile needs Lite published with it and the pin moved,
   which is a separate step and a separate decision.
4. **iOS Lockdown Mode disables WebAssembly.** A device with it enabled will
   report `moduleLoad.ok: false`. That is a real result about that device, not a
   probe defect — see the run instructions.

## 5. Running it, on real hardware

Two devices, one page load each. Nothing below makes an inference call, reads
user data, or writes anything except one throwaway OPFS file the probe deletes.

### Step 0 — build the probe bundle (once, on the Mac)

```sh
cd <personal-server-ts>            # on feat/query-layer
npm install
npm run build                      # core's dist must exist first
npm run bundle-device-probe -w @opendatalabs/personal-server-ts-lite
cp packages/lite/dist/device-probe/vana-quickjs-device-probe.js \
   <unity-surfaces>/apps/mobile-shell/assets/ps/
```

Expect ~1.1 MB. It is gitignored in `unity-surfaces`, so it will not appear in
`git status` there — confirm it with `ls -la apps/mobile-shell/assets/ps/`
instead. **If it is missing, the probe reports `probeMissing: true` rather than
timing out**; that is a correct result meaning "step 0 was skipped", not a device
finding.

### Step 1 — iOS, one real iPhone

```sh
cd <unity-surfaces>/apps/mobile-shell
flutter analyze && flutter test          # the Dart has not been analysed anywhere yet
flutter build ios --profile --dart-define=W1_AUTORUN=true
xcrun devicectl device install app --device "$VANA_IOS_DEVICE" \
  build/ios/iphoneos/Runner.app
tools/run-ios.sh logs/ios-quickjs-1.log
```

Profile, not debug: a debug Flutter build runs Dart under JIT and dies on a
standalone launch. Install with `devicectl`, **never** `flutter run` — the latter
replaces the app container and takes the vault with it.

`tools/run-ios.sh` waits for the `===W1-DONE===` sentinel and captures the whole
run. Then:

```sh
grep -A200 '===W1-BEGIN quickjs-device-probe===' logs/ios-quickjs-1.log
```

**Before reading a `moduleLoad.ok: false`, check Settings → Privacy & Security →
Lockdown Mode on that device.** Lockdown Mode disables WebAssembly outright, and
a run under it answers a different question than the one being asked. Note which
it was either way.

### Step 2 — Android, one real device

```sh
cd <unity-surfaces>/apps/mobile-shell
flutter build apk --profile --dart-define=W1_AUTORUN=true
adb install -r build/app/outputs/flutter-apk/app-profile.apk
tools/run-android.sh logs/and-quickjs-1.log
grep -A200 '===W1-BEGIN quickjs-device-probe===' logs/and-quickjs-1.log
```

`adb install -r` preserves the data directory; `flutter run` does not. Record the
WebView version — `adb shell dumpsys package com.google.android.webview | grep
versionName` — because it is the engine under test and it updates independently
of the OS.

### Step 3 — run each device more than once

§19.18's own method note applies: "A single green run is not evidence." Two
findings in the earlier spike were artefacts of the harness and were withdrawn
only after control runs. Launch each device at least twice — `tools/run-*.sh`
takes an output path, so use a fresh one — and paste both.

### If you would rather tap than build

`--dart-define=W1_CONTROLS=true` renders the suite's Run / Copy buttons on the
device. `Copy` puts `W1Suite.reportText` — including the
`quickjs-device-probe` block — on the clipboard verbatim.

## 6. Paste-back template

One block per device per run. Paste it as-is; do not summarise it. The `verdict`
line is the probe's own reading and is deliberately conservative — it says `PASS`
only when all four fields are good, and appends "This is one device; it says
nothing about any other."

```text
device:        [iPhone 15 Pro / Pixel 8 / …]
os:            [iOS 18.5 / Android 15]
webview:       [WKWebView, or the com.google.android.webview versionName]
lockdown mode: [on / off / n-a]   <- iOS only; on disables WebAssembly outright
run:           [1 of 2]
shell build:   [the "shell <sha>" stamp the app renders, or `git rev-parse --short HEAD`]

===W1-BEGIN quickjs-device-probe===
{
  "probe": "vana-quickjs-device-probe",
  "version": 2,
  "at": "",
  "origin": "",
  "userAgent": "",
  "secureContext": null,

  "moduleLoad": { "ok": null, "ms": null },

  "egressGlobalsPresent": null,

  "mechanics": {
    "stackLimitAt8MbFailsEval": null,
    "memoryLimitRaisesRatherThanNull": null,
    "hostErrorReturnValueDoesNotThrow": null,
    "maxStackBytes": null,
    "errors": []
  },

  "opfs": {
    "getDirectoryPresent": null,
    "createWritablePresent": null,
    "writable": null,
    "roundTripOk": null,
    "error": null
  },

  "verdict": ""
}
===W1-END quickjs-device-probe===
```

### How to read it

| reading                            | what it means                                                                                                                                                                                                                    |
| ---------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `moduleLoad.ok: false`             | The query layer cannot run on that surface at all. Check Lockdown Mode first; the message in `moduleLoad.error` is the only other evidence.                                                                                      |
| `egressGlobalsPresent` non-empty   | **Stop.** The containment claim is void on that engine. §19.18's claim is that these are absent because QuickJS never creates them; a name here means something upstream changed.                                                |
| any `mechanics` field `false`      | That WebView's WASM behaves differently from Node's build. `stackLimitAt8MbFailsEval: false` in particular means `MAX_STACK_BYTES` needs re-measuring for that platform rather than inheriting 1 MB.                             |
| `opfs.writable: false`             | Exactly the failure §19.17 predicted for WKWebView. PS-Lite must stay on the IndexedDB file store there — which is already the mobile host's default, for this reason.                                                           |
| `probeMissing: true`               | Step 0 was skipped. Not a device finding.                                                                                                                                                                                        |
| all four good, on **both** devices | The cross-platform condition §19.18 records is met **for those two devices and those two engine versions**. It is still not a claim about the platform, and it does not by itself put the query layer on mobile — see blocker 3. |

## 7. What this does not resolve

- `260828-query-layer-implementation-plan.md` §6 is untouched. The
  `connect-src 'none'` item and the Lite-corpus item stay open exactly as
  written; nothing here gives any host a CSP, and Lite still has no mechanism to
  require or verify one.
- Mobile QuickJS/WASM remains **UNVERIFIED** until the blocks in §6 above come
  back from real hardware. Two green desktop engines and one green desktop
  wiring check are not that.
- Blocker 3 stands regardless of the probe's result: the shipping mobile bundle
  pins a published Lite that does not contain the query layer.
