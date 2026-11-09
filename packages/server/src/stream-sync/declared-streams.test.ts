/**
 * The server's `declaredStreams` hook for the stream-sync delete: the union of
 * the host's `declaredStreams` option and the streams of the manifests this
 * server retained. A connector the host no longer verifies (uninstalled, its
 * manifest not retained) is named by the option alone.
 */
import { describe, expect, it } from "vitest";
import { manifestStreamLister } from "@opendatalabs/personal-server-ts-core/stream-sync";
import { declaredStreamsHook } from "./declared-streams.js";

const CONNECTOR = "uninstalled-connector";

const manifest = (connector: string, streams: string[]) =>
  JSON.stringify({
    connector_key: connector,
    version: "1.0.0",
    streams: streams.map((name) => ({ name, primary_key: ["id"] })),
  });

const retainedItems = [manifest(CONNECTOR, ["items"])];

describe("declared streams of a connection delete", () => {
  it("a stream known only from the host option is deleted", () => {
    const hook = declaredStreamsHook(
      () => ["extra"],
      () => [],
    );
    expect(hook(CONNECTOR)).toEqual(["extra"]);
  });

  it("the host option's streams are deleted for an uninstalled connector with no retained manifest", () => {
    const hook = declaredStreamsHook(
      (connector) => (connector === CONNECTOR ? ["items", "extra"] : []),
      () => [],
    );
    expect(hook(CONNECTOR)).toEqual(["items", "extra"]);
  });

  it("a manifest stream is kept beside the host option's streams (union, not replace)", () => {
    const hook = declaredStreamsHook(
      () => ["extra"],
      () => retainedItems,
    );
    expect(hook(CONNECTOR).slice().sort()).toEqual(["extra", "items"]);
  });

  it("a stream known to both the manifest and the option is listed once", () => {
    const hook = declaredStreamsHook(
      () => ["items"],
      () => retainedItems,
    );
    expect(hook(CONNECTOR)).toEqual(["items"]);
  });

  it("with no host option the hook is exactly the manifest lister, as before", () => {
    const retained = [manifest(CONNECTOR, ["items", "extra"])];
    const hook = declaredStreamsHook(undefined, () => retained);
    expect(hook(CONNECTOR)).toEqual(manifestStreamLister(retained)(CONNECTOR));
    expect(hook("some-other-connector")).toEqual([]);
  });

  it("an option that names nothing for the connector still gets its manifest streams", () => {
    const hook = declaredStreamsHook(
      () => [],
      () => retainedItems,
    );
    expect(hook(CONNECTOR)).toEqual(["items"]);
  });

  it("the retained manifests are read at call time, so a manifest verified after boot counts", () => {
    let retained: string[] = [];
    const hook = declaredStreamsHook(undefined, () => retained);
    expect(hook(CONNECTOR)).toEqual([]);
    retained = retainedItems;
    expect(hook(CONNECTOR)).toEqual(["items"]);
  });
});
