import { manifestStreamLister } from "@opendatalabs/personal-server-ts-core/stream-sync";

/**
 * The `declaredStreams` hook of the stream-sync writer: the streams a
 * connection delete fences for `connector`. It is the union of the host's
 * option and the streams of the manifests this server retained, each name
 * once. The retained manifests are read on every call, so a manifest verified
 * after boot counts at delete time.
 */
export function declaredStreamsHook(
  option: ((connector: string) => readonly string[]) | undefined,
  retainedManifests: () => readonly string[],
): (connector: string) => readonly string[] {
  return (connector) => {
    const names = new Set(manifestStreamLister(retainedManifests())(connector));
    for (const stream of option?.(connector) ?? []) names.add(stream);
    return [...names];
  };
}
