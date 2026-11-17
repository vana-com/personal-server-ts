# browser-tls-rustls

The TLS server that PS Lite runs inside a browser tab. It is a rustls
`ServerConnection` (with the pure-Rust `rustls-rustcrypto` provider) compiled to
WebAssembly. `packages/lite/src/relay-tls.ts` feeds it bytes; it has no sockets.

```ts
const server = new TlsServer(certPem, keyPem);
const step = server.process_tls(ciphertext); // { plaintext, tls, handshaking }
const out = server.write_plaintext(bytes, close); // { plaintext, tls, handshaking }
server.free();
```

- `plaintext`: application data this call decrypted.
- `tls`: ciphertext to send to the peer.
- `handshaking`: rustls `is_handshaking()` after the call.
- A TLS failure is thrown as a string. The string carries no bytes. rustls keeps
  the fatal alert it queued, and `write_plaintext(new Uint8Array(), false)`
  returns it. `relay.ts` does not fetch it today: it logs the error and closes
  the stream.
- The step does not report that the peer sent `close_notify`; the relay's
  `stream.close` message ends a stream. Input in a later call after
  `close_notify` throws `peer closed the connection`. Bytes after it in the same
  call are dropped.
- An empty input is a no-op.

## Rebuild

The committed output in `../../src/browser-tls-rustls/` comes from this crate.
Do not edit it by hand. From `packages/lite`:

```sh
npm run build:tls-wasm
```

You need:

- `rustup`. `rust-toolchain.toml` pins the compiler and adds the
  `wasm32-unknown-unknown` target. The script installs it if it is missing.
- The prebuilt `wasm-bindgen` CLI from the
  [wasm-bindgen releases page](https://github.com/wasm-bindgen/wasm-bindgen/releases),
  at the same version as the `wasm-bindgen` crate in `Cargo.lock`. Do not use
  `cargo install wasm-bindgen-cli`: that build writes different metadata into the
  wasm, so the bytes would not match the committed file. Set `WASM_BINDGEN` if the
  CLI is not on `PATH`.

The script remaps the home, checkout, Cargo and rustup paths, so the binary does
not carry the paths of the machine that built it. It then runs
`scripts/check-binary-home-paths.sh` on the result. Two builds of the same
commit give the same bytes. CI rebuilds the binary and fails if it differs from
the committed one.

## Change the dependencies

Keep `Cargo.lock` committed and build with `--locked`. After a change, rebuild,
run `npx vitest run packages/lite/src/relay-tls-handshake.test.ts` from the repo
root, and commit the new binary with the lock file. A change to the toolchain,
the `wasm-bindgen` version or the profile in `Cargo.toml` changes the output
bytes.
