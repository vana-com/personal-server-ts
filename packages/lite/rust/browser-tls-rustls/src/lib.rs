//! Browser-side TLS 1.2/1.3 server for Personal Server Lite's relay.
//!
//! The relay forwards raw TLS bytes between a remote client and the browser
//! tab. This crate is the tab's end of that connection: a rustls
//! `ServerConnection` driven as a pure byte pump, with no sockets. JavaScript
//! (`packages/lite/src/relay-tls.ts`) feeds it ciphertext with `process_tls`
//! and plaintext with `write_plaintext`, and sends back whatever TLS bytes
//! each call returns.
//!
//! Both methods return a plain object `{ plaintext, tls, handshaking }`:
//! `plaintext` is the application data decrypted by this call, `tls` is the
//! ciphertext to send to the peer, and `handshaking` is rustls's
//! `is_handshaking()` after the call. A TLS failure is thrown as a string.

use std::io::{self, Read, Write};
use std::sync::Arc;

use js_sys::{Object, Reflect, Uint8Array};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection};
use wasm_bindgen::prelude::*;

fn js_err(message: impl ToString) -> JsValue {
    JsValue::from_str(&message.to_string())
}

#[wasm_bindgen]
pub struct TlsServer {
    conn: ServerConnection,
}

#[wasm_bindgen]
impl TlsServer {
    // Builds a server connection for one relay stream from a PEM certificate
    // chain and a PEM private key (PKCS#8, PKCS#1 RSA or SEC1 EC).
    #[wasm_bindgen(constructor)]
    pub fn new(cert_pem: &str, key_pem: &str) -> Result<TlsServer, JsValue> {
        let chain = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| js_err(format!("invalid certificate PEM: {e}")))?;
        if chain.is_empty() {
            return Err(js_err("certificate chain is empty"));
        }
        let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
            .map_err(|_| js_err("private key is missing"))?;

        let config = ServerConfig::builder_with_provider(Arc::new(rustls_rustcrypto::provider()))
        .with_safe_default_protocol_versions()
        .map_err(js_err)?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(js_err)?;

        let conn = ServerConnection::new(Arc::new(config)).map_err(js_err)?;
        Ok(TlsServer { conn })
    }

    // Feeds ciphertext from the peer. An empty input is a no-op.
    pub fn process_tls(&mut self, input: &[u8]) -> Result<JsValue, JsValue> {
        let mut plaintext = Vec::new();
        let mut remaining = input;
        while !remaining.is_empty() {
            let consumed = self.conn.read_tls(&mut remaining).map_err(js_err)?;
            self.conn.process_new_packets().map_err(js_err)?;
            self.drain_plaintext(&mut plaintext)?;
            if consumed == 0 {
                return Err(js_err("TLS input buffer is full"));
            }
        }
        let tls = self.drain_tls()?;
        Ok(self.step(&plaintext, &tls))
    }

    // Encrypts application data for the peer. With `close` set, a TLS
    // `close_notify` alert follows the data.
    pub fn write_plaintext(&mut self, plaintext: &[u8], close: bool) -> Result<JsValue, JsValue> {
        let mut tls = Vec::new();
        let mut remaining = plaintext;
        while !remaining.is_empty() {
            let written = self.conn.writer().write(remaining).map_err(js_err)?;
            remaining = &remaining[written..];
            let flushed = self.conn.wants_write();
            self.flush_tls(&mut tls)?;
            if written == 0 && !flushed {
                return Err(js_err("TLS write buffer is full"));
            }
        }
        if close {
            self.conn.send_close_notify();
        }
        self.flush_tls(&mut tls)?;
        Ok(self.step(&[], &tls))
    }
}

impl TlsServer {
    /// Moves every decrypted byte rustls holds into `out`.
    fn drain_plaintext(&mut self, out: &mut Vec<u8>) -> Result<(), JsValue> {
        let mut chunk = [0u8; 16 * 1024];
        loop {
            match self.conn.reader().read(&mut chunk) {
                // Clean EOF: the peer sent close_notify.
                Ok(0) => return Ok(()),
                Ok(n) => out.extend_from_slice(&chunk[..n]),
                // No more plaintext available right now.
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(e) => return Err(js_err(e)),
            }
        }
    }

    fn flush_tls(&mut self, out: &mut Vec<u8>) -> Result<(), JsValue> {
        while self.conn.wants_write() {
            self.conn.write_tls(out).map_err(js_err)?;
        }
        Ok(())
    }

    fn drain_tls(&mut self) -> Result<Vec<u8>, JsValue> {
        let mut out = Vec::new();
        self.flush_tls(&mut out)?;
        Ok(out)
    }

    fn step(&self, plaintext: &[u8], tls: &[u8]) -> JsValue {
        let step = Object::new();
        let set = |key: &str, value: &JsValue| {
            // Setting a property on a fresh plain object cannot fail.
            let _ = Reflect::set(&step, &JsValue::from_str(key), value);
        };
        set("plaintext", &Uint8Array::from(plaintext));
        set("tls", &Uint8Array::from(tls));
        set("handshaking", &JsValue::from_bool(self.conn.is_handshaking()));
        step.into()
    }
}
