//! Transport layer.
//!
//! * `TransportProvider` / `PassthroughTransport` -- the original minimal
//!   interface, retained for unit tests of the sealing layer only. The live
//!   application-message path does NOT use passthrough.
//! * `pipeline` -- the image-based transport (frame v1 + bootstrap v1 over
//!   a Python image service). See `docs/stego-transport.md`.

pub mod b64;
pub mod backend;
pub mod config;
pub mod error;
pub mod explain;
pub mod fake;
pub mod frame;
pub mod http;
pub mod pipeline;
pub mod report;
pub mod wire;

pub trait TransportProvider: Send + Sync {
    /// Encode already-AEAD-protected ciphertext bytes into whatever this
    /// transport sends "on the wire."
    fn encode(&self, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>>;
    /// Recover the AEAD ciphertext bytes from the wire representation.
    fn decode(&self, wire: &[u8]) -> anyhow::Result<Vec<u8>>;
    fn name(&self) -> &'static str;
}

/// Currently-active transport: passthrough (no steganography).
pub struct PassthroughTransport;

impl TransportProvider for PassthroughTransport {
    fn encode(&self, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(ciphertext.to_vec())
    }
    fn decode(&self, wire: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(wire.to_vec())
    }
    fn name(&self) -> &'static str {
        "passthrough"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passthrough_round_trip() {
        let t = PassthroughTransport;
        let wire = t.encode(b"ciphertext-bytes").unwrap();
        assert_eq!(t.decode(&wire).unwrap(), b"ciphertext-bytes");
        assert_eq!(t.name(), "passthrough");
    }
}
