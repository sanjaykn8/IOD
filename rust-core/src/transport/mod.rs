//! Transport abstraction, deliberately kept minimal in this version.
//!
//! Per the project brief, steganography is OUT OF SCOPE for this
//! version — this module exists solely to provide the clean interface
//! boundary a future adaptive-steganography subsystem would implement,
//! without requiring any change to `protocol::secure_messaging` or
//! anything upstream of it. The currently-active transport is the
//! identity/passthrough implementation: AEAD ciphertext bytes are
//! transmitted as-is.
//!
//! ```text
//! plaintext -> AEAD -> ciphertext -> TransportProvider -> "on the wire" bytes
//! ```
//!
//! A future `SteganographyTransportProvider` (PLACEHOLDER/FUTURE — not
//! implemented) would implement the same `TransportProvider` trait,
//! embedding `ciphertext` into e.g. image data on `encode` and
//! extracting it on `decode`, and could be swapped in via
//! `protocol::secure_messaging` construction without touching the AEAD
//! layer, the group-key layer, or any authentication code above it.

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
