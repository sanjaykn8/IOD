pub mod auth_flow;
pub mod canon;
pub mod credentials;
pub mod entities;
pub mod envelope;
pub mod events;
pub mod group_key;
pub mod messages;
pub mod registration;
pub mod secure_messaging;
pub mod simulation;
pub mod transcript;

/// Maximum accepted clock skew / message age (ms). Research-prototype
/// value, not production-tuned.
pub const MAX_TIMESTAMP_SKEW_MS: i64 = 5 * 60 * 1000;
/// Lifetime of a pseudonym (PID) after issuance.
pub const PID_VALIDITY_MS: u64 = 24 * 3600 * 1000;
/// Lifetime of an authentication session record at the GCS.
pub const SESSION_VALIDITY_MS: u64 = 10 * 60 * 1000;
