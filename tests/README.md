Tests live alongside the code that owns them, following each language's
own convention, rather than in this directory:

- Rust unit tests: inline `#[cfg(test)] mod tests` blocks throughout
  `rust-core/src/**/*.rs`.
- Rust integration tests (public-API-level): `rust-core/tests/*.rs`
  (standard Cargo convention — automatically picked up by `cargo test`).
- Python tests: `python-service/tests/*.py` (pytest convention).

See `docs/testing.md` for the full test suite summary and the
checklist-to-test mapping.
