# Configuration

Each component reads its configuration from environment variables (see
the `.env.example` file in that component's own directory:
`rust-core/.env.example`, `node-server/.env.example`,
`python-service/.env.example`, `web-ui/.env.example`). Copy the relevant
file to `.env` in that same directory, or export the variables directly
in your shell, before running that component.

## Simulation parameters

- **Merkle tree depth**: fixed at 8 (capacity 256 drones per group) in
  `rust-core/src/api/state.rs`'s `SimulationState::new` — change
  `merkle_depth` there and rebuild if you need a larger/smaller capacity.
- **PUF noise level**: `puf::fuzzy_extractor::DEFAULT_BIT_FLIP_PROB`
  (5%) — see `docs/puf.md` for the reliability trade-off if you change
  this.
- **Timestamp skew window**: `protocol::auth_flow::MAX_TIMESTAMP_SKEW_MS`
  (5 minutes).
- **PID pool batch size**: `protocol::registration::PID_POOL_BATCH_SIZE`
  (64).

These are compile-time constants rather than environment variables in
this version — a reasonable target for a future "simulation parameters"
config file if this project grows a need to tune them without
recompiling.

## Development / demo / test modes

This version does not implement distinct "development/demo/test" mode
profiles as separate configuration presets — the same binaries and
default configuration are used throughout. The most relevant switches
in practice are: `IOD_DB_PATH` (point at a scratch file for a throwaway
demo vs. a persistent one for repeated use) and the test suites
themselves (`cargo test`, `pytest`) which use `Database::open_in_memory()`
rather than any file path at all, so tests never touch your real
simulation database.
