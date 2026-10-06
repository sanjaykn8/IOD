# Migration Notes: Registration Redesign & RAG's Changed Role

This stage made one architectural pivot large enough to need its own
note: **RAG's role changed from an independent "collaborative drone
contribution" subsystem into a registration-time evidence-retrieval
system feeding a deterministic, measurement-based algorithm
selector**, and device registration (R1-R3) gained a real
steganographic transport. This document is for anyone extending this
project who needs to know what changed, what didn't, and why nothing
old was deleted.

## What changed

- **New registration path**: `protocol::registration_stego` (R1-R3
  as explicit, independently-decryptable, KEM-then-AEAD-sealed
  messages, steganographically embedded) alongside the original
  `protocol::registration` (fused, in-process, no transport). See
  `docs/registration-stego.md`.
- **New Python subsystem**: `python-service/src/stego/` (five real
  algorithms, `docs/steganography.md`) and a new primary consumer of
  `python-service/src/rag/`: `rag/selector.py` +
  `rag/stego_knowledge.py`, wired together by `stego_api.py`'s
  `/stego/*` endpoints. See `docs/algorithm-selection.md` and
  `docs/rag-stego-selection.md`.
- **New live HTTP endpoint**: `POST /api/drones/:id/register-stego`
  (`rust-core/src/api/state.rs`'s `register_drone_via_stego`,
  `server.rs`'s route), proxied by the Node gateway at the same path.
- **New dashboard page**: Registration (Stego)
  (`web-ui/src/components/command/registration-page.tsx`, route
  `/registration`), now the primary-navigation entry where "RAG /
  Knowledge" used to be.
- **A dozen protocol-level security fixes** (spec items 25-A through
  25-K) to the existing M1-M8/K1-K4 code, independent of the
  registration redesign but delivered in the same stage -- see
  `docs/claims-and-limitations.md` §7-§7a for the full list with test
  names, and `docs/security-review.md`/`docs/threat-model.md` for the
  security framing.

## What did NOT change, and why it still exists

- **`protocol::registration::register_drone`** (the original, fused,
  non-steganographic path) is unchanged and still used by every
  test/benchmark that does not need steganographic transport, and by
  the live `POST /api/drones/:id/register` endpoint. It is not a
  deprecated fallback -- it is the right tool whenever a real cover
  image and a live `python-service` are unnecessary ceremony (most
  unit/integration tests; any deployment that doesn't want the
  steganographic transport at all).
- **The original collaborative RAG pipeline**
  (`rag/{retrieval,validation,fusion}.py`, `llm/`, the `/rag/*` API,
  the dashboard's RAG page at `/rag`) is unchanged, still fully
  tested, and still reachable -- it simply lost its place in primary
  navigation and its role in registration. See `docs/rag.md`'s
  "Historical subsystem" section. Nothing was deleted because nothing
  about it became wrong; it answers a different question (collaborative
  multi-drone knowledge fusion) than the one registration now needs
  (single-request algorithm selection).
- **`VerificationReport`'s shape grew (5 booleans -> 6)**, not
  replaced -- `credential_consistency_ok` (spec 25-B) was added
  alongside the original five, and every existing caller/test that
  only inspected the original five still compiles and passes; this
  pivot and the spec-25 fixes were designed to be additive to the
  existing protocol surface, not a breaking rewrite of it.

## A design choice worth calling out explicitly

The registration-time selector (`docs/algorithm-selection.md`) and the
narrative generator (`docs/rag-stego-selection.md`) are two separate
Python modules with a one-directional data flow (benchmark ->
selector -> knowledge/narrative) specifically so that the retrieval
layer's known weakness (lexical word-overlap, not real semantic
search) can never corrupt the decision layer's correctness. If you are
extending this project and are tempted to let the narrative generator
"help" the selector choose (e.g. by letting retrieved text nudge a
score), that would break the "RAG must never invent performance
numbers" property this stage was built around -- keep the one-way
flow.

## If you're extending this further

- **Adding a sixth steganography algorithm**: implement the
  `StegoAlgorithm` protocol (`stego/base.py`), register it in
  `stego/registry.py`'s `ALGORITHMS` dict, add a knowledge-base file
  at `knowledge/steganography/algorithms/<id>.md`. The benchmark
  engine, selector, and Flask API all iterate the registry -- no other
  code needs to change.
- **Changing importance weights or adding a new importance level**:
  `rag/selector.py`'s `IMPORTANCE_WEIGHTS` dict, or pass
  `weights_override` per call. This is a policy change, not a code
  change to the selection algorithm itself.
- **Wiring a different transport for R1/R3** (not steganography):
  implement `StegoClient` (`protocol/stego_client.rs`) -- everything
  in `registration_stego.rs` is written against that trait, not
  against HTTP or Python specifically.
