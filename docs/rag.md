# Collaborative RAG / Mock LLM Simulation

Implemented entirely in Python (`python-service/`), independent of the
Rust cryptographic core. **No cryptography, no external network calls,
no paid API** — every requirement the project brief states for this
subsystem.

## Historical subsystem (superseded as the project's primary RAG role)

This document describes the subsystem as originally built: an
independent "collaborative drone contribution" pipeline (contribute →
retrieve → validate → fuse → generate), reachable from the dashboard's
RAG page and the `/rag/*` API, with no role in device registration.

As of this stage, RAG's **primary** role in this project is different:
registration-time, measurement-grounded steganography-algorithm
selection, consumed by `stego_api.py` during R1/R3 (see
`docs/rag-stego-selection.md` and `docs/algorithm-selection.md`). That
subsystem is architecturally unable to fabricate a performance number
-- it only ever quotes measurements `stego/benchmark.py` already
computed -- which is a stronger, narrower honesty property than
anything this page's word-overlap retrieval claims for itself.

The collaborative pipeline documented below is **not removed and not
broken**: `rag/{retrieval,validation,fusion}.py`, `llm/`, and this
page's own tests all still exist, still pass, and are still reachable
(the dashboard's "Registration (Stego)" page replaced this one in
primary navigation, but the underlying route and API are unchanged and
still live -- see `docs/architecture.md`). It is simply no longer
load-bearing for registration, and nothing below should be read as a
description of how a drone's enrollment credentials reach GCS -- that
is `docs/registration-stego.md`'s subject. See
`docs/claims-and-limitations.md` §9 for the full classification of
both roles side by side.

## Pipeline

```
drone contribution → retrieval → validation → fusion → generation
```

1. **Contribution** (`rag/models.py`): `{drone_id, content, confidence}`.
   No cryptographic material — by the time content reaches this service
   in a full deployment, it would already have traveled over the Rust
   core's AEAD-protected secure-messaging channel and been decrypted;
   this service only ever sees plaintext content plus metadata. That
   transport-security boundary is NOT re-implemented or re-simulated
   here — it is Rust's job, already done in
   `rust-core/src/protocol/secure_messaging.rs`.
2. **Retrieval** (`rag/retrieval.py`): word-overlap (Jaccard similarity)
   ranking against the query. **SIMULATED, explicitly not real
   retrieval** — no embeddings, no vector search. Labeled as such in the
   module docstring, not just here.
3. **Validation** (`rag/validation.py`): flags a contribution as
   "suspicious" if its content is a similarity outlier relative to the
   rest of the batch (average pairwise Jaccard below a threshold), and
   downweights its trust score proportionally. **This is a
   demonstration-level heuristic, explicitly NOT a real Byzantine
   fault-tolerant defense** — it has no characterized false-positive/
   false-negative rate, would misfire on genuinely novel-but-true
   reports, and does not use any cryptographic attestation of
   provenance. Labeled as such in the module docstring.
4. **Fusion** (`rag/fusion.py`): trust-ordered concatenation, excluding
   anything below a minimum trust floor.
5. **Generation** (`llm/mock_provider.py`): `MockLLMProvider` — fully
   deterministic, template-based text generation. No randomness, no
   network call, no API key.

## LLM provider interface

`llm/provider.py` defines `LLMProvider` (abstract: `generate`, `name`).
`MockLLMProvider` is the active default. `llm/ollama_provider.py` is a
documented **PLACEHOLDER/FUTURE**: it implements the same interface but
`generate()` raises `NotImplementedError` — it exists solely to show
that swapping in a real local model later requires no change to
`app.py` beyond selecting a different provider instance.

## Verified behavior

Live-tested (see `docs/testing.md`): two consistent contributions about
the same event plus one deliberately off-topic "adversarial"
contribution → the off-topic one is correctly flagged as suspicious,
its trust score is reduced, it is excluded from fusion, and the
generated output correctly synthesizes only the two consistent reports.
13 pytest unit tests cover retrieval ranking, validation flagging/
non-flagging (including the single-contribution edge case), fusion
ordering/exclusion, and mock-LLM determinism.

## Persistence

In-memory only, process-lifetime scoped — a documented simplification.
The Rust core's SQLite database already has an (unused, forward-looking)
`rag_contributions` table scaffolded in `storage::db` if durable RAG
history is wanted later.
