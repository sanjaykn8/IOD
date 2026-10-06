# RAG-Assisted Steganography Selection (Registration-Time RAG)

This is RAG's **primary role** as of this stage (see `docs/rag.md`'s
"Historical subsystem" section for the original, now-secondary,
collaborative-drone-contribution role). "RAG-assisted" here means
specifically: **retrieval and narrative generation, never the decision
itself.** The decision is `rag/selector.py`'s job
(`docs/algorithm-selection.md`); this module cannot make it and cannot
influence it.

## What `rag/stego_knowledge.py` actually does

1. **`retrieve_evidence(algorithm_id, query, top_k=2)`**: splits that
   algorithm's hand-written knowledge-base markdown file
   (`python-service/knowledge/steganography/algorithms/<id>.md`) into
   `##`-headed sections, scores each section against the query by the
   same lexical word-overlap (Jaccard) similarity this project's
   original RAG module (`rag/retrieval.py`) already uses, and returns
   the top-`k` sections. **Deliberately not embeddings or a vector
   store** -- labeled as such in the module docstring, not just here,
   for the same reason `docs/rag.md` labels the original retrieval the
   same way. A missing knowledge-base file returns `[]` rather than
   raising: a documentation gap is not a reason to fail a
   registration.
2. **`explain_selection(algorithm_id, importance, measurement, query=None)`**:
   builds the narrative shown to the operator, quoting the REAL,
   already-computed measurement dict for the winning algorithm
   (`stego.benchmark.AlgorithmMeasurement.to_dict()`, as the selector
   already has it) -- every number in the narrative (`capacity_bytes`,
   `payload_bytes`, `embed_time_ms`, `extract_time_ms`, `ssim`,
   `psnr_db`, `mse`) is read from that dict verbatim. Returns
   `{algorithm_id, narrative, measurement_used, evidence}`.

## Why this module is architecturally unable to fabricate a number

It has no embed/extract/timing code of its own and does not import
`stego.benchmark`'s measurement internals -- it only ever receives a
measurement dict as a plain argument, already computed by the caller.
If a future change gave this module the ability to invent a number,
that would be a regression from this design, not an extension of it.
This is a stronger, narrower property than "the retrieval is
accurate": the retrieval can be topically weak (word-overlap always
can be), but it cannot misreport what the benchmark actually measured,
because it never sees anything else.

## Knowledge base

`python-service/knowledge/steganography/algorithms/{adaptive_lsb,pvd,
dct,dwt,svd}.md` -- one hand-written file per algorithm, covering its
technique, typical capacity/distortion trade-offs, and known
limitations (the same honest-limitations material summarized in
`docs/steganography.md`, written once and retrieved from here, not
duplicated by hand into every narrative). Extending the knowledge base
is adding or editing these files; there is no training step, index
build, or embedding pipeline to re-run.

## Call order (matters for the "never invent a number" property)

`stego_api.py`'s `POST /stego/select-and-embed`:

```
measurements = stego.benchmark.measure_all(cover_pixels, payload)   # REAL numbers, first
selection     = rag.selector.select_algorithm(measurements, importance)  # REAL decision, from those numbers
explanation   = rag.stego_knowledge.explain_selection(winner_id, importance, winner_measurement)  # narrative, from that decision's own measurement
```

Selection always happens before the explanation is built, and the
explanation only ever receives the winner's own already-computed
measurement -- there is no path through this code where a narrative
could be generated for a number nobody measured.

## Tests

`python-service/tests/test_stego_knowledge.py`: retrieval ranking
against real knowledge-base content, narrative construction quoting
exact measurement fields, and the missing-knowledge-base-file
non-raising path. Run with `cd python-service && pytest`.
