---
title: Steganography Knowledge Base Index
---

# Steganography Knowledge Base

This directory tree is the local, file-based knowledge base the RAG
subsystem (`src/rag/stego_knowledge.py`) retrieves evidence from when
explaining a registration-time algorithm choice to the operator.

```
knowledge/steganography/
  algorithms/   one .md file per algorithm (adaptive_lsb, pvd, dct, dwt, svd):
                technique description + representative literature +
                qualitative trade-offs (capacity/distortion/robustness/speed)
  papers/       consolidated bibliography.md listing every citation
                used across the algorithm files, in one place
  index/        this file
```

**What this knowledge base IS**: a small, hand-curated, honestly-scoped
set of reference documents describing five classical 2D image-
steganography techniques, with representative (not exhaustively
verified page-by-page) citations to the literature each technique is
drawn from.

**What this knowledge base is NOT, and never supplies**: performance
numbers. Every trade-off note in `algorithms/*.md` is deliberately
qualitative ("generally lower distortion than X", "slowest of the
five") rather than quantitative (no "~3dB better PSNR" claims) --
retrieval over this knowledge base is read-only evidence for the
narrative explanation shown in the UI; it is never consulted by, nor
able to override, the deterministic selector in `src/rag/selector.py`,
which decides purely from `src/stego/benchmark.py`'s real measurements
on the actual image and payload at hand. See
`docs/rag-stego-selection.md` for the full architecture and
`docs/claims-and-limitations.md` for this subsystem's REAL vs
RESEARCH-PROTOTYPE classification.
