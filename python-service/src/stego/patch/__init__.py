"""Patch-wise transport: irregular segmentation, per-patch knowledge-base selection,
in-image manifest (bootstrap v2 + Frame v2). See docs/patchwise-transport.md."""

FORMAT_VERSION = "frame-v2/appwire-v1/bootstrap-v2/manifest-v1"
SEGMENTATION_VERSION = "arg-cells-1"   # adaptive region growing on a cell grid, version id 1
SEGMENTATION_VERSION_ID = 1
SELECTOR_VERSION = "kb-bm25-1"         # structured filters + BM25 top-1, version id 1
SELECTOR_VERSION_ID = 1
