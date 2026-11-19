"""Patch-wise transport: irregular segmentation, per-patch knowledge-base selection,
in-image manifest (keyed bootstrap-v3 carrier + Frame v3). See docs/patchwise-transport.md
and docs/bootstrap-v3-design.md."""

FORMAT_VERSION = "frame-v3/appwire-v1/bootstrap-v3/manifest-v2"
SEGMENTATION_VERSION = "arg-cells-1"   # adaptive region growing on a cell grid, version id 1
SEGMENTATION_VERSION_ID = 1
SELECTOR_VERSION = "kb-risk-1"         # structured filters + risk-table ranking (tier, distortion, cost) + BM25, id 2
SELECTOR_VERSION_ID = 2
