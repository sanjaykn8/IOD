"""Steganographic transport (Python side): bytes <-> pixels only.

No keys, MACs or plaintext ever reach this package; it manipulates opaque
frame bytes and images. See docs/patchwise-transport.md.
"""

SERVICE_VERSION = "4.0.0"  # patch-wise transport on locally generated covers (frame v2 / bootstrap v2 / manifest v1, procgen-1)
