"""Steganographic transport (Python side): bytes <-> pixels only.

No keys, MACs or plaintext ever reach this package; it manipulates opaque
frame bytes and images. See docs/patchwise-transport.md.
"""

SERVICE_VERSION = "5.0.0"  # frame v3 / keyed bootstrap v3 / manifest v2 on locally generated covers (procgen-1)
