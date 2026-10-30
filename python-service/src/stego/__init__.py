"""Steganographic transport (Python side): bytes <-> pixels only.

No keys, MACs or plaintext ever reach this package; it manipulates opaque
frame bytes and images. See docs/stego-implementation-note.md.
"""

SERVICE_VERSION = "2.0.0"
POLICY_VERSION = "sel-policy-2"  # v2: ten-algorithm candidate set (v1 had five)
