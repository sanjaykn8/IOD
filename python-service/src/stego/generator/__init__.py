"""Payload-aware procedural cover generation (operational cover source of the patch-wise transport).

* `families`  -- the CPU-only multi-scale generator (NumPy only; no model, no network, no pretrained data)
* `quality`   -- transparent visual-coherence heuristics and hard gates (not a steganalysis detector)
* `profile`   -- named resource profiles, validated configuration, hard ceilings
* `select`    -- bounded candidate generation -> pre-screen -> real patch planner -> best feasible candidate

The generator is told the payload LENGTH only. It never receives payload bytes, keys or plaintext.
"""

GENERATOR_VERSION = "procgen-1"
QUALITY_VERSION = "cover-quality-1"
