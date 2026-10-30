"""Algorithm Learning workbench (EDUCATIONAL ONLY).

Separate from the operational UAV transport:
  * own Flask namespace (/learn/*), own fixtures, no artifact store, no events table,
    never called by the operational selector or pipeline;
  * reuses the tested low-level algorithm library (stego.algorithms) so the experiments
    execute the real implementations, and the worked walkthroughs call the same helper
    functions (Haar/DCT/SVD/QIM, PVD tables, edge mask, WOW/S-UNIWARD/HUGO costs, STC);
  * payload bytes come from the caller (the Rust core seals a TEST-ONLY envelope, or a
    labelled synthetic fixture is used) -- this package never sees keys.
"""

LEARN_VERSION = "learn-1"
LABEL = "Educational experiment - not a live UAV transmission"
