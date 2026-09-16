"""Data model for one drone's contribution to a collaborative RAG round.

This module holds NO cryptographic material. In the full architecture,
a contribution would arrive over the AEAD-protected secure-messaging
channel implemented in the Rust core (see
`rust-core/src/protocol/secure_messaging.rs`); by the time it reaches
this Python service it is already-decrypted plaintext content plus
metadata. This service does not re-implement or simulate that transport
security layer — see docs/rag.md for the documented boundary between
"secure delivery" (Rust) and "content processing" (Python, this file).
"""

from dataclasses import dataclass, field
import time


@dataclass
class Contribution:
    drone_id: str
    content: str
    # Self-reported confidence in [0, 1]. Like everything else here,
    # this is taken at face value from the simulated drone — a real
    # system would need some independent corroboration signal, which is
    # exactly what `validation.py`'s heuristic scoring approximates in a
    # deliberately simple way.
    confidence: float
    timestamp_unix_ms: int = field(default_factory=lambda: int(time.time() * 1000))
    # Populated by validation.py, not at construction time.
    trust_score: float = 1.0
    flagged_suspicious: bool = False
    flag_reason: str = ""

    def to_dict(self):
        return {
            "drone_id": self.drone_id,
            "content": self.content,
            "confidence": self.confidence,
            "timestamp_unix_ms": self.timestamp_unix_ms,
            "trust_score": self.trust_score,
            "flagged_suspicious": self.flagged_suspicious,
            "flag_reason": self.flag_reason,
        }
