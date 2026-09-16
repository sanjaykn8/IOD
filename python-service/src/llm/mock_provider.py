"""MockLLMProvider: deterministic, template-based "generation" — NOT a
real language model. No network calls, no API key, no randomness. This
is the default/active provider for this project, matching the "do not
require a paid API" and "deterministic/mock LLM" requirements exactly.
"""

from .provider import LLMProvider


class MockLLMProvider(LLMProvider):
    def name(self) -> str:
        return "mock-deterministic-v1"

    def generate(self, query: str, fused_context: str) -> str:
        if not fused_context.strip():
            return (
                f"[mock-llm] No validated contributions were available to answer: '{query}'. "
                f"All submitted contributions were excluded by the validation step, or none were submitted."
            )
        lines = [ln for ln in fused_context.split("\n") if ln.strip()]
        return (
            f"[mock-llm] Synthesized assessment for query '{query}', "
            f"drawing on {len(lines)} validated drone contribution(s):\n"
            + "\n".join(f"  - {ln}" for ln in lines)
        )
