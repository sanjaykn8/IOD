"""PLACEHOLDER/FUTURE: a real local-LLM backend via Ollama.

Not implemented in this version — no network calls are made from this
project to any LLM API, paid or local, and this class exists purely to
show the extension point. A real implementation would POST to a local
Ollama server's `/api/generate` endpoint and would need no changes to
`app.py` beyond selecting this provider instead of `MockLLMProvider`,
since both implement the same `LLMProvider` interface.
"""

from .provider import LLMProvider


class OllamaLLMProvider(LLMProvider):
    def __init__(self, base_url: str = "http://127.0.0.1:11434", model: str = "llama3"):
        self.base_url = base_url
        self.model = model

    def name(self) -> str:
        return f"ollama:{self.model} (PLACEHOLDER - not implemented)"

    def generate(self, query: str, fused_context: str) -> str:
        raise NotImplementedError(
            "OllamaLLMProvider is a documented future-work placeholder in this version. "
            "Use MockLLMProvider (the active default) instead."
        )
