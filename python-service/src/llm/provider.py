"""LLMProvider interface.

Any concrete provider takes a query plus already-fused context text and
returns a generated string. The RAG pipeline (`app.py`) depends only on
this interface, so swapping `MockLLMProvider` for a real local model
provider (see `ollama_provider.py`) requires no change anywhere else.
"""

from abc import ABC, abstractmethod


class LLMProvider(ABC):
    @abstractmethod
    def generate(self, query: str, fused_context: str) -> str:
        ...

    @abstractmethod
    def name(self) -> str:
        ...
