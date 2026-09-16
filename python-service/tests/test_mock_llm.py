from llm.mock_provider import MockLLMProvider


def test_mock_llm_is_deterministic():
    llm = MockLLMProvider()
    a = llm.generate("query", "[d1 | trust=0.9] some content")
    b = llm.generate("query", "[d1 | trust=0.9] some content")
    assert a == b


def test_mock_llm_handles_empty_context():
    llm = MockLLMProvider()
    out = llm.generate("query", "")
    assert "No validated contributions" in out


def test_mock_llm_name_identifies_itself_as_mock():
    llm = MockLLMProvider()
    assert "mock" in llm.name().lower()
