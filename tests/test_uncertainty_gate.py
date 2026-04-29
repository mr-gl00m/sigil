"""Tests for UncertaintyGate self-consistency checking."""

from unittest.mock import MagicMock

from sigil_llm_adapter import UncertaintyGate, ConsistencyResult, LLMAdapter


def _make_mock_adapter(responses):
    """Create a mock LLM adapter that returns predetermined responses."""
    adapter = MagicMock(spec=LLMAdapter)
    adapter.complete = MagicMock(side_effect=responses)
    return adapter


def test_consistent_responses_pass():
    """Highly similar responses are marked consistent."""
    adapter = _make_mock_adapter([
        "The capital of France is Paris.",
        "The capital of France is Paris.",
        "The capital of France is Paris.",
    ])
    gate = UncertaintyGate(adapter, k_samples=3, consistency_threshold=0.2)
    result = gate.robust_generate("What is the capital of France?")
    assert result.is_consistent is True
    assert result.primary_response != ""
    assert result.confidence_score > 0


def test_inconsistent_responses_abstain():
    """Divergent responses trigger abstention."""
    adapter = _make_mock_adapter([
        "The answer is 42.",
        "I think the answer involves quantum mechanics and string theory.",
        "There is no definitive answer to this philosophical question about existence.",
    ])
    gate = UncertaintyGate(adapter, k_samples=3, consistency_threshold=0.9)
    result = gate.robust_generate("test")
    assert result.is_consistent is False
    assert result.abstention_message is not None


def test_empty_responses_handled():
    """If all completions fail, result indicates failure."""
    adapter = MagicMock(spec=LLMAdapter)
    adapter.complete = MagicMock(side_effect=Exception("API Error"))
    gate = UncertaintyGate(adapter, k_samples=3)
    result = gate.robust_generate("test")
    assert result.is_consistent is False
    assert result.confidence_score == 0.0
    assert result.abstention_message is not None
    assert "Failed" in result.abstention_message


def test_single_response_passes():
    """A single response (k=1) is always consistent."""
    adapter = _make_mock_adapter(["Only response."])
    gate = UncertaintyGate(adapter, k_samples=1, consistency_threshold=0.5)
    result = gate.robust_generate("test")
    assert result.is_consistent is True
    assert result.confidence_score == 1.0


def test_calculate_similarity_identical():
    """Identical texts have similarity ~1.0."""
    adapter = _make_mock_adapter([])
    gate = UncertaintyGate(adapter)
    sim = gate._calculate_similarity("hello world test", "hello world test")
    assert sim == 1.0


def test_calculate_similarity_different():
    """Different texts have similarity < 1.0."""
    adapter = _make_mock_adapter([])
    gate = UncertaintyGate(adapter)
    sim = gate._calculate_similarity("cats are fluffy", "quantum physics rocks")
    assert sim < 1.0


def test_calculate_similarity_empty():
    """Empty sets return 0.0 similarity."""
    adapter = _make_mock_adapter([])
    gate = UncertaintyGate(adapter)
    # After removing stop words, these might be empty
    sim = gate._calculate_similarity("the a an is", "to of in for")
    assert sim == 0.0


def test_select_best_response():
    """_select_best_response picks the most central response."""
    adapter = _make_mock_adapter([])
    gate = UncertaintyGate(adapter)
    responses = [
        "Paris is the capital of France",
        "The capital of France is Paris city",
        "Something completely different about cats",
    ]
    best = gate._select_best_response(responses)
    # The first two are similar; one of them should be selected
    assert "Paris" in best or "capital" in best


def test_custom_abstention_message():
    """Custom abstention message is used when provided."""
    adapter = _make_mock_adapter([
        "Answer A about topic X",
        "Completely different answer B about topic Y",
        "Yet another answer C about topic Z entirely",
    ])
    gate = UncertaintyGate(adapter, k_samples=3, consistency_threshold=0.99)
    result = gate.robust_generate("test", abstention_message="CUSTOM: I don't know")
    if not result.is_consistent:
        assert result.abstention_message == "CUSTOM: I don't know"


def test_default_abstention_message():
    """Default abstention message is used when none provided."""
    adapter = _make_mock_adapter([
        "Answer A about topic X",
        "Completely different answer B about topic Y",
        "Yet another answer C about topic Z entirely",
    ])
    gate = UncertaintyGate(adapter, k_samples=3, consistency_threshold=0.99)
    result = gate.robust_generate("test")
    if not result.is_consistent:
        message = result.abstention_message or ""
        assert "cannot answer" in message.lower()
