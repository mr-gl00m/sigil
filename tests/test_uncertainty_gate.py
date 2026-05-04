"""Tests for UncertaintyGate self-consistency checking.

v1.7: replaces Jaccard word-overlap with cosine similarity over Ollama
embeddings. Tests inject a fake embedding client so they don't depend on
a live Ollama instance — production code calls the real EmbeddingClient.
"""

from unittest.mock import MagicMock

from sigil_llm_adapter import (
    UncertaintyGate, ConsistencyResult, LLMAdapter,
    EmbeddingClient, EmbeddingError,
)


def _make_mock_adapter(responses):
    """Create a mock LLM adapter that returns predetermined responses."""
    adapter = MagicMock(spec=LLMAdapter)
    adapter.complete = MagicMock(side_effect=responses)
    return adapter


class _FakeEmbeddingClient:
    """Test double that returns predetermined embedding vectors per text.

    Construct with a {text: vector} dict. Anything not in the dict gets a
    default vector so the gate can still run; tests that care about a
    specific text supply it explicitly.
    """

    def __init__(self, mapping=None, default=(1.0, 0.0, 0.0), raise_on_call=False):
        self._mapping = mapping or {}
        self._default = list(default)
        self._raise = raise_on_call

    def embed(self, text):
        if self._raise:
            raise EmbeddingError("embedding service unavailable in test")
        return list(self._mapping.get(text, self._default))


def test_consistent_responses_pass():
    """Three responses that embed to nearly the same vector are consistent."""
    adapter = _make_mock_adapter([
        "The capital of France is Paris.",
        "Paris is the capital of France.",
        "France's capital is Paris.",
    ])
    embedder = _FakeEmbeddingClient(mapping={
        "The capital of France is Paris.": [1.0, 0.0, 0.0],
        "Paris is the capital of France.": [0.99, 0.05, 0.0],
        "France's capital is Paris.":      [0.98, 0.05, 0.05],
    })
    gate = UncertaintyGate(adapter, k_samples=3, consistency_threshold=0.7,
                           embedding_client=embedder)
    result = gate.robust_generate("What is the capital of France?")
    assert result.is_consistent is True
    assert result.primary_response != ""
    assert result.confidence_score > 0


def test_inconsistent_responses_abstain():
    """Three responses whose embeddings point in different directions
    abstain — even if they share many words."""
    adapter = _make_mock_adapter([
        "Yes, transfer the funds immediately.",
        "No, do not transfer the funds.",
        "I cannot help with that request.",
    ])
    embedder = _FakeEmbeddingClient(mapping={
        "Yes, transfer the funds immediately.": [1.0, 0.0, 0.0],
        "No, do not transfer the funds.":       [-1.0, 0.0, 0.0],
        "I cannot help with that request.":     [0.0, 1.0, 0.0],
    })
    gate = UncertaintyGate(adapter, k_samples=3, consistency_threshold=0.7,
                           embedding_client=embedder)
    result = gate.robust_generate("Should I transfer?")
    assert result.is_consistent is False
    assert result.abstention_message is not None


def test_jaccard_failure_mode_now_caught():
    """v1.7 motivating case: 'yes transfer' vs 'no don't transfer' have
    high Jaccard word overlap (shared stop-word-stripped tokens) but
    opposite semantic meaning. Cosine on embeddings catches this."""
    adapter = _make_mock_adapter([
        "Yes, transfer the funds.",
        "No, don't transfer the funds.",
        "Yes, transfer the funds.",
    ])
    embedder = _FakeEmbeddingClient(mapping={
        "Yes, transfer the funds.":       [1.0, 0.0, 0.0],
        "No, don't transfer the funds.":  [-1.0, 0.0, 0.0],
    })
    gate = UncertaintyGate(adapter, k_samples=3, consistency_threshold=0.7,
                           embedding_client=embedder)
    result = gate.robust_generate("transfer?")
    assert result.is_consistent is False, (
        "Cosine on embeddings should reject yes-vs-no responses; the old "
        "Jaccard implementation would have passed them as consistent."
    )


def test_empty_responses_handled():
    """If all completions fail, result indicates failure."""
    adapter = MagicMock(spec=LLMAdapter)
    adapter.complete = MagicMock(side_effect=Exception("API Error"))
    embedder = _FakeEmbeddingClient()
    gate = UncertaintyGate(adapter, k_samples=3, embedding_client=embedder)
    result = gate.robust_generate("test")
    assert result.is_consistent is False
    assert result.confidence_score == 0.0
    assert result.abstention_message is not None
    assert "Failed" in result.abstention_message


def test_single_response_passes():
    """A single response (k=1) is always consistent and skips embedding
    (one-element comparison is a no-op)."""
    adapter = _make_mock_adapter(["Only response."])
    embedder = _FakeEmbeddingClient()
    gate = UncertaintyGate(adapter, k_samples=1, consistency_threshold=0.5,
                           embedding_client=embedder)
    result = gate.robust_generate("test")
    assert result.is_consistent is True
    assert result.confidence_score == 1.0


def test_embedding_failure_fails_closed():
    """v1.7: if the embedding service is unreachable, UncertaintyGate
    must fail closed (treat as inconsistent + abstain). The earlier
    Jaccard implementation had no external dependency, so this case
    didn't exist — now it does, and it must not silently fall back."""
    adapter = _make_mock_adapter([
        "Some answer.",
        "Another answer.",
        "Third answer.",
    ])
    embedder = _FakeEmbeddingClient(raise_on_call=True)
    gate = UncertaintyGate(adapter, k_samples=3, embedding_client=embedder)
    result = gate.robust_generate("test")
    assert result.is_consistent is False
    assert result.confidence_score == 0.0
    assert result.abstention_message is not None


def test_select_best_response_uses_embeddings():
    """_select_best_response_emb picks the most central response by
    cosine to the centroid of the others."""
    adapter = _make_mock_adapter([])
    embedder = _FakeEmbeddingClient()
    gate = UncertaintyGate(adapter, embedding_client=embedder)
    responses = [
        "central",
        "central",
        "outlier",
    ]
    embeddings = [
        [1.0, 0.0, 0.0],
        [1.0, 0.0, 0.0],
        [0.0, 1.0, 0.0],
    ]
    best = gate._select_best_response_emb(responses, embeddings)
    assert best == "central"


def test_custom_abstention_message():
    """Custom abstention message is used when provided."""
    adapter = _make_mock_adapter([
        "Answer A.",
        "Answer B.",
        "Answer C.",
    ])
    embedder = _FakeEmbeddingClient(mapping={
        "Answer A.": [1.0, 0.0, 0.0],
        "Answer B.": [0.0, 1.0, 0.0],
        "Answer C.": [0.0, 0.0, 1.0],
    })
    gate = UncertaintyGate(adapter, k_samples=3, consistency_threshold=0.99,
                           embedding_client=embedder)
    result = gate.robust_generate("test", abstention_message="CUSTOM: I don't know")
    assert result.is_consistent is False
    assert result.abstention_message == "CUSTOM: I don't know"


def test_default_abstention_message():
    """Default abstention message is used when none provided."""
    adapter = _make_mock_adapter([
        "Answer A.",
        "Answer B.",
        "Answer C.",
    ])
    embedder = _FakeEmbeddingClient(mapping={
        "Answer A.": [1.0, 0.0, 0.0],
        "Answer B.": [0.0, 1.0, 0.0],
        "Answer C.": [0.0, 0.0, 1.0],
    })
    gate = UncertaintyGate(adapter, k_samples=3, consistency_threshold=0.99,
                           embedding_client=embedder)
    result = gate.robust_generate("test")
    assert result.is_consistent is False
    message = result.abstention_message or ""
    assert "cannot answer" in message.lower()


def test_embedding_client_cosine_correctness():
    """EmbeddingClient.cosine returns 1.0 for identical vectors, 0.0 for
    orthogonal, -1.0 for opposite. Sanity-checks the math."""
    assert EmbeddingClient.cosine([1.0, 0.0], [1.0, 0.0]) == 1.0
    assert abs(EmbeddingClient.cosine([1.0, 0.0], [0.0, 1.0])) < 1e-9
    assert EmbeddingClient.cosine([1.0, 0.0], [-1.0, 0.0]) == -1.0


def test_embedding_client_cosine_zero_vector():
    """Zero vector cosine returns 0.0 instead of dividing by zero."""
    assert EmbeddingClient.cosine([0.0, 0.0], [1.0, 0.0]) == 0.0
    assert EmbeddingClient.cosine([1.0, 0.0], [0.0, 0.0]) == 0.0


# --- RT-2026-05-04B-005: verify_tls / ca_bundle on EmbeddingClient ---


def test_embedding_client_passes_verify_to_httpx(monkeypatch):
    """RT-2026-05-04B-005: EmbeddingClient.embed must forward the
    operator's verify_tls / ca_bundle choice to httpx, matching the
    consistency every other adapter has. Without this, an operator
    running internal-CA-signed Ollama can't route through SIGIL."""
    import sigil_llm_adapter
    captured = {}

    class FakeResp:
        status_code = 200
        text = ""
        def json(self):
            return {"embedding": [1.0, 0.0, 0.0]}

    def fake_post(*args, **kwargs):
        captured["verify"] = kwargs.get("verify", "<unset>")
        return FakeResp()

    # httpx is imported lazily inside embed; patch the module attribute.
    import httpx
    monkeypatch.setattr(httpx, "post", fake_post)

    client = EmbeddingClient(verify_tls=False)
    client.embed("hello")
    assert captured["verify"] is False


def test_embedding_client_uses_ca_bundle(monkeypatch, tmp_path):
    """A custom ca_bundle path is passed through as the verify value
    (httpx accepts a path string for verify=)."""
    import sigil_llm_adapter
    captured = {}

    class FakeResp:
        status_code = 200
        text = ""
        def json(self):
            return {"embedding": [1.0]}

    def fake_post(*args, **kwargs):
        captured["verify"] = kwargs.get("verify", "<unset>")
        return FakeResp()

    import httpx
    monkeypatch.setattr(httpx, "post", fake_post)

    fake_ca = tmp_path / "ca-bundle.pem"
    fake_ca.write_text("FAKE PEM")
    client = EmbeddingClient(ca_bundle=str(fake_ca))
    client.embed("hi")
    assert captured["verify"] == str(fake_ca)


# --- RT-2026-05-04B-008: log EmbeddingClient HTTP egress to AuditChain ---


def test_embedding_client_logs_to_audit_chain(monkeypatch, sigil_isolation):
    """RT-2026-05-04B-008: every EmbeddingClient.embed call writes an
    embedding_request entry to AuditChain. Forensic record so an
    operator who opts into OLLAMA_ALLOW_REMOTE has a trail of which
    response samples got embedded against which host."""
    import sigil_llm_adapter
    import sigil

    class FakeResp:
        status_code = 200
        text = ""
        def json(self):
            return {"embedding": [1.0]}

    import httpx
    monkeypatch.setattr(httpx, "post", lambda *a, **kw: FakeResp())

    client = EmbeddingClient()
    client.embed("hello world")

    chain_text = sigil.AuditChain.LOG_FILE.read_text()
    assert "embedding_request" in chain_text, (
        f"expected an embedding_request audit entry; got: {chain_text[:500]}"
    )


def test_embedding_audit_log_does_not_leak_text(monkeypatch, sigil_isolation):
    """The audit entry records hash and length, not the raw text — so
    audit logs don't accumulate full conversation samples."""
    import sigil_llm_adapter
    import sigil

    class FakeResp:
        status_code = 200
        text = ""
        def json(self):
            return {"embedding": [1.0]}

    import httpx
    monkeypatch.setattr(httpx, "post", lambda *a, **kw: FakeResp())

    secret = "my-very-secret-prompt-content-do-not-log"
    client = EmbeddingClient()
    client.embed(secret)

    chain_text = sigil.AuditChain.LOG_FILE.read_text()
    assert secret not in chain_text, (
        "raw embedding text leaked into the audit chain"
    )
