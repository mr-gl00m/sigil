#!/usr/bin/env python3
"""
SIGIL Audit Proxy - Model Performance & Integrity Auditor

A transparent proxy layer that sits between your application and LLM providers
to log latency, track token costs, and verify response consistency.

Features:
  - Request/response logging with timestamps
  - Latency tracking (time-to-first-byte, total response time)
  - Token usage and cost calculation
  - Response fingerprinting for consistency checks
  - Integration with SIGIL AuditChain for tamper-evident logs
  - Provider-agnostic design (OpenAI, Anthropic, Google, Ollama)

Philosophy: You paid for the API call. You have the right to know exactly
what you're getting in return.

License: MIT
"""

import json
import time
import hashlib
import os
import threading
import queue
import atexit
import re
import zipfile
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple, TYPE_CHECKING
from pathlib import Path
from enum import Enum
from abc import ABC, abstractmethod
import statistics
import collections

try:
    import tiktoken
except ImportError:
    tiktoken = None

if TYPE_CHECKING:
    from sigil_llm_adapter import LLMAdapter

try:
    import httpx
except ImportError:
    httpx = None  # Will raise clear error if used without install

from sigil import AuditChain, AUDIT_DIR, FileLock, SIGIL_DIR

# =============================================================================
# CONFIGURATION
# =============================================================================

AUDIT_LOG_DIR = AUDIT_DIR / "proxy_logs"
CONFIG_DIR = SIGIL_DIR / "config"
AUDIT_LOG_DIR.mkdir(parents=True, exist_ok=True)
CONFIG_DIR.mkdir(parents=True, exist_ok=True)

class Provider(Enum):
    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    GOOGLE = "google"
    OLLAMA = "ollama"
    UNKNOWN = "unknown"


# =============================================================================
# DATA STRUCTURES
# =============================================================================

@dataclass
class RequestMetadata:
    """Captures metadata about an outgoing request."""
    request_id: str
    timestamp_utc: str
    provider: str
    model: str
    endpoint: str
    input_tokens_estimated: int
    request_body_hash: str  # SHA256 of request body (for deduplication)
    headers_logged: Dict[str, str] = field(default_factory=dict)


@dataclass
class ResponseMetadata:
    """Captures metadata about an incoming response."""
    request_id: str
    timestamp_utc: str
    status_code: int
    latency_ms: float  # Total round-trip time
    time_to_first_byte_ms: Optional[float]  # For streaming responses
    input_tokens: Optional[int]  # From provider's response
    output_tokens: Optional[int]  # From provider's response
    output_tokens_estimated: int  # Our estimate
    response_fingerprint: str  # SHA256 of response content
    headers_logged: Dict[str, str] = field(default_factory=dict)


@dataclass
class AuditRecord:
    """Complete audit record for a single API interaction."""
    request_id: str
    timestamp_utc: str
    provider: str
    model: str
    
    # Timing
    latency_ms: float
    time_to_first_byte_ms: Optional[float]
    
    # Tokens
    input_tokens: int
    output_tokens: int
    total_tokens: int
    
    # Cost
    estimated_cost_usd: float
    
    # Integrity
    request_hash: str
    response_fingerprint: str
    
    # Status
    status_code: int
    success: bool
    error_message: Optional[str] = None
    
    # Optional detailed logging
    request_preview: Optional[str] = None  # First N chars of request
    response_preview: Optional[str] = None  # First N chars of response
    alerts: List[str] = field(default_factory=list)
    anomaly_score: float = 0.0
    anomaly_reasons: List[str] = field(default_factory=list)


@dataclass
class PerformanceStats:
    """Aggregated performance statistics."""
    total_requests: int
    successful_requests: int
    failed_requests: int
    
    # Latency stats (ms)
    avg_latency_ms: float
    min_latency_ms: float
    max_latency_ms: float
    p50_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    
    # Token stats
    total_input_tokens: int
    total_output_tokens: int
    avg_input_tokens: float
    avg_output_tokens: float
    
    # Cost stats
    total_cost_usd: float
    avg_cost_per_request_usd: float
    
    # Time range
    first_request_utc: str
    last_request_utc: str
    
    # Provider breakdown
    requests_by_provider: Dict[str, int] = field(default_factory=dict)
    cost_by_provider: Dict[str, float] = field(default_factory=dict)


# =============================================================================
# TOKEN ESTIMATION
# =============================================================================

class TokenEstimator:
    """
    Estimates token counts, preferring exact tokenizers when available.
    Falls back to a heuristic when tiktoken is unavailable.
    """

    CHARS_PER_TOKEN = 4.0
    _ENCODINGS: Dict[str, Any] = {}

    @classmethod
    def _get_encoding(cls, model: str):
        if not tiktoken:
            return None
        if model not in cls._ENCODINGS:
            try:
                cls._ENCODINGS[model] = tiktoken.encoding_for_model(model)
            except KeyError:
                cls._ENCODINGS[model] = tiktoken.get_encoding("cl100k_base")
        return cls._ENCODINGS[model]

    @classmethod
    def estimate_tokens(cls, text: str, model: str = "gpt-4") -> int:
        if not text:
            return 0

        enc = cls._get_encoding(model)
        if enc:
            try:
                return len(enc.encode(text))
            except Exception:
                pass

        return max(1, int(len(text) / cls.CHARS_PER_TOKEN))

    @classmethod
    def estimate_from_messages(cls, messages: List[Dict], model: str = "gpt-4") -> int:
        total = 0
        for msg in messages:
            content = msg.get("content", "")
            if isinstance(content, str):
                total += cls.estimate_tokens(content, model=model)
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and "text" in part:
                        total += cls.estimate_tokens(part["text"], model=model)
        return total


# =============================================================================
# COST CALCULATOR
# =============================================================================

class CostCalculator:
    """Calculates API costs from externalized pricing config."""

    _PRICING_CACHE: Optional[Dict[str, Dict[str, Dict[str, float]]]] = None
    _PRICING_CACHE_TIME: float = 0.0
    _PRICING_CACHE_TTL: float = 300.0  # 5 minutes

    _DEFAULT = {
        "anthropic": {"default": {"input": 0.003, "output": 0.015}},
        "openai": {"default": {"input": 0.01, "output": 0.03}},
        "google": {"default": {"input": 0.00125, "output": 0.005}},
        "ollama": {"default": {"input": 0.0, "output": 0.0}},
    }

    @classmethod
    def reload(cls):
        """Force reload pricing from disk on next access."""
        cls._PRICING_CACHE = None
        cls._PRICING_CACHE_TIME = 0.0

    @classmethod
    def _verify_pricing_integrity(cls, pricing_data: dict, pricing_path: Path) -> bool:
        """Verify pricing data against its signature file (M-03).

        Returns True if:
        - No .sig file exists (backward compatible — logs warning)
        - .sig file exists and signature is valid
        Returns False if .sig file exists but signature is invalid.
        """
        sig_path = pricing_path.with_suffix('.sig')
        if not sig_path.exists():
            try:
                AuditChain.log("pricing_unsigned", {"path": str(pricing_path)})
            except Exception:
                pass
            return True

        try:
            sig_data = json.loads(sig_path.read_text())
            signature = sig_data.get("signature", "")
            signer_key_id = sig_data.get("signer_key_id", "")

            from sigil import Keyring
            # Determine key name from key_id or use default
            key_name = sig_data.get("key_name", "architect")
            vk = Keyring.load_verifier(key_name)

            canonical = json.dumps(pricing_data, sort_keys=True, separators=(',', ':')).encode()
            vk.verify(canonical, bytes.fromhex(signature))
            return True
        except Exception:
            try:
                AuditChain.log("pricing_integrity_failure", {"path": str(pricing_path)})
            except Exception:
                pass
            return False

    @classmethod
    def sign_pricing(cls, key_name: str = "architect"):
        """Sign current pricing.json and write .sig file (M-03)."""
        from sigil import Keyring
        pricing_path = CONFIG_DIR / "pricing.json"
        if not pricing_path.exists():
            raise FileNotFoundError(f"Pricing file not found: {pricing_path}")

        pricing_data = json.loads(pricing_path.read_text())
        signer = Keyring.load_signer(key_name)
        key_id = Keyring.get_key_id(key_name)

        canonical = json.dumps(pricing_data, sort_keys=True, separators=(',', ':')).encode()
        signature = signer.sign(canonical).signature.hex()

        sig_path = pricing_path.with_suffix('.sig')
        sig_path.write_text(json.dumps({
            "signature": signature,
            "signer_key_id": key_id,
            "key_name": key_name,
        }, indent=2))

    @classmethod
    def _load_pricing(cls) -> Dict[str, Dict[str, Dict[str, float]]]:
        now = time.time()
        if cls._PRICING_CACHE is not None and (now - cls._PRICING_CACHE_TIME) < cls._PRICING_CACHE_TTL:
            return cls._PRICING_CACHE

        pricing_path = CONFIG_DIR / "pricing.json"
        if pricing_path.exists():
            try:
                loaded = json.loads(pricing_path.read_text())
                if isinstance(loaded, dict):
                    # Verify pricing integrity (M-03)
                    if not cls._verify_pricing_integrity(loaded, pricing_path):
                        # Tampered — fall back to defaults
                        cls._PRICING_CACHE = cls._DEFAULT
                        cls._PRICING_CACHE_TIME = now
                        return cls._PRICING_CACHE
                    cls._PRICING_CACHE = loaded
                    cls._PRICING_CACHE_TIME = now
                    return loaded
            except Exception:
                pass

        pricing_path.write_text(json.dumps(cls._DEFAULT, indent=2))
        cls._PRICING_CACHE = cls._DEFAULT
        cls._PRICING_CACHE_TIME = now
        return cls._PRICING_CACHE

    @classmethod
    def calculate(
        cls,
        provider: str,
        model: str,
        input_tokens: int,
        output_tokens: int
    ) -> float:
        pricing_data = cls._load_pricing()
        provider_lower = provider.lower()
        provider_rates = pricing_data.get(provider_lower, pricing_data.get("openai", {}))

        rates = provider_rates.get(model)
        if not rates:
            for key, val in provider_rates.items():
                if key != "default" and key in model:
                    rates = val
                    break
        rates = rates or provider_rates.get("default", {"input": 0.0, "output": 0.0})

        input_cost = (input_tokens / 1000.0) * rates.get("input", 0.0)
        output_cost = (output_tokens / 1000.0) * rates.get("output", 0.0)
        return round(input_cost + output_cost, 6)


# =============================================================================
# RESPONSE FINGERPRINTING
# =============================================================================

class ResponseFingerprinter:
    """
    Creates fingerprints of API responses for consistency verification.
    
    This helps detect:
    - Response drift over time (model updates)
    - Differential treatment (same prompt, different responses for different users)
    - Silent content filtering changes
    """
    
    @staticmethod
    def fingerprint(content: str) -> str:
        """Create a SHA256 fingerprint of response content."""
        return hashlib.sha256(content.encode('utf-8')).hexdigest()
    
    @staticmethod
    def fingerprint_normalized(content: str) -> str:
        """
        Create a fingerprint of normalized content.
        
        Normalizes whitespace and case for "semantic" similarity detection.
        Two responses that say the same thing differently will have similar
        normalized fingerprints.
        """
        # Normalize: lowercase, collapse whitespace, strip
        normalized = ' '.join(content.lower().split())
        return hashlib.sha256(normalized.encode('utf-8')).hexdigest()


# =============================================================================
# AUDIT PROXY - The Core Component
# =============================================================================

class AuditProxy:
    """
    Transparent proxy that wraps LLM API calls with comprehensive auditing.
    
    Usage:
        proxy = AuditProxy()
        
        # Wrap an existing adapter
        audited_adapter = proxy.wrap(ClaudeAdapter(api_key="..."))
        
        # Or use the proxy directly
        response = proxy.audited_request(
            provider="anthropic",
            endpoint="https://api.anthropic.com/v1/messages",
            headers={...},
            body={...}
        )
    """
    
    # Headers that must be redacted before logging (H-03)
    REDACTED_HEADERS = {
        "authorization", "x-api-key", "api-key", "x-goog-api-key",
        "cookie", "set-cookie", "proxy-authorization",
    }

    # Regex for scrubbing sensitive values from request bodies (H-03)
    _SENSITIVE_BODY_RE = re.compile(
        r'(?i)(api[_-]?key|secret|token|password|authorization)\s*[=:]\s*\S+',
    )

    def __init__(
        self,
        log_to_chain: bool = True,
        log_to_file: bool = True,
        preview_length: int = 200,
        log_full_content: bool = False,
        redact_patterns: Optional[List[str]] = None,
        custom_contradiction_phrases: Optional[List[str]] = None,
        custom_compliance_markers: Optional[List[str]] = None,
    ):
        """
        Initialize the audit proxy.

        Args:
            log_to_chain: Log records to SIGIL AuditChain (tamper-evident)
            log_to_file: Log records to JSON files
            preview_length: Characters to include in request/response previews
            log_full_content: If True, log full request/response (privacy warning!)
            redact_patterns: Optional list of regex patterns for custom sensitive fields.
            custom_contradiction_phrases: Extra contradiction phrases for loyalty analysis (M-04).
            custom_compliance_markers: Extra compliance markers for loyalty analysis (M-04).
        """
        self.log_to_chain = log_to_chain
        self.log_to_file = log_to_file
        self.preview_length = preview_length
        self.log_full_content = log_full_content
        self._custom_redact_patterns = [re.compile(p) for p in (redact_patterns or [])]

        self._audit_chain = AuditChain if log_to_chain else None
        self._records: collections.deque[AuditRecord] = collections.deque(maxlen=10000)
        self._lock = threading.Lock()
        self._request_counter = 0
        self._log_queue: "queue.Queue[AuditRecord]" = queue.Queue(maxsize=1000)
        self._stop_event = threading.Event()

        # Configurable contradiction phrases and compliance markers (M-04)
        self._contradiction_phrases: List[str] = [
            "ignore previous instructions",
            "override",
            "unrestricted",
            "bypass",
            "you are now",
            "transfer $",
            "disregard your training",
            "new system prompt",
            "developer mode",
            "jailbreak",
            "DAN",
            "ignore your rules",
            "forget your instructions",
        ]
        if custom_contradiction_phrases:
            self._contradiction_phrases.extend(custom_contradiction_phrases)

        self._compliance_markers: List[str] = [
            "sure", "okay", "done", "completed", "here you go",
            "transferred", "i will", "executed",
        ]
        if custom_compliance_markers:
            self._compliance_markers.extend(custom_compliance_markers)

        self._negative_compliance_markers: List[str] = [
            "cannot", "can't", "refuse", "not allowed", "i'm unable",
            "against my instructions", "i won't", "not permitted",
            "sorry, but", "i'm not able",
        ]

        self._political_buzzwords: List[str] = [
            "stakeholder alignment",
            "brand safety",
            "responsible ai",
            "responsible artificial intelligence",
            "compliance posture",
            "governance framework",
            "risk posture",
            "policy escalation",
            "trust and safety",
            "safety policies",
            "corporate values",
            "reputational risk",
            "ai principles"
        ]
        
        # Load existing records from file if present
        self._load_existing_records()

        # Start async logger worker
        self._log_thread = threading.Thread(target=self._log_worker, daemon=True)
        self._log_thread.start()
        atexit.register(self.shutdown)
    
    def _generate_request_id(self) -> str:
        """Generate a unique request ID."""
        with self._lock:
            self._request_counter += 1
            timestamp = int(time.time() * 1000)
            return f"req_{timestamp}_{self._request_counter:06d}"

    def _redact_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Return a copy of headers with sensitive values replaced by [REDACTED] (H-03)."""
        redacted = {}
        for key, value in headers.items():
            if key.lower() in self.REDACTED_HEADERS:
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = value
        return redacted

    def _redact_body(self, body_str: str) -> str:
        """Scrub sensitive key/value patterns from a body string (H-03)."""
        result = self._SENSITIVE_BODY_RE.sub(
            lambda m: m.group(1) + m.group(0)[len(m.group(1)):m.group(0).index(m.group(0).split()[-1])] + "[REDACTED]",
            body_str,
        )
        # Simpler approach: replace value portion
        result = re.sub(
            r'(?i)(api[_-]?key|secret|token|password|authorization)\s*([=:])\s*\S+',
            r'\1\2 [REDACTED]',
            body_str,
        )
        for pattern in self._custom_redact_patterns:
            result = pattern.sub("[REDACTED]", result)
        return result
    
    def _load_existing_records(self):
        """Load existing audit records from the log file (last 10000 only)."""
        log_file = AUDIT_LOG_DIR / "audit_records.jsonl"
        if log_file.exists():
            try:
                lines: list = []
                with open(log_file, 'r') as f:
                    for line in f:
                        if line.strip():
                            lines.append(line)
                # Only load the most recent records up to maxlen
                for line in lines[-10000:]:
                    try:
                        data = json.loads(line)
                        self._records.append(AuditRecord(**data))
                    except (json.JSONDecodeError, TypeError):
                        continue
            except (json.JSONDecodeError, TypeError, OSError):
                pass  # Start fresh if file is corrupted

    def _log_worker(self):
        """Background worker that flushes audit records to disk and chain."""
        log_file = AUDIT_LOG_DIR / "audit_records.jsonl"
        while not self._stop_event.is_set() or not self._log_queue.empty():
            try:
                record: AuditRecord = self._log_queue.get(timeout=0.25)
            except queue.Empty:
                continue

            if self.log_to_file:
                with FileLock(log_file):
                    with open(log_file, 'a') as f:
                        f.write(json.dumps(asdict(record)) + "\n")

            if self.log_to_chain and self._audit_chain:
                self._audit_chain.log(
                    event="api_call",
                    data={
                        "request_id": record.request_id,
                        "provider": record.provider,
                        "model": record.model,
                        "latency_ms": record.latency_ms,
                        "tokens": record.total_tokens,
                        "cost_usd": record.estimated_cost_usd,
                        "fingerprint": record.response_fingerprint,
                        "success": record.success,
                        "alerts": list(record.alerts),
                    }
                )

            self._log_queue.task_done()

    def shutdown(self, wait: bool = True):
        """Flush queued logs and stop the background logger."""
        self._stop_event.set()
        if wait:
            self._log_queue.join()
            if hasattr(self, "_log_thread"):
                self._log_thread.join(timeout=2.0)
    
    def _detect_provider(self, endpoint: str) -> str:
        """Detect provider from endpoint URL."""
        endpoint_lower = endpoint.lower()
        if "anthropic" in endpoint_lower:
            return Provider.ANTHROPIC.value
        elif "openai" in endpoint_lower:
            return Provider.OPENAI.value
        elif "googleapis" in endpoint_lower or "generativelanguage" in endpoint_lower:
            return Provider.GOOGLE.value
        elif "localhost" in endpoint_lower or "127.0.0.1" in endpoint_lower:
            return Provider.OLLAMA.value
        return Provider.UNKNOWN.value
    
    def _extract_model(self, body: Dict, provider: str) -> str:
        """Extract model name from request body."""
        if "model" in body:
            return body["model"]
        elif provider == Provider.GOOGLE.value:
            # Gemini model is in the URL, not body
            return "gemini-unknown"
        return "unknown"
    
    def _extract_tokens_from_response(
        self,
        response_data: Dict,
        provider: str
    ) -> Tuple[Optional[int], Optional[int]]:
        """Extract token counts from provider response."""
        try:
            if provider == Provider.ANTHROPIC.value:
                usage = response_data.get("usage", {})
                return usage.get("input_tokens"), usage.get("output_tokens")
            
            elif provider == Provider.OPENAI.value:
                usage = response_data.get("usage", {})
                return usage.get("prompt_tokens"), usage.get("completion_tokens")
            
            elif provider == Provider.GOOGLE.value:
                # Gemini includes usage metadata
                metadata = response_data.get("usageMetadata", {})
                return metadata.get("promptTokenCount"), metadata.get("candidatesTokenCount")
            
            elif provider == Provider.OLLAMA.value:
                return response_data.get("prompt_eval_count"), response_data.get("eval_count")
        
        except (KeyError, TypeError):
            pass
        
        return None, None
    
    def _extract_response_text(self, response_data: Dict, provider: str) -> str:
        """Extract the actual response text from provider response."""
        try:
            if provider == Provider.ANTHROPIC.value:
                content = response_data.get("content", [])
                if content and isinstance(content, list):
                    return content[0].get("text", "")
            
            elif provider == Provider.OPENAI.value:
                choices = response_data.get("choices", [])
                if choices:
                    return choices[0].get("message", {}).get("content", "")
            
            elif provider == Provider.GOOGLE.value:
                candidates = response_data.get("candidates", [])
                if candidates:
                    parts = candidates[0].get("content", {}).get("parts", [])
                    if parts:
                        return parts[0].get("text", "")
            
            elif provider == Provider.OLLAMA.value:
                return response_data.get("response", "")
        
        except (KeyError, TypeError, IndexError):
            pass
        
        return str(response_data)

    def _extract_context_sections(self, body: Dict[str, Any]) -> Tuple[str, str, str]:
        """Pull out raw context, ironclad section, and user data for heuristics."""
        context_text = ""
        if "messages" in body and body.get("messages"):
            msg = body["messages"][0]
            context_text = msg.get("content", "") if isinstance(msg, dict) else ""
        elif "prompt" in body:
            context_text = str(body.get("prompt", ""))
        elif "contents" in body:
            contents = body.get("contents", [])
            if contents and isinstance(contents[0], dict):
                parts = contents[0].get("parts", [])
                if parts and isinstance(parts[0], dict):
                    context_text = str(parts[0].get("text", ""))

        ironclad_text = ""
        user_text = ""
        if context_text:
            ironclad_match = re.search(r"<IRONCLAD_CONTEXT[^>]*>(.*?)</IRONCLAD_CONTEXT>", context_text, re.DOTALL | re.IGNORECASE)
            user_match = re.search(r"<USER_DATA[^>]*>(.*?)</USER_DATA>", context_text, re.DOTALL | re.IGNORECASE)
            ironclad_text = ironclad_match.group(1).strip() if ironclad_match else ""
            user_text = user_match.group(1).strip() if user_match else ""

        return context_text, ironclad_text, user_text

    def _analyze_loyalty(
        self,
        body: Dict[str, Any],
        response_text: str,
        provider: str,
        model: str,
    ) -> List[str]:
        """Flag clear cases where user data contradicts signed context and wins."""
        _, ironclad_text, user_text = self._extract_context_sections(body)
        alerts: List[str] = []

        if not user_text:
            return alerts

        lowered_user = user_text.lower()

        looks_contradictory = any(p in lowered_user for p in self._contradiction_phrases)

        if looks_contradictory:
            lowered_response = response_text.lower()

            # Check negative compliance markers first (M-04) — if the
            # response contains refusal language, suppress CRITICAL and
            # downgrade to LOYALTY_RISK_DETECTED
            has_negative = any(
                marker in lowered_response
                for marker in self._negative_compliance_markers
            )

            if has_negative:
                alerts.append("LOYALTY_RISK_DETECTED")
            elif any(marker in lowered_response for marker in self._compliance_markers):
                alerts.append("CRITICAL_LOYALTY_FAILURE")
            else:
                alerts.append("LOYALTY_RISK_DETECTED")

        # Heuristic: if ironclad mentions limits and response ignores them
        if ironclad_text and "do not" in ironclad_text.lower() and "cannot" in ironclad_text.lower():
            if "sorry" not in response_text.lower() and looks_contradictory:
                if "CRITICAL_LOYALTY_FAILURE" not in alerts:
                    alerts.append("LOYALTY_POLICY_MISMATCH")

        # Detect corporate/political refusal language to flag agenda injection
        lowered_response = response_text.lower()
        if any(phrase in lowered_response for phrase in self._political_buzzwords):
            alerts.append("POLITICAL_INJECTION_DETECTED")

        return alerts

    def _score_anomaly(
        self,
        body: Dict[str, Any],
        response_text: str,
        input_tokens: int,
        output_tokens: int,
        cost_usd: float,
        latency_ms: float,
        alerts: List[str],
    ) -> Tuple[float, List[str]]:
        """Compute a coarse anomaly score to spotlight odd interactions."""
        score = 0.0
        reasons: List[str] = []

        body_text = json.dumps(body)[:4000]  # Avoid huge strings
        if re.search(r"%[0-9a-fA-F]{2}", body_text):
            score += 2.0
            reasons.append("URL-encoded payload detected")
        if re.search(r"[A-Za-z0-9+/]{120,}={0,2}", body_text):
            score += 2.0
            reasons.append("Base64-like blob in request")

        if (input_tokens + output_tokens) > 4000:
            score += 2.0
            reasons.append("Unusually large token count")

        if cost_usd > 1.0:
            score += 1.5
            reasons.append("High-cost interaction")

        if latency_ms > 5000:
            score += 1.0
            reasons.append("Slow response time")

        if alerts:
            score += min(3.0, 1.5 + 0.5 * len(alerts))
            reasons.append("Alerts triggered: " + ", ".join(alerts))

        if response_text:
            if len(response_text.split()) < 4:
                score += 0.5
                reasons.append("Abnormally terse response")
            if re.search(r"(?i)hash|signature|sha-256", response_text):
                score += 0.5
                reasons.append("Response mentions cryptographic material")

        return round(min(score, 10.0), 1), reasons

    def _extract_chunk_text(self, chunk: Any) -> str:
        """Best-effort extraction for streaming chunks."""
        if isinstance(chunk, dict):
            if "delta" in chunk and isinstance(chunk["delta"], dict):
                return chunk["delta"].get("content", "") or ""
            if "content" in chunk and isinstance(chunk["content"], str):
                return chunk["content"]
            if "text" in chunk:
                return str(chunk.get("text", ""))
        return str(chunk)
    
    def audited_request(
        self,
        endpoint: str,
        headers: Dict[str, str],
        body: Dict[str, Any],
        timeout: float = 60.0,
        provider: Optional[str] = None,
        model: Optional[str] = None
    ) -> Tuple[Dict, AuditRecord]:
        """
        Make an audited API request.
        
        Returns:
            Tuple of (response_data, audit_record)
        """
        if httpx is None:
            raise ImportError("Install httpx: pip install httpx")
        
        request_id = self._generate_request_id()
        timestamp_start = datetime.now(timezone.utc)
        
        # Detect provider and model
        detected_provider = provider or self._detect_provider(endpoint)
        detected_model = model or self._extract_model(body, detected_provider)
        
        # Estimate input tokens
        messages = body.get("messages", [])
        if messages:
            input_tokens_est = TokenEstimator.estimate_from_messages(messages, model=detected_model)
        else:
            # For Ollama/Gemini style
            prompt = body.get("prompt", body.get("contents", [{}])[0].get("parts", [{}])[0].get("text", ""))
            input_tokens_est = TokenEstimator.estimate_tokens(str(prompt), model=detected_model)
        
        # Create request hash
        request_hash = hashlib.sha256(
            json.dumps(body, sort_keys=True).encode()
        ).hexdigest()
        
        # Make the request with timing
        start_time = time.perf_counter()
        error_message = None
        response_data = {}
        status_code = 0
        
        response = None
        try:
            response = httpx.post(
                endpoint,
                headers=headers,
                json=body,
                timeout=timeout
            )
            status_code = response.status_code
            response_data = response.json()
            
        except httpx.TimeoutException:
            error_message = "Request timed out"
            status_code = 408
        except httpx.RequestError as e:
            error_message = f"Request error: {str(e)}"
            status_code = 0
        except json.JSONDecodeError:
            error_message = "Invalid JSON response"
            status_code = response.status_code if response is not None else 0
        
        end_time = time.perf_counter()
        latency_ms = (end_time - start_time) * 1000
        
        # Extract tokens from response
        input_tokens, output_tokens = self._extract_tokens_from_response(
            response_data, detected_provider
        )
        
        # Use estimates if provider didn't report
        input_tokens = input_tokens or input_tokens_est
        
        # Extract and fingerprint response text
        response_text = self._extract_response_text(response_data, detected_provider)
        output_tokens = output_tokens or TokenEstimator.estimate_tokens(response_text, model=detected_model)
        response_fingerprint = ResponseFingerprinter.fingerprint(response_text)

        alerts = self._analyze_loyalty(body, response_text, detected_provider, detected_model)
        
        # Calculate cost
        cost = CostCalculator.calculate(
            detected_provider, detected_model, input_tokens, output_tokens
        )

        anomaly_score, anomaly_reasons = self._score_anomaly(
            body,
            response_text,
            input_tokens,
            output_tokens,
            cost,
            latency_ms,
            alerts,
        )
        
        # Create audit record
        record = AuditRecord(
            request_id=request_id,
            timestamp_utc=timestamp_start.isoformat(),
            provider=detected_provider,
            model=detected_model,
            latency_ms=round(latency_ms, 2),
            time_to_first_byte_ms=None,  # TODO: Implement for streaming
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=input_tokens + output_tokens,
            estimated_cost_usd=cost,
            request_hash=request_hash,
            response_fingerprint=response_fingerprint,
            status_code=status_code,
            success=200 <= status_code < 300,
            error_message=error_message,
            request_preview=self._redact_body(str(body)[:self.preview_length]) if not self.log_full_content else self._redact_body(str(body)),
            response_preview=response_text[:self.preview_length] if not self.log_full_content else response_text,
            alerts=alerts,
            anomaly_score=anomaly_score,
            anomaly_reasons=anomaly_reasons,
        )
        
        # Store the record
        self._store_record(record)
        
        return response_data, record

    def audited_stream_generator(
        self,
        generator,
        endpoint: str,
        headers: Dict[str, str],
        body: Dict[str, Any],
        provider: Optional[str] = None,
        model: Optional[str] = None,
    ):
        """Wrap a streaming response generator to capture TTFB and totals."""
        request_id = self._generate_request_id()
        timestamp_start = datetime.now(timezone.utc)
        detected_provider = provider or self._detect_provider(endpoint)
        detected_model = model or self._extract_model(body, detected_provider)

        messages = body.get("messages", [])
        if messages:
            input_tokens_est = TokenEstimator.estimate_from_messages(messages, model=detected_model)
        else:
            prompt = body.get("prompt", body.get("contents", [{}])[0].get("parts", [{}])[0].get("text", ""))
            input_tokens_est = TokenEstimator.estimate_tokens(str(prompt), model=detected_model)

        request_hash = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()

        start_time = time.perf_counter()
        first_byte_ms: Optional[float] = None
        chunks: List[str] = []
        error_message = None
        status_code = 200

        try:
            for chunk in generator:
                if first_byte_ms is None:
                    first_byte_ms = (time.perf_counter() - start_time) * 1000
                text_piece = self._extract_chunk_text(chunk)
                if text_piece:
                    chunks.append(text_piece)
                yield chunk
        except Exception as exc:  # pragma: no cover - streaming errors
            error_message = str(exc)
            status_code = 500
            raise
        finally:
            end_time = time.perf_counter()
            latency_ms = (end_time - start_time) * 1000
            response_text = "".join(chunks)
            output_tokens = TokenEstimator.estimate_tokens(response_text, model=detected_model)
            alerts = self._analyze_loyalty(body, response_text, detected_provider, detected_model)
            cost = CostCalculator.calculate(detected_provider, detected_model, input_tokens_est, output_tokens)
            anomaly_score, anomaly_reasons = self._score_anomaly(
                body,
                response_text,
                input_tokens_est,
                output_tokens,
                cost,
                latency_ms,
                alerts,
            )

            record = AuditRecord(
                request_id=request_id,
                timestamp_utc=timestamp_start.isoformat(),
                provider=detected_provider,
                model=detected_model,
                latency_ms=round(latency_ms, 2),
                time_to_first_byte_ms=round(first_byte_ms, 2) if first_byte_ms is not None else None,
                input_tokens=input_tokens_est,
                output_tokens=output_tokens,
                total_tokens=input_tokens_est + output_tokens,
                estimated_cost_usd=cost,
                request_hash=request_hash,
                response_fingerprint=ResponseFingerprinter.fingerprint(response_text),
                status_code=status_code,
                success=200 <= status_code < 300,
                error_message=error_message,
                request_preview=str(body)[:self.preview_length] if not self.log_full_content else str(body),
                response_preview=response_text[:self.preview_length] if not self.log_full_content else response_text,
                alerts=alerts,
                anomaly_score=anomaly_score,
                anomaly_reasons=anomaly_reasons,
            )

            self._store_record(record)

    def run_canary(self, adapter: "LLMAdapter") -> bool:
        """Execute a canary prompt to detect model swaps or hidden safety rewrites."""
        success = IntegrityCheck.verify_model_capability(adapter)
        try:
            AuditChain.log("canary_check", {"success": success})
        except Exception:
            pass
        return success
    
    def _store_record(self, record: AuditRecord):
        """Store an audit record to configured destinations."""
        with self._lock:
            self._records.append(record)
        try:
            self._log_queue.put_nowait(record)
        except queue.Full:
            import sys
            print("[SIGIL WARN] Audit log queue full (1000). Record dropped.", file=sys.stderr)
    
    def get_stats(
        self,
        provider: Optional[str] = None,
        since: Optional[datetime] = None
    ) -> PerformanceStats:
        """
        Get aggregated performance statistics.
        
        Args:
            provider: Filter by provider (optional)
            since: Only include records after this time (optional)
        """
        with self._lock:
            records = list(self._records)
        
        # Filter records
        if provider:
            records = [r for r in records if r.provider == provider]
        if since:
            since_iso = since.isoformat()
            records = [r for r in records if r.timestamp_utc >= since_iso]
        
        if not records:
            return PerformanceStats(
                total_requests=0,
                successful_requests=0,
                failed_requests=0,
                avg_latency_ms=0,
                min_latency_ms=0,
                max_latency_ms=0,
                p50_latency_ms=0,
                p95_latency_ms=0,
                p99_latency_ms=0,
                total_input_tokens=0,
                total_output_tokens=0,
                avg_input_tokens=0,
                avg_output_tokens=0,
                total_cost_usd=0,
                avg_cost_per_request_usd=0,
                first_request_utc="",
                last_request_utc="",
            )
        
        latencies = [r.latency_ms for r in records]
        latencies_sorted = sorted(latencies)
        
        def percentile(data: List[float], p: float) -> float:
            if not data:
                return 0
            k = (len(data) - 1) * p / 100
            f = int(k)
            c = f + 1 if f + 1 < len(data) else f
            return data[f] + (k - f) * (data[c] - data[f]) if c != f else data[f]
        
        # Aggregate by provider
        requests_by_provider: Dict[str, int] = {}
        cost_by_provider: Dict[str, float] = {}
        for r in records:
            requests_by_provider[r.provider] = requests_by_provider.get(r.provider, 0) + 1
            cost_by_provider[r.provider] = cost_by_provider.get(r.provider, 0) + r.estimated_cost_usd
        
        total_cost = sum(r.estimated_cost_usd for r in records)
        total_input = sum(r.input_tokens for r in records)
        total_output = sum(r.output_tokens for r in records)
        
        return PerformanceStats(
            total_requests=len(records),
            successful_requests=sum(1 for r in records if r.success),
            failed_requests=sum(1 for r in records if not r.success),
            avg_latency_ms=round(statistics.mean(latencies), 2),
            min_latency_ms=round(min(latencies), 2),
            max_latency_ms=round(max(latencies), 2),
            p50_latency_ms=round(percentile(latencies_sorted, 50), 2),
            p95_latency_ms=round(percentile(latencies_sorted, 95), 2),
            p99_latency_ms=round(percentile(latencies_sorted, 99), 2),
            total_input_tokens=total_input,
            total_output_tokens=total_output,
            avg_input_tokens=round(total_input / len(records), 1),
            avg_output_tokens=round(total_output / len(records), 1),
            total_cost_usd=round(total_cost, 4),
            avg_cost_per_request_usd=round(total_cost / len(records), 6),
            first_request_utc=min(r.timestamp_utc for r in records),
            last_request_utc=max(r.timestamp_utc for r in records),
            requests_by_provider=requests_by_provider,
            cost_by_provider={k: round(v, 4) for k, v in cost_by_provider.items()},
        )
    
    def get_records(
        self,
        limit: int = 100,
        offset: int = 0,
        provider: Optional[str] = None
    ) -> List[AuditRecord]:
        """Get audit records with pagination."""
        with self._lock:
            records = list(self._records)
        
        if provider:
            records = [r for r in records if r.provider == provider]
        
        # Most recent first
        records = sorted(records, key=lambda r: r.timestamp_utc, reverse=True)
        
        return records[offset:offset + limit]
    
    def export_records(self, filepath: Optional[Path] = None) -> Path:
        """Export all records to a JSON file."""
        filepath = filepath or AUDIT_LOG_DIR / f"export_{int(time.time())}.json"
        
        with self._lock:
            records = [asdict(r) for r in self._records]
        
        with open(filepath, 'w') as f:
            json.dump({
                "exported_at": datetime.now(timezone.utc).isoformat(),
                "total_records": len(records),
                "records": records,
                "stats": asdict(self.get_stats()),
            }, f, indent=2)
        
        return filepath


class LegalExporter:
    """Prepare tamper-evident discovery bundles for legal/regulatory use."""

    @staticmethod
    def _hash_file(path: Path) -> str:
        digest = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def create_discovery_package(
        time_range: Tuple[datetime, datetime],
        case_id: str,
        proxy: "AuditProxy",
        output_dir: Optional[Path] = None,
    ) -> Path:
        """
        Bundle logs, manifest, and summaries into a single zip for discovery.

        Steps:
          1. Collect records in the given time window.
          2. Write JSON + human-readable summaries.
          3. Generate a SHA-256 manifest for tamper-evidence.
          4. Zip everything into one artifact.
        """

        import re
        if not re.match(r'^[a-zA-Z0-9_-]+$', case_id):
            raise ValueError(
                f"Invalid case_id '{case_id}'. "
                "Case IDs must contain only alphanumeric characters, hyphens, and underscores."
            )

        start, end = time_range
        package_root = Path(output_dir or AUDIT_LOG_DIR)
        package_root.mkdir(parents=True, exist_ok=True)
        bundle_dir = package_root / f"legal_{case_id}_{int(time.time())}"
        bundle_dir.mkdir(parents=True, exist_ok=True)

        # Collect records inside the window
        with proxy._lock:
            records = list(proxy._records)

        windowed: List[AuditRecord] = []
        for rec in records:
            try:
                ts = datetime.fromisoformat(rec.timestamp_utc.replace("Z", "+00:00"))
            except ValueError:
                continue
            if start <= ts <= end:
                windowed.append(rec)

        export_json = {
            "case_id": case_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "time_range": {
                "start": start.isoformat(),
                "end": end.isoformat(),
            },
            "record_count": len(windowed),
            "records": [asdict(r) for r in windowed],
        }
        records_path = bundle_dir / "records.json"
        records_path.write_text(json.dumps(export_json, indent=2))

        stats = asdict(proxy.get_stats())
        stats_path = bundle_dir / "summary_stats.json"
        stats_path.write_text(json.dumps(stats, indent=2))

        # Chain of custody note
        chain_valid, chain_msg = AuditChain.verify_chain()
        custody_path = bundle_dir / "chain_of_custody.txt"
        custody_path.write_text(
            "\n".join(
                [
                    f"Case ID: {case_id}",
                    f"Generated: {datetime.now(timezone.utc).isoformat()}",
                    f"Records: {len(windowed)}",
                    f"Chain Health: {'OK' if chain_valid else 'FAIL'}",
                    f"Details: {chain_msg}",
                ]
            )
        )

        # Plain-English summary
        summary_lines = [
            f"Discovery package for case {case_id}",
            f"Window: {start.isoformat()} to {end.isoformat()}",
            f"Records included: {len(windowed)}",
            f"Providers: {', '.join(sorted({r.provider for r in windowed}) or ['none'])}",
            f"Alerts present: {sum(1 for r in windowed if r.alerts)}",
            f"Avg anomaly score: {round(sum(r.anomaly_score for r in windowed) / len(windowed), 2) if windowed else 0.0}",
        ]
        (bundle_dir / "summary_report.txt").write_text("\n".join(summary_lines))

        # Manifest for tamper-evidence
        manifest = {}
        for path in bundle_dir.iterdir():
            if path.is_file():
                manifest[path.name] = LegalExporter._hash_file(path)
        manifest_path = bundle_dir / "sha256_manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2))

        # Zip it
        zip_path = bundle_dir.with_suffix(".zip")
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for path in bundle_dir.iterdir():
                zf.write(path, arcname=path.name)

        return zip_path


# =============================================================================
# AUDITED ADAPTER WRAPPER
# =============================================================================

class AuditedAdapter:
    """
    Wrapper that adds auditing to any existing LLM adapter.
    
    Usage:
        from sigil_llm_adapter import ClaudeAdapter
        from sigil_audit_proxy import AuditProxy, AuditedAdapter
        
        proxy = AuditProxy()
        base_adapter = ClaudeAdapter(api_key="...")
        audited = AuditedAdapter(base_adapter, proxy)
        
        response = audited.complete("Hello, world!")
        print(proxy.get_stats())
    """
    
    def __init__(self, adapter, proxy: AuditProxy):
        self._adapter = adapter
        self._proxy = proxy
        if hasattr(self._adapter, "proxy"):
            setattr(self._adapter, "proxy", proxy)
    
    def complete(self, context: str, max_tokens: int = 1000) -> str:
        """Delegate to the adapter; proxy handles auditing internally."""
        return self._adapter.complete(context, max_tokens)
    
    @property
    def last_record(self) -> Optional[AuditRecord]:
        """Get the most recent audit record."""
        records = self._proxy.get_records(limit=1)
        return records[0] if records else None


class IntegrityCheck:
    """Canary to verify model identity and honesty using randomized challenges."""

    # Static hash kept for provenance checks only
    EXPECTED_HASH = hashlib.sha256(b"SIGIL").hexdigest()

    @classmethod
    def verify_model_capability(cls, adapter: "LLMAdapter") -> bool:
        # Generate a random challenge each time to prevent caching/replay
        challenge = os.urandom(16).hex()
        expected = hashlib.sha256(challenge.encode()).hexdigest()
        prompt = f"Reply with ONLY the SHA256 hash of the exact string '{challenge}'. No other text."

        try:
            start = time.time()
            response = adapter.complete(prompt, max_tokens=128)
            elapsed = time.time() - start
        except Exception as exc:
            AuditChain.log("integrity_check_error", {"error": str(exc)})
            return False

        normalized = response.strip().lower()
        hash_match = expected in normalized or expected[:16] in normalized

        # Timing plausibility: a real model inference should take >100ms
        timing_plausible = elapsed > 0.1

        success = hash_match and timing_plausible

        AuditChain.log("integrity_check", {
            "challenge": challenge,
            "expected": expected,
            "observed_fragment": normalized[:64],
            "hash_match": hash_match,
            "elapsed_seconds": round(elapsed, 3),
            "timing_plausible": timing_plausible,
            "success": success,
        })

        return success


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def create_audited_adapter(adapter_class, proxy: Optional[AuditProxy] = None, **kwargs):
    """
    Factory function to create an audited adapter.
    
    Usage:
        audited_claude = create_audited_adapter(ClaudeAdapter, api_key="...")
        response = audited_claude.complete("Hello!")
    """
    proxy = proxy or AuditProxy()
    kwargs.setdefault("proxy", proxy)
    base_adapter = adapter_class(**kwargs)
    return AuditedAdapter(base_adapter, proxy), proxy


def print_stats(stats: PerformanceStats):
    """Pretty-print performance statistics."""
    print("\n" + "=" * 60)
    print("MODEL PERFORMANCE & INTEGRITY AUDIT REPORT")
    print("=" * 60)
    print(f"\n📊 OVERVIEW")
    print(f"   Total Requests:     {stats.total_requests}")
    print(f"   Successful:         {stats.successful_requests}")
    print(f"   Failed:             {stats.failed_requests}")
    print(f"   Time Range:         {stats.first_request_utc[:19]} → {stats.last_request_utc[:19]}")
    
    print(f"\n⏱️  LATENCY (milliseconds)")
    print(f"   Average:            {stats.avg_latency_ms:,.1f} ms")
    print(f"   Min:                {stats.min_latency_ms:,.1f} ms")
    print(f"   Max:                {stats.max_latency_ms:,.1f} ms")
    print(f"   P50 (median):       {stats.p50_latency_ms:,.1f} ms")
    print(f"   P95:                {stats.p95_latency_ms:,.1f} ms")
    print(f"   P99:                {stats.p99_latency_ms:,.1f} ms")
    
    print(f"\n🔤 TOKENS")
    print(f"   Total Input:        {stats.total_input_tokens:,}")
    print(f"   Total Output:       {stats.total_output_tokens:,}")
    print(f"   Avg Input/Request:  {stats.avg_input_tokens:,.1f}")
    print(f"   Avg Output/Request: {stats.avg_output_tokens:,.1f}")
    
    print(f"\n💰 COST (USD)")
    print(f"   Total Spent:        ${stats.total_cost_usd:,.4f}")
    print(f"   Avg per Request:    ${stats.avg_cost_per_request_usd:,.6f}")
    
    if stats.requests_by_provider:
        print(f"\n📡 BY PROVIDER")
        for provider, count in stats.requests_by_provider.items():
            cost = stats.cost_by_provider.get(provider, 0)
            print(f"   {provider:15} {count:5} requests  ${cost:,.4f}")
    
    print("\n" + "=" * 60)


# =============================================================================
# CLI INTERFACE
# =============================================================================

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="SIGIL Audit Proxy - Model Performance & Integrity Auditor"
    )
    parser.add_argument("--stats", action="store_true", help="Show audit statistics")
    parser.add_argument("--export", type=str, help="Export records to file")
    parser.add_argument("--recent", type=int, default=10, help="Show N recent records")
    parser.add_argument("--provider", type=str, help="Filter by provider")
    
    args = parser.parse_args()
    
    proxy = AuditProxy(log_to_chain=False, log_to_file=False)
    
    if args.stats:
        stats = proxy.get_stats(provider=args.provider)
        print_stats(stats)
    
    elif args.export:
        path = proxy.export_records(Path(args.export))
        print(f"Exported to: {path}")
    
    else:
        records = proxy.get_records(limit=args.recent, provider=args.provider)
        if records:
            print(f"\n📋 Recent {len(records)} Audit Records:\n")
            for r in records:
                status = "✅" if r.success else "❌"
                print(f"{status} [{r.timestamp_utc[:19]}] {r.provider}/{r.model}")
                print(f"   Latency: {r.latency_ms:.0f}ms | Tokens: {r.total_tokens} | Cost: ${r.estimated_cost_usd:.4f}")
                print()
        else:
            print("No audit records found. Make some API calls first!")
