"""
CyberGPT LLM Service — NVIDIA NIM enterprise failover engine.

CRITICAL ARCHITECTURE:
  * ALL requests route exclusively to NVIDIA NIM
    (https://integrate.api.nvidia.com/v1) using nvapi- keys.
  * No third-party DeepSeek / GLM endpoints are ever contacted.
  * Rotation pool of nvapi- keys with 401/403 quarantine + rotation.
  * Strict 45.0s client timeout.
  * Per-tier NVIDIA NIM model identifiers with enforced token caps.

Tier mapping (ultra-fast, rock-solid NIM models):
  Flash    -> meta/llama-3.1-8b-instruct          (max_tokens=350, 2-3 lines)
  Balanced -> meta/llama-3.3-70b-instruct         (max_tokens=750, 4-7 lines)
  Pro      -> nvidia/llama-3.1-nemotron-70b-instruct (max_tokens=2200, 13-20 lines)
"""

import os
import re
import time
import asyncio
import logging
import hashlib
import threading
from typing import Dict, List, Optional, Any, AsyncGenerator
from dataclasses import dataclass, asdict, field
from enum import Enum
from collections import deque

import aiohttp
from aiohttp import ClientTimeout, TCPConnector

logger = logging.getLogger(__name__)

# ============================================================================
# Persistent background event-loop bridge
# ---------------------------------------------------------------------------
# aiohttp ClientSession objects are bound to the event loop that created
# them. We keep ONE long-lived loop in a daemon thread and submit coroutines
# via asyncio.run_coroutine_threadsafe. This avoids the "attached to a
# different loop" error that occurs when bridging synchronous Flask request
# threads with async HTTP clients using per-request asyncio.run() calls.
# ============================================================================
class _AsyncBridge:
    def __init__(self):
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._start()

    def _start(self):
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._run, args=(self._loop,), daemon=True, name="cybergpt-async-loop"
        )
        self._thread.start()
        for _ in range(150):
            if self._loop.is_running():
                break
            time.sleep(0.02)

    @staticmethod
    def _run(loop):
        asyncio.set_event_loop(loop)
        try:
            loop.run_forever()
        finally:
            loop.close()

    def run(self, coro):
        """Submit a coroutine to the persistent loop and block for its result."""
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return future.result()

    def stop(self):
        if self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)


_bridge = _AsyncBridge()


def run_async(coro):
    """Run a coroutine on the persistent background event loop."""
    return _bridge.run(coro)


def shutdown_bridge():
    _bridge.stop()


# ============================================================================
# Enums & data models
# ============================================================================
class ModelTier(Enum):
    FLASH = "flash"
    BALANCED = "balanced"
    PRO = "pro"


@dataclass
class TokenUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    estimated_cost_usd: float = 0.0


@dataclass
class LLMResponse:
    content: str
    model_used: str
    tier: ModelTier
    token_usage: TokenUsage
    latency_ms: float
    success: bool
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Clean JSON contract: {"success", "reply", "model_used", "tokens_used", ...}."""
        return {
            "success": self.success,
            "reply": self.content,
            "model_used": self.model_used,
            "tokens_used": self.token_usage.total_tokens,
            "tier": self.tier.value,
            "latency_ms": round(self.latency_ms, 1),
            "error": self.error,
            "tokens": {
                "prompt": self.token_usage.prompt_tokens,
                "completion": self.token_usage.completion_tokens,
                "total": self.token_usage.total_tokens,
            },
        }


# ============================================================================
# NVIDIA NIM configuration
# ============================================================================
NVIDIA_BASE_URL = "https://integrate.api.nvidia.com/v1"
CLIENT_TIMEOUT = 45.0  # strict, rock-solid

# Exact, ultra-fast NVIDIA NIM model identifiers per tier.
TIER_MODELS: Dict[ModelTier, str] = {
    ModelTier.FLASH: "meta/llama-3.1-8b-instruct",
    ModelTier.BALANCED: "meta/llama-3.3-70b-instruct",
    ModelTier.PRO: "nvidia/llama-3.1-nemotron-70b-instruct",
}

# Strict token allocation per tier (enforced server-side via max_tokens).
TIER_MAX_TOKENS: Dict[ModelTier, int] = {
    ModelTier.FLASH: 350,     # 2-3 high-impact lines, ~3-5s
    ModelTier.BALANCED: 750,  # 4-7 lines: mechanics + detection
    ModelTier.PRO: 2200,      # 13-20 lines: executive briefing
}

# Extended failover pool of currently-available NVIDIA NIM models.
# The primary tier models (above) are the enterprise design targets;
# if any of them is end-of-life or not provisioned for the account,
# the failover chain degrades gracefully to these live NIM models
# (ordered fast -> large). See NVIDIA NIM /v1/models catalog.
EXTENDED_FAILOVER_MODELS: List[str] = [
    "nvidia/mistral-nemo-minitron-8b-8k-instruct",   # ultra-fast
    "ibm/granite-3.0-8b-instruct",                   # fast
    "mistralai/mistral-7b-instruct-v0.3",            # fast
    "z-ai/glm-5.3-flash",                            # fast
    "nv-mistralai/mistral-nemo-12b-instruct",        # balanced
    "microsoft/phi-3.5-moe-instruct",                # balanced
    "nvidia/llama-3.1-nemotron-51b-instruct",        # balanced
    "mistralai/mistral-large-2-instruct",            # balanced/pro
    "nvidia/nemotron-4-340b-instruct",               # pro
    "nvidia/llama-3.1-nemotron-ultra-253b-v1",      # pro
]

TIER_TEMPERATURE: Dict[ModelTier, float] = {
    ModelTier.FLASH: 0.3,
    ModelTier.BALANCED: 0.5,
    ModelTier.PRO: 0.7,
}

# Rotation pool of nvapi- keys. Env vars take precedence; the defaults
# below mirror the enterprise pool declared in config.py so the platform
# works out-of-the-box.
DEFAULT_NVIDIA_KEYS = [
    "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",
    "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",
]


def _load_key_pool() -> List[str]:
    keys: List[str] = []
    env_keys = os.getenv("NVIDIA_API_KEYS", "")
    for k in env_keys.split(","):
        k = k.strip()
        if k and k not in keys:
            keys.append(k)
    single = os.getenv("NVIDIA_API_KEY", "").strip()
    if single and single not in keys:
        keys.append(single)
    for k in DEFAULT_NVIDIA_KEYS:
        if k and k not in keys:
            keys.append(k)
    return keys


class APIKeyPool:
    """Round-robin rotation pool with 401/403 quarantine."""

    def __init__(self, keys: List[str]):
        self._keys = list(keys)
        self._index = 0
        self._lock = threading.Lock()
        self._quarantined: set = set()

    @property
    def size(self) -> int:
        return len(self._keys)

    def next(self) -> str:
        with self._lock:
            for _ in range(len(self._keys)):
                key = self._keys[self._index % len(self._keys)]
                self._index += 1
                if key not in self._quarantined:
                    return key
            # All keys quarantined — reset and hand out a fresh key.
            self._quarantined.clear()
            key = self._keys[self._index % len(self._keys)]
            self._index += 1
            return key

    def snapshot(self) -> List[str]:
        with self._lock:
            available = [k for k in self._keys if k not in self._quarantined]
            if not available:
                self._quarantined.clear()
                available = list(self._keys)
            return available

    def quarantine(self, key: str) -> None:
        with self._lock:
            self._quarantined.add(key)


# ============================================================================
# System prompts — strict line-count constraints per tier
# ============================================================================
SYSTEM_PROMPTS = {
    ModelTier.FLASH: """You are CyberGPT Flash Tier - Rapid SOC Intelligence.
OUTPUT CONSTRAINTS:
- MAX 3 LINES (hard limit). Each line must be a high-impact fact.
- NO fluff, NO intros, NO conclusions.
- Format: Bullet points or numbered facts only.
- Target: 3-5 second mental parse time for the analyst.
- If the user asks for a specific line count, honor it within 1-5 lines.""",

    ModelTier.BALANCED: """You are CyberGPT Balanced Tier - Vulnerability Mechanics & Detection.
OUTPUT CONSTRAINTS:
- MAX 7 LINES (hard limit). Structure: Vulnerability mechanics (2-3 lines) + Detection/IoCs (2-3 lines) + One mitigation (1-2 lines).
- NO fluff, NO intros, NO conclusions.
- Include specific Event IDs, registry keys, or CLI artifacts where applicable.
- If the user asks for a specific line count, honor it within 4-10 lines.""",

    ModelTier.PRO: """You are CyberGPT Pro Tier - Executive SOC Briefing.
OUTPUT CONSTRAINTS:
- 13-20 LINES (hard limit). Mandatory sections:
  1. EXECUTIVE OVERVIEW (2-3 lines): Business impact, threat actor profile, blast radius.
  2. UNDER-THE-HOOD MECHANICS (4-5 lines): Root cause, exploit chain, privilege escalation path.
  3. EVENT IDs / IoCs / SIGMA RULES (3-4 lines): Specific Sysmon/Windows IDs, file hashes, IPs, domains, YARA/Sigma snippets.
  4. HARDENED CODE / CONFIG (2-3 lines): Before/after code blocks or registry/policy changes.
  5. SOC PRO-TIPS (2-3 lines): Detection logic, hunting queries, containment playbook steps.
- NO fluff. Dense, actionable, citation-ready.
- If the user asks for a specific line count, honor it within 10-25 lines.""",
}

# Smart cross-referencing: append lab recommendations for these topics.
CROSS_REF_TRIGGERS = {
    "phishing": "Phishing Lab",
    "pass-the-hash": "SOC Drills",
    "kerberoasting": "SOC Drills",
    "sql injection": "SOC Drills",
    "powershell": "SOC Drills",
    "cloud": "SOC Drills",
    "oauth": "Phishing Lab",
    "quishing": "Phishing Lab",
    "rdp": "SOC Drills",
    "psexec": "SOC Drills",
    "s3": "SOC Drills",
    "aws": "SOC Drills",
    "cloudtrail": "SOC Drills",
    "brute-force": "SOC Drills",
    "brute force": "SOC Drills",
    "lateral movement": "SOC Drills",
}

LAB_RECOMMENDATION_TEMPLATE = "\n[CyberGPT Lab Recommendation: Test your skills live in {lab_name}]"


# ============================================================================
# Sanitization & helpers
# ============================================================================
def sanitize_messages(messages: List[Dict[str, str]], max_chars: int = 12000) -> List[Dict[str, str]]:
    """Sanitize and truncate message history to prevent token overflow."""
    sanitized: List[Dict[str, str]] = []
    total_chars = 0
    for msg in reversed(messages):
        content = str(msg.get("content", ""))
        if not content:
            continue
        # Neutralize template/HTML injection patterns.
        content = content.replace("{{", "&#123;&#123;").replace("}}", "&#125;&#125;")
        content = content.replace("<script", "&lt;script").replace("</script", "&lt;/script")
        if total_chars + len(content) > max_chars:
            content = content[-(max_chars - total_chars):]
            sanitized.insert(0, {"role": msg.get("role", "user"), "content": content})
            break
        sanitized.insert(0, {"role": msg.get("role", "user"), "content": content})
        total_chars += len(content)
    return sanitized


def count_tokens_estimate(text: str) -> int:
    """Rough token estimation: ~4 chars per token for English."""
    return max(1, len(text) // 4)


def inject_lab_recommendations(content: str) -> str:
    """Inject cross-referenced lab recommendations based on content keywords."""
    content_lower = content.lower()
    injected = set()
    for trigger, lab in CROSS_REF_TRIGGERS.items():
        if trigger in content_lower and lab not in injected:
            content += LAB_RECOMMENDATION_TEMPLATE.format(lab_name=lab)
            injected.add(lab)
    return content


# ============================================================================
# LLM Service
# ============================================================================
class LLMService:
    def __init__(self):
        self.session: Optional[aiohttp.ClientSession] = None
        self.token_history: deque = deque(maxlen=100)
        self.session_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
        self.key_pool = APIKeyPool(_load_key_pool())
        # NOTE: The aiohttp session is created lazily inside the async event
        # loop (aiohttp's TCPConnector requires a running loop). Do NOT create
        # it here at module-import time.

    def _ensure_session(self) -> aiohttp.ClientSession:
        """Lazily create the aiohttp session within the running event loop."""
        if self.session is None or self.session.closed:
            timeout = ClientTimeout(total=CLIENT_TIMEOUT, connect=10.0, sock_read=40.0)
            connector = TCPConnector(limit=10, ttl_dns_cache=300, enable_cleanup_closed=True)
            self.session = aiohttp.ClientSession(timeout=timeout, connector=connector)
        return self.session

    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()
            self.session = None

    def _build_payload(
        self, messages: List[Dict[str, str]], tier: ModelTier, model_id: str
    ) -> Dict[str, Any]:
        system_prompt = SYSTEM_PROMPTS[tier]
        max_tokens = TIER_MAX_TOKENS[tier]

        user_content = " ".join(m.get("content", "") for m in messages if m.get("role") == "user")

        # Honor explicit user-requested line counts if provided in the prompt.
        line_match = re.search(r"(\d+)\s*lines?", user_content, re.IGNORECASE)
        if line_match:
            requested_lines = int(line_match.group(1))
            # Estimate ~40 tokens per line, capped at the tier maximum.
            max_tokens = min(max_tokens, max(50, requested_lines * 40))

        return {
            "model": model_id,
            "messages": [
                {"role": "system", "content": system_prompt},
                *messages,
            ],
            "max_tokens": max_tokens,
            "temperature": TIER_TEMPERATURE[tier],
            "top_p": 0.9,
            "stream": False,
        }

    async def _call_model(
        self, model_id: str, payload: Dict[str, Any], tier: ModelTier, api_key: str
    ) -> LLMResponse:
        start = time.perf_counter()
        session = self._ensure_session()
        try:
            async with session.post(
                f"{NVIDIA_BASE_URL}/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                    "X-Session-ID": self.session_id,
                },
                json=payload,
            ) as resp:
                latency_ms = (time.perf_counter() - start) * 1000
                if resp.status != 200:
                    error_text = await resp.text()
                    logger.error(f"{model_id} HTTP {resp.status}: {error_text[:200]}")
                    return LLMResponse(
                        content="",
                        model_used=model_id,
                        tier=tier,
                        token_usage=TokenUsage(),
                        latency_ms=latency_ms,
                        success=False,
                        error=f"HTTP {resp.status}: {error_text[:200]}",
                    )
                data = await resp.json()
                content = data["choices"][0]["message"]["content"]
                usage = data.get("usage", {}) or {}
                token_usage = TokenUsage(
                    prompt_tokens=usage.get("prompt_tokens", 0),
                    completion_tokens=usage.get("completion_tokens", 0),
                    total_tokens=usage.get("total_tokens", 0),
                )
                if token_usage.total_tokens == 0:
                    prompt_est = count_tokens_estimate(str(payload["messages"]))
                    comp_est = count_tokens_estimate(content)
                    token_usage.prompt_tokens = prompt_est
                    token_usage.completion_tokens = comp_est
                    token_usage.total_tokens = prompt_est + comp_est

                content = inject_lab_recommendations(content)

                self.token_history.append(
                    {
                        "timestamp": time.time(),
                        "model": model_id,
                        "tier": tier.value,
                        "tokens": token_usage.total_tokens,
                    }
                )

                return LLMResponse(
                    content=content.strip(),
                    model_used=model_id,
                    tier=tier,
                    token_usage=token_usage,
                    latency_ms=latency_ms,
                    success=True,
                )
        except asyncio.TimeoutError:
            latency_ms = (time.perf_counter() - start) * 1000
            logger.error(f"{model_id} timeout after {latency_ms:.0f}ms (limit {CLIENT_TIMEOUT}s)")
            return LLMResponse(
                content="",
                model_used=model_id,
                tier=tier,
                token_usage=TokenUsage(),
                latency_ms=latency_ms,
                success=False,
                error=f"Request timeout ({CLIENT_TIMEOUT:.0f}s)",
            )
        except Exception as e:
            latency_ms = (time.perf_counter() - start) * 1000
            logger.error(f"{model_id} exception: {e}")
            return LLMResponse(
                content="",
                model_used=model_id,
                tier=tier,
                token_usage=TokenUsage(),
                latency_ms=latency_ms,
                success=False,
                error=str(e)[:200],
            )

    async def chat(
        self, messages: List[Dict[str, str]], tier: ModelTier = ModelTier.BALANCED
    ) -> LLMResponse:
        """Main entry point with NVIDIA NIM model + key failover chain.

        Failover order:
          1. The tier's designated NIM model.
          2. The other two NIM models (so a single-model outage degrades
             gracefully instead of failing the request).
        For each model, every available nvapi- key is tried; 401/403 keys are
        quarantined and rotated out of the pool.
        """
        sanitized = sanitize_messages(messages)
        last_error: Optional[str] = None

        # Ordered failover plan: (1) tier's designated NIM model,
        # (2) the other two tier models, (3) extended live NIM models.
        failover_plan: List[tuple] = [(TIER_MODELS[tier], tier)]
        for t in ModelTier:
            if t != tier:
                failover_plan.append((TIER_MODELS[t], t))
        for model_id in EXTENDED_FAILOVER_MODELS:
            if model_id not in TIER_MODELS.values():
                failover_plan.append((model_id, tier))

        for model_id, attempt_tier in failover_plan:
            for api_key in self.key_pool.snapshot():
                payload = self._build_payload(sanitized, attempt_tier, model_id)
                response = await self._call_model(model_id, payload, attempt_tier, api_key)
                if response.success:
                    logger.info(
                        f"Success with {model_id} "
                        f"({response.latency_ms:.0f}ms, {response.token_usage.total_tokens} tokens)"
                    )
                    return response

                last_error = response.error
                err_str = str(response.error or "")
                if "401" in err_str or "403" in err_str:
                    self.key_pool.quarantine(api_key)
                    logger.warning(f"NVIDIA key quarantined (auth failure) — rotating to next key")
                    continue
                # Non-auth error: try the next key for this model, then move on.
                break

        # Complete failover exhaustion.
        return LLMResponse(
            content="All NVIDIA NIM models/keys unavailable. Verify your nvapi- keys and connectivity.",
            model_used="none",
            tier=tier,
            token_usage=TokenUsage(),
            latency_ms=0,
            success=False,
            error=f"Failover chain exhausted: {last_error}",
        )

    async def stream_chat(
        self, messages: List[Dict[str, str]], tier: ModelTier = ModelTier.BALANCED
    ) -> AsyncGenerator[str, None]:
        """Streaming is not implemented for the failover chain; yields the full response."""
        response = await self.chat(messages, tier)
        if response.success:
            yield response.content
        else:
            yield f"Error: {response.error}"

    def chat_sync(
        self, messages: List[Dict[str, str]], tier: ModelTier = ModelTier.BALANCED
    ) -> LLMResponse:
        """Synchronous entry point for Flask handlers.

        Submits the async chat() coroutine to the persistent background event
        loop and blocks for the result. Safe to call from request threads; the
        underlying aiohttp session stays bound to one loop.
        """
        return run_async(self.chat(messages, tier))

    def get_token_stats(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "total_requests": len(self.token_history),
            "total_tokens": sum(h["tokens"] for h in self.token_history),
            "active_keys": self.key_pool.size,
            "endpoint": NVIDIA_BASE_URL,
            "timeout_s": CLIENT_TIMEOUT,
            "tier_models": {t.value: TIER_MODELS[t] for t in ModelTier},
        }


# Shared singleton + backward-compatible accessors (used by services/__init__.py).
llm_service = LLMService()


def get_llm_service() -> LLMService:
    """Return the shared LLMService singleton."""
    return llm_service


def reset_session_history() -> None:
    """Clear token history and rotate the session ID."""
    llm_service.token_history.clear()
    llm_service.session_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
