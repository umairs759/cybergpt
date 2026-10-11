"""
CyberGPT LLM Service — NVIDIA NIM enterprise failover engine.

CRITICAL ARCHITECTURE:
  * ALL requests route exclusively to NVIDIA NIM
    (https://integrate.api.nvidia.com/v1) using nvapi- keys.
  * No third-party DeepSeek / GLM endpoints are ever contacted.
  * Rotation pool of nvapi- keys with 401/403 quarantine + rotation.
  * Strict 50.0s client timeout.
  * Per-tier NVIDIA NIM model identifiers with enforced token caps.

MODEL DISCOVERY (verified live against GET /v1/models + 1-token completions):
  * meta/llama-3.1-8b-instruct / meta/llama-3.3-70b-instruct -> HTTP 410 (EOL).
  * ibm/granite, microsoft/phi-3.5, mistral-*, nemotron-4-340b,
    llama-3.1-nemotron-51b/70b/ultra -> HTTP 404 (not provisioned).
  * Only the models below returned HTTP 200 with real completions, so
    TIER_MODELS and every fallback slot are bound strictly to them.

VERIFIED-200 TIER MAP (latency medians from live benchmark):
  Flash    -> nvidia/nemotron-3-super-120b-a12b   (~1.8-3s, MoE 12B active)
  Balanced -> nvidia/nemotron-3-super-120b-a12b   (clean 4-7 line answers)
  Pro      -> nvidia/nemotron-3-super-120b-a12b   (120B; proven 13-20 line briefs)
  Fallback -> openai/gpt-oss-20b (deep reasoner), nvidia/nemotron-3.5-lightning-30b-a3b,
              poolside/laguna-xs-2.1 — all 200-verified. lightning is only ever
              served with chat_template_kwargs.enable_thinking=false — without
              it, it dumps its chain-of-thought into the visible content.
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

# Load .env here (app.py does not import config.py, so this is the module
# that must surface NVIDIA_API_KEYS / NVIDIA_API_KEY to the key pool).
try:
    from dotenv import load_dotenv

    load_dotenv()
except Exception:  # pragma: no cover - dotenv optional
    pass

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
NVIDIA_BASE_URL = "https://integrate.api.nvidia.com/v1"  # strict, never overridden
CLIENT_TIMEOUT = 50.0  # strict 50s client timeout (mandated)

# ----------------------------------------------------------------------------
# Verified NVIDIA NIM model identifiers (HTTP 200 confirmed via /v1/models
# listing + live chat/completions probes). Anything NOT in these dicts is
# never contacted: 410 (EOL) and 404 (not provisioned) models are excluded.
# ----------------------------------------------------------------------------
TIER_MODELS: Dict[ModelTier, str] = {
    ModelTier.FLASH: "nvidia/nemotron-3-super-120b-a12b",      # ~1.8s, fast MoE
    ModelTier.BALANCED: "nvidia/nemotron-3-super-120b-a12b",   # clean 4-7 lines
    ModelTier.PRO: "nvidia/nemotron-3-super-120b-a12b",        # 120B, 13-20 lines
}

# Per-model payload extras, each verified live (HTTP 200 + clean content).
# lightning-30b WITHOUT enable_thinking=false leaks its reasoning into the
# visible reply ("Here's a thinking process: ..." 30+ lines), so it is only
# ever served with thinking disabled.
MODEL_PAYLOAD_EXTRAS: Dict[str, Dict[str, Any]] = {
    "nvidia/nemotron-3.5-lightning-30b-a3b": {
        "chat_template_kwargs": {"enable_thinking": False},
    },
    # Caps gpt-oss latency (36-50s at default effort vs 19-34s at medium)
    # whenever it serves as the deep-reasoning fallback. Verified HTTP 200 live.
    "openai/gpt-oss-20b": {
        "reasoning_effort": "medium",
    },
}

# Per-tier failover queues. EVERY entry returned HTTP 200 during discovery.
TIER_FAILOVER: Dict[ModelTier, List[str]] = {
    ModelTier.FLASH: [
        "openai/gpt-oss-20b",
        "nvidia/nemotron-3.5-lightning-30b-a3b",
        "poolside/laguna-xs-2.1",
    ],
    ModelTier.BALANCED: [
        "openai/gpt-oss-20b",
        "nvidia/nemotron-3.5-lightning-30b-a3b",
        "poolside/laguna-xs-2.1",
    ],
    ModelTier.PRO: [
        "openai/gpt-oss-20b",
        "nvidia/nemotron-3.5-lightning-30b-a3b",
        "poolside/laguna-xs-2.1",
    ],
}

# Single source of truth for the verified pool (HTTP 200 only).
VERIFIED_MODELS: List[str] = [
    "nvidia/nemotron-3-super-120b-a12b",
    "nvidia/nemotron-3.5-lightning-30b-a3b",
    "openai/gpt-oss-20b",
    "poolside/laguna-xs-2.1",
]

# Strict token allocation per tier (enforced server-side via max_tokens).
# Headroom included because the verified NIM models are reasoning models:
# reasoning tokens are billed inside completion_tokens and would otherwise
# truncate the visible answer (finish_reason=length).
TIER_MAX_TOKENS: Dict[ModelTier, int] = {
    ModelTier.FLASH: 500,     # 2-3 high-impact lines
    ModelTier.BALANCED: 1200,  # 4-7 lines: mechanics + detection
    ModelTier.PRO: 3200,      # 13-20 lines: executive briefing
}

TIER_TEMPERATURE: Dict[ModelTier, float] = {
    ModelTier.FLASH: 0.3,
    ModelTier.BALANCED: 0.5,
    ModelTier.PRO: 0.7,
}

# Rotation pool of nvapi- keys. Env vars take precedence (loaded from .env at
# import time); the defaults below mirror the .env pool as an out-of-box
# fallback. NOTE: the first default key previously carried a typo (-kVG
# instead of -qVG) which produced HTTP 403 "Authorization failed" on every
# other request — it has been corrected here.
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
- EXACTLY 2-3 LINES (hard limit). Each line must be a high-impact fact.
- Count your lines before answering; NEVER exceed 3 lines.
- NO fluff, NO intros, NO conclusions, NO preamble, NO thinking narration.
- Format: bullet points or numbered facts only.
- Target: 2-3 second mental parse time for the analyst.
- If the user asks for a specific line count, honor it within 1-5 lines.""",

    ModelTier.BALANCED: """You are CyberGPT Balanced Tier - Vulnerability Mechanics & Detection.
OUTPUT CONSTRAINTS:
- EXACTLY 4-7 LINES (hard limit). Structure: Vulnerability mechanics (2-3 lines) + Detection/IoCs (2-3 lines) + One mitigation (1-2 lines).
- Count your lines before answering; NEVER exceed 7 lines.
- NO fluff, NO intros, NO conclusions, NO preamble, NO thinking narration.
- Include specific Event IDs, registry keys, or CLI artifacts where applicable.
- If the user asks for a specific line count, honor it within 4-10 lines.""",

    ModelTier.PRO: """You are CyberGPT Pro Tier - Executive SOC Briefing.
OUTPUT CONSTRAINTS:
- EXACTLY 13-20 LINES (hard limit). Count your lines; if you approach 20, merge bullets — NEVER exceed 20 lines. Mandatory sections:
  1. EXECUTIVE OVERVIEW (2-3 lines): Business impact, threat actor profile, blast radius.
  2. UNDER-THE-HOOD MECHANICS (4-5 lines): Root cause, exploit chain, privilege escalation path.
  3. EVENT IDs / IoCs / SIGMA RULES (3-4 lines): Specific Sysmon/Windows IDs, file hashes, IPs, domains, YARA/Sigma snippets.
  4. HARDENED CODE / CONFIG (2-3 lines): Before/after code blocks or registry/policy changes.
  5. SOC PRO-TIPS (2-3 lines): Detection logic, hunting queries, containment playbook steps.
- NO fluff, NO preamble, NO thinking narration. Dense, actionable, citation-ready.
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


def _coerce_tier(tier: Any) -> ModelTier:
    """Accept ModelTier members or plain strings ("flash" / "balanced" / "pro")."""
    if isinstance(tier, ModelTier):
        return tier
    try:
        return ModelTier(str(tier).strip().lower())
    except Exception:
        logger.warning(f"Unknown tier {tier!r} — defaulting to 'balanced'")
        return ModelTier.BALANCED


def _extract_content(message: Dict[str, Any]) -> str:
    """Pull the visible answer out of a chat message.

    Reasoning models (gpt-oss, Nemotron-3.x) return their chain-of-thought in
    a separate `reasoning_content` field, but with a tight token budget the
    visible `content` can come back null. Never expose reasoning text as the
    reply; return "" so the caller can fail over instead of crashing.
    """
    content = message.get("content")
    if isinstance(content, str) and content.strip():
        return content
    if isinstance(content, list):  # content-part arrays (OpenAI style)
        parts = []
        for part in content:
            if isinstance(part, dict) and part.get("type") == "text":
                parts.append(str(part.get("text", "")))
            elif isinstance(part, str):
                parts.append(part)
        text = "\n".join(p for p in parts if p).strip()
        if text:
            return text
    return ""


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
            timeout = ClientTimeout(total=CLIENT_TIMEOUT, connect=10.0, sock_read=CLIENT_TIMEOUT)
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
        # +400 tokens of headroom: the verified NIM models reason before they
        # answer, and reasoning tokens count against max_tokens.
        line_match = re.search(r"(\d+)\s*lines?", user_content, re.IGNORECASE)
        if line_match:
            requested_lines = int(line_match.group(1))
            max_tokens = min(max_tokens, max(200, requested_lines * 40 + 400))

        payload: Dict[str, Any] = {
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
        # Per-model verified extras (e.g. disable lightning's thinking dump).
        payload.update(MODEL_PAYLOAD_EXTRAS.get(model_id, {}))
        return payload

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
                choices = data.get("choices") or []
                if not choices:
                    logger.error(f"{model_id} returned no choices: {str(data)[:200]}")
                    return LLMResponse(
                        content="",
                        model_used=model_id,
                        tier=tier,
                        token_usage=TokenUsage(),
                        latency_ms=latency_ms,
                        success=False,
                        error="HTTP 200 but empty choices",
                    )

                raw_content = _extract_content(choices[0].get("message") or {})
                if not raw_content:
                    # Reasoning budget exhausted -> null content. Fail over
                    # instead of surfacing an empty reply.
                    finish = choices[0].get("finish_reason")
                    logger.error(f"{model_id} empty content (finish_reason={finish})")
                    return LLMResponse(
                        content="",
                        model_used=model_id,
                        tier=tier,
                        token_usage=TokenUsage(),
                        latency_ms=latency_ms,
                        success=False,
                        error=f"empty content (finish_reason={finish})",
                    )

                usage = data.get("usage", {}) or {}
                token_usage = TokenUsage(
                    prompt_tokens=usage.get("prompt_tokens", 0),
                    completion_tokens=usage.get("completion_tokens", 0),
                    total_tokens=usage.get("total_tokens", 0),
                )
                if token_usage.total_tokens == 0:
                    prompt_est = count_tokens_estimate(str(payload["messages"]))
                    comp_est = count_tokens_estimate(raw_content)
                    token_usage.prompt_tokens = prompt_est
                    token_usage.completion_tokens = comp_est
                    token_usage.total_tokens = prompt_est + comp_est

                content = inject_lab_recommendations(raw_content)

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

    def _failover_plan(self, tier: ModelTier) -> List[str]:
        """Ordered, de-duplicated model queue for a tier.

        Only verified HTTP-200 models appear anywhere in the plan; the dead
        410/404 models from the old pool are gone entirely.
        """
        plan: List[str] = []
        for model_id in [TIER_MODELS[tier], *TIER_FAILOVER[tier]]:
            if model_id not in plan:
                plan.append(model_id)
        # Last resort: other tiers' primaries (still verified-200), so a
        # single-model outage degrades gracefully instead of failing.
        for t in ModelTier:
            primary = TIER_MODELS[t]
            if primary not in plan:
                plan.append(primary)
        for model_id in VERIFIED_MODELS:
            if model_id not in plan:
                plan.append(model_id)
        return plan

    async def chat(
        self, messages: List[Dict[str, str]], tier: ModelTier = ModelTier.BALANCED
    ) -> LLMResponse:
        """Main entry point with NVIDIA NIM model + key failover chain.

        The REQUESTED tier's system prompt, line rules and token cap are
        applied to every attempt — a Flash request never comes back as a
        13-20 line Pro briefing just because it failed over.

        Failover order:
          1. The tier's designated NIM model.
          2. The tier's verified fallback queue.
          3. The remaining verified NIM models.
        For each model, every available nvapi- key is tried; 401/403 keys are
        quarantined and rotated out of the pool.
        """
        tier = _coerce_tier(tier)
        sanitized = sanitize_messages(messages)
        last_error: Optional[str] = None
        tried_models: List[str] = []

        for model_id in self._failover_plan(tier):
            tried_models.append(model_id)
            payload = self._build_payload(sanitized, tier, model_id)
            model_failed = False

            for api_key in self.key_pool.snapshot():
                response = await self._call_model(model_id, payload, tier, api_key)
                if response.success:
                    logger.info(
                        f"Success with {model_id} "
                        f"({response.latency_ms:.0f}ms, {response.token_usage.total_tokens} tokens)"
                    )
                    return response

                last_error = response.error
                err_str = str(response.error or "")

                if "401" in err_str or "403" in err_str:
                    # Auth failure is key-scoped: quarantine and try the next key.
                    self.key_pool.quarantine(api_key)
                    logger.warning("NVIDIA key quarantined (auth failure) — rotating to next key")
                    continue

                # Everything else (404 not provisioned, 410 EOL, 400, 429,
                # 503 overloaded, timeout, empty content) is model-scoped for
                # this attempt: stop burning keys and move to the next model.
                model_failed = True
                break

            if model_failed:
                logger.warning(f"Failover: {model_id} failed — trying next verified model")

        # Complete failover exhaustion.
        logger.error(
            f"Failover chain exhausted for tier={tier.value}: "
            f"models={tried_models} last_error={last_error}"
        )
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
        return run_async(self.chat(messages, _coerce_tier(tier)))

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
