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
    action: Optional[str] = None  # e.g., "switch_mode"
    suggested_labs: Optional[List[Dict]] = None  # up to 2 real lab objects from catalog

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
            "action": self.action,
            "suggested_labs": self.suggested_labs,
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
        self, messages: List[Dict[str, str]], tier: ModelTier = ModelTier.BALANCED, mode: str = "cyber"
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
        
        # ---- Intent Classification ----
        # Classify user intent before reaching the LLM failover chain.
        # This allows certain query types to bypass the model entirely,
        # ensuring consistent, factual responses and avoiding template misuse.
        first_user_msg = ""
        for msg in messages:
            if msg.get("role") == "user":
                first_user_msg = msg.get("content", "")
                break
        intent_result = _classify_intent(first_user_msg, mode)

        # Handle META_IDENTITY: return direct natural response
        if intent_result.intent == Intent.META_IDENTITY:
            return LLMResponse(
                content=intent_result.direct_response
                or "I'm CyberGPT, a defensive cybersecurity learning assistant developed by Muhammad Umair. How can I assist your security studies today?",
                model_used="cybergpt-meta",
                tier=tier,
                token_usage=TokenUsage(),
                latency_ms=0,
                success=True,
                suggested_labs=intent_result.suggested_labs or [],
            )

        # Handle CONCEPTS: plain definition + why it matters + core components
        if intent_result.intent == Intent.CONCEPTS:
            section = intent_result.section_name or "concept"
            if section == "concept":
                # Build a clean concept response without Event IDs or inline lab strings
                msg = messages[0]["content"] if messages else ""
                # Strip any existing [CyberGPT Lab Recommendation:...] strings
                clean = re.sub(r'\[CyberGPT Lab Recommendation:.*?\]', '', msg).strip()
                # Remove any raw Event ID references that might leak
                clean = re.sub(r'Event ID \d+', 'Event ID [removed]', clean)
                clean = re.sub(r'\b4776\b', 'Event ID [removed]', clean)
                # Remove any CLI command references unless explicitly requested
                clean = re.sub(r'\b(?:cmd\.exe|powershell|bash):?\s*', '', clean)
                # Ensure no inline bracketed lab strings remain
                clean = re.sub(r'\[.*?\]', '', clean).strip()
                
                # Build dynamic concept response based on the query
                lower = clean.lower()
                lines = []
                
                if "what is cyber security" in lower or "what is information security" in lower:
                    lines.append(f"Cybersecurity (or Information Security) is the practice of protecting systems, networks, and data from digital attacks, unauthorized access, and damage.")
                    lines.append(f"It matters because modern organizations rely on digital assets — breaches cause financial loss, reputational harm, regulatory fines, and operational disruption.")
                    lines.append(f"Core domains: Network Security (firewalls, IDS/IPS, segmentation), Endpoint Security (EDR, patching, hardening), Application Security (SAST/DAST, WAF, secure coding), Identity & Access (MFA, PAM, Zero Trust), Cloud Security (CSPM, CIEM, workload protection), Data Security (encryption, DLP, classification), Incident Response (detection, containment, recovery).")
                    lines.append(f"Frameworks: NIST CSF, ISO 27001, CIS Controls, MITRE ATT&CK. These provide structure for building and measuring a security program.")
                elif "zero trust" in lower:
                    lines.append(f"Zero Trust is a security concept that assumes no user or device should be trusted by default, whether inside or outside the network perimeter.")
                    lines.append(f"It matters because traditional perimeter-based security cannot protect against lateral movement and insider threats; Zero Trust enforces continuous verification.")
                    lines.append(f"Core components include: explicit verification of identity and context, least-privilege access, and continuous monitoring and validation of all assets.")
                    lines.append(f"Example: Instead of automatically allowing all traffic from the corporate network, Zero Trust requires device health checks and user authentication before granting access to each application service.")
                elif "cia triad" in lower or "confidentiality integrity availability" in lower:
                    lines.append(f"The CIA Triad is the foundational model for information security: Confidentiality, Integrity, and Availability.")
                    lines.append(f"Confidentiality ensures only authorized access; Integrity protects data from unauthorized modification; Availability guarantees systems are accessible when needed.")
                    lines.append(f"All security controls map to at least one of these three pillars — a control failing to address any is incomplete.")
                    lines.append(f"Example: Encryption protects Confidentiality; Hashing + signatures protect Integrity; Redundancy + backups protect Availability.")
                elif "defense in depth" in lower:
                    lines.append(f"Defense in Depth is a layered security strategy where multiple defensive mechanisms protect assets, so if one layer fails, others still provide protection.")
                    lines.append(f"It matters because no single control is perfect — perimeter, network, host, application, and data layers each need their own controls.")
                    lines.append(f"Layers: Perimeter (firewall) → Network (IDS/IPS, segmentation) → Endpoint (EDR, patching) → Application (WAF, input validation) → Data (encryption, DLP).")
                    lines.append(f"Example: An attacker breaches the firewall but is caught by EDR, then blocked by application WAF, and data remains encrypted.")
                elif "pass the hash" in lower or "pth" in lower:
                    lines.append(f"Pass-the-Hash (PtH) is a lateral movement technique where an attacker reuses a captured NTLM hash to authenticate to remote systems without knowing the plaintext password.")
                    lines.append(f"It matters because NTLM hashes can be extracted from LSASS memory (Mimikatz, sekurlsa) and reused — the password itself is never needed.")
                    lines.append(f"Key indicators: Event ID 4624 LogonType 3 (Network) with AuthenticationPackage NTLM; PsExec service (PSEXESVC) installs via Event ID 7045; ADMIN$ share writes.")
                    lines.append(f"Mitigation: Enforce Kerberos (disable NTLM where possible), use LAPS for local admin passwords, restrict ADMIN$ access, monitor for NTLM use in privileged contexts.")
                elif "kerberoasting" in lower:
                    lines.append(f"Kerberoasting is a credential access technique where any domain user requests Kerberos service tickets (TGS) for SPNs and requests weak RC4 (0x17) encryption to crack the hash offline.")
                    lines.append(f"It matters because service account hashes (especially with RC4) can be cracked in hours/days, yielding plaintext passwords for privileged accounts.")
                    lines.append(f"Key indicators: Event ID 4769 spike with TicketEncryptionType 0x17 (RC4-HMAC); tools like Rubeus.exe in memory; high TGS request volume from single user.")
                    lines.append(f"Mitigation: Disable RC4 in domain (msDS-SupportedEncryptionTypes), use gMSAs for service accounts, enforce AES-only, monitor 4769 anomalies.")
                elif "golden ticket" in lower:
                    lines.append(f"Golden Ticket is a forged Kerberos TGT (Ticket Granting Ticket) created using the KRBTGT account's hash, allowing unlimited-lifetime authentication as any user in the domain.")
                    lines.append(f"It matters because the KRBTGT hash signs ALL TGTs — compromising it means total domain compromise that survives password resets.")
                    lines.append(f"Key indicators: 4624 LogonType 3 with 10-year TGT lifetime; 4768 TGT requests for non-existent users; Mimikatz 'kerberos::golden' artifacts.")
                    lines.append(f"Mitigation: Rotate KRBTGT password TWICE (per Microsoft guidance), monitor for anomalous TGT lifetimes, restrict KRBTGT replication rights.")
                elif "dcsync" in lower:
                    lines.append(f"DCSync is a credential dumping technique where an attacker with replication rights (DS-Replication-Get-Changes-All) uses the directory replication protocol (MS-DRSR) to pull password hashes from a domain controller — without being a DC.")
                    lines.append(f"It matters because any principal with replication rights can extract all domain credentials, including KRBTGT, enabling Golden Tickets.")
                    lines.append(f"Key indicators: Event ID 4662 with DS-Replication-Get-Changes-All GUID on a non-DC host; Mimikatz 'lsadump::dcsync' signature in traffic.")
                    lines.append(f"Mitigation: Restrict replication rights to DCs only, audit 4662 events from non-DCs, rotate KRBTGT, use gMSAs.")
                elif "sql injection" in lower or "sqli" in lower:
                    lines.append(f"SQL Injection (SQLi) occurs when untrusted user input is concatenated into SQL queries without parameterization, allowing attackers to manipulate query logic and extract/modify/destroy data.")
                    lines.append(f"It matters because databases often hold the most sensitive data (PII, credentials, financial records) and SQLi is a top OWASP risk.")
                    lines.append(f"Types: Error-based (DB errors leak schema), Union-based (append SELECTs), Blind/Time-based (boolean/time oracles), Stacked (multiple statements).")
                    lines.append(f"Mitigation: ALWAYS use parameterized queries / prepared statements; never concatenate strings; least-privilege DB accounts; WAF rules.")
                elif "xss" in lower or "cross site scripting" in lower:
                    lines.append(f"Cross-Site Scripting (XSS) occurs when an application reflects or stores untrusted user input without sanitization, executing attacker-controlled JavaScript in victims' browsers.")
                    lines.append(f"It matters because XSS can steal session cookies, perform actions as the user, deface sites, and deliver malware — all bypassing same-origin policy.")
                    lines.append(f"Types: Reflected (payload in URL/params), Stored (payload in DB), DOM-based (client-side only).")
                    lines.append(f"Mitigation: Content-Security-Policy (script-src 'self'), output encoding per context, HttpOnly+Secure+SameSite cookies, input validation.")
                elif "csrf" in lower or "cross site request forgery" in lower:
                    lines.append(f"Cross-Site Request Forgery (CSRF) tricks a user's browser into making authenticated requests to a target site without their consent, exploiting the browser's automatic cookie sending.")
                    lines.append(f"It matters because state-changing actions (password change, fund transfer, admin actions) can be executed by the attacker via the victim's session.")
                    lines.append(f"Mitigation: SameSite cookies (Lax/Strict), CSRF tokens (synchronizer pattern), double-submit cookies, custom headers (X-Requested-With).")
                elif "ssrf" in lower or "server side request forgery" in lower:
                    lines.append(f"Server-Side Request Forgery (SSRF) occurs when an attacker induces the server to make HTTP requests to internal/arbitrary destinations, bypassing firewall rules.")
                    lines.append(f"It matters because SSRF can access cloud metadata services (AWS IMDS, GCP metadata), internal APIs, and file:/// schemas — leading to credential theft and RCE.")
                    lines.append(f"Mitigation: Allow-list egress URLs, block private IP ranges (169.254.169.254, 10.x, 192.168.x), validate user-supplied URLs, use egress proxies.")
                elif "password spray" in lower:
                    lines.append(f"Password Spraying is a credential access attack where a single common password is tried against many accounts, staying under per-account lockout thresholds.")
                    lines.append(f"It matters because it evades traditional brute-force detection (which looks for many failures on ONE account) and often succeeds with common passwords like 'Spring2024!' or 'Password1'.")
                    lines.append(f"Key indicators: Event ID 4625 burst with status 0xC000006A, one attempt per account, single source IP; followed by 4624 LogonType 10 (RDP) success.")
                    lines.append(f"Mitigation: Enforce MFA on all remote access, monitor 4625 SourceIP cardinality, ban common passwords, use Azure AD Password Protection.")
                elif "credential stuffing" in lower:
                    lines.append(f"Credential Stuffing is the automated injection of breached username/password pairs across many sites, exploiting password reuse.")
                    lines.append(f"It matters because billions of credentials are available from past breaches; automation tools (Sentry MBA, OpenBullet) can test millions per hour.")
                    lines.append(f"Mitigation: MFA (blocks login even with valid creds), rate-limiting, bot detection (reCAPTCHA, device fingerprinting), breach monitoring (HaveIBeenPwned API).")
                elif "entropy" in lower or "shannon" in lower:
                    lines.append(f"Shannon Entropy measures the unpredictability of a password in bits: H = -Σ(p × log2 p) for each character's frequency. Higher entropy = harder to guess.")
                    lines.append(f"It matters because entropy directly correlates to crack time: 28 bits = instant, 40 bits = hours, 55 bits = years, 75+ bits = effectively unbreakable offline.")
                    lines.append(f"Example: 'Password123!' has low entropy (common word + pattern); 'CorrectHorseBatteryStaple' has high entropy (4 random words).")
                    lines.append(f"Tool: CyberGPT Password Audit computes Shannon + charset entropy, penalizes patterns, estimates Argon2id/bcrypt crack times.")
                elif "argon2id" in lower or "bcrypt" in lower:
                    lines.append(f"Argon2id and bcrypt are memory-hard password hashing algorithms designed to resist GPU/ASIC cracking by requiring significant memory and CPU per guess.")
                    lines.append(f"Argon2id (OWASP recommended): m=64MB, t=3, p=4 — slows attackers to ~1,000 guesses/sec vs billions for SHA-256.")
                    lines.append(f"bcrypt (min cost 12): ~10,000 guesses/sec — slower than SHA but faster than Argon2id; widely supported.")
                    lines.append(f"Never use MD5, SHA-1, SHA-256, or plaintext for passwords — they are not designed for credential storage.")
                else:
                    # Generic fallback for unknown concepts
                    lines.append(f"'{clean}' is a cybersecurity concept. For detailed explanations, try: 'explain zero trust', 'explain pass the hash', 'explain kerberoasting', 'what is sql injection', 'what is xss', 'explain cia triad', 'what is defense in depth', 'explain password spraying', 'what is entropy', 'explain argon2id'.")
                
                clean_text = " ".join(lines)
                return LLMResponse(
                    content=clean_text,
                    model_used="cybergpt-concept",
                    tier=tier,
                    token_usage=TokenUsage(),
                    latency_ms=0,
                    success=True,
                    suggested_labs=intent_result.suggested_labs or [],
                )
            # Fall through to LLM if concept handling not matched

        # Handle OFF_TOPIC in Cyber mode: return 1-line + action chip
        if intent_result.intent == Intent.OFF_TOPIC:
            return LLMResponse(
                content=intent_result.direct_response or "I'm CyberGPT in Cyber mode — I specialize in defensive cybersecurity. For general topics, please switch to Normal mode.",
                model_used="cybergpt-offtopic",
                tier=tier,
                token_usage=TokenUsage(),
                latency_ms=0,
                success=True,
                action=intent_result.action,
                suggested_labs=[],
            )

        # Handle INCIDENT_TRIAGE: use structured template, continue to normal flow
        if intent_result.intent == Intent.INCIDENT_TRIAGE:
            # Use the Balanced tier prompt which includes Event IDs / IoCs / SIGMA Rules
            # The system prompt already includes the proper template;
            # we just need to ensure the messages are properly sanitized
            sanitized = sanitize_messages(messages)
            # No bypass - let the normal failover chain handle it
            # but with sanitized messages that don't have inline lab strings
            # We simply continue to the normal flow
            pass

        # Handle GREETINGS: friendly response with Normal mode hint
        if intent_result.intent == Intent.GREETINGS:
            # Return the greeting response from intent classification
            if intent_result.direct_response:
                return LLMResponse(
                    content=intent_result.direct_response,
                    model_used="cybergpt-greeting",
                    tier=tier,
                    token_usage=TokenUsage(),
                    latency_ms=0,
                    success=True,
                    suggested_labs=intent_result.suggested_labs or [],
                )
            # Default greeting response
            greeting_text = ("Hello! I'm CyberGPT in Cyber mode — I can help with defensive security questions, scenario labs, or password audits. "
                            "Switch to Normal mode for broader AI assistance.")
            return LLMResponse(
                content=greeting_text,
                model_used="cybergpt-greeting",
                tier=tier,
                token_usage=TokenUsage(),
                latency_ms=0,
                success=True,
                suggested_labs=intent_result.suggested_labs or [],
            )

        # --- Original failover loop begins here ---
        tried_models = []
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
                    # Strip inline lab recommendations from LLM response
                    # and inject suggested labs from catalog
                    from services.scenario_manager import LAB_REPOSITORY
                    cleaned_content, suggested_labs = _inject_lab_recommendations(response.content, LAB_REPOSITORY)
                    response.content = cleaned_content
                    response.suggested_labs = suggested_labs or intent_result.suggested_labs or []
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
        self, messages: List[Dict[str, str]], tier: ModelTier = ModelTier.BALANCED, mode: str = "cyber"
    ) -> LLMResponse:
        """Synchronous entry point for Flask handlers.

        Submits the async chat() coroutine to the persistent background event
        loop and blocks for the result. Safe to call from request threads; the
        underlying aiohttp session stays bound to one loop.
        """
        return run_async(self.chat(messages, _coerce_tier(tier), mode))

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


# --- Intent Classification ---

from enum import Enum
from dataclasses import dataclass
from typing import Optional, List

class Intent(Enum):
    META_IDENTITY = "meta_identity"
    CONCEPTS = "concepts"
    INCIDENT_TRIAGE = "incident_triage"
    GREETINGS = "greetings"
    GENERAL_CHAT = "general_chat"
    OFF_TOPIC = "off_topic"


@dataclass
class IntentResult:
    intent: Intent
    bypass_llm: bool
    direct_response: Optional[str]
    section_name: Optional[str]
    requires_telemetry: bool
    suggested_labs: List[dict] = None
    action: Optional[str] = None  # e.g., "switch_mode"

    def __post_init__(self):
        if self.suggested_labs is None:
            self.suggested_labs = []


# --- Intent Classification ---

def _classify_intent(message: str, mode: str = "cyber") -> IntentResult:
    """Classify user message intent for routing decisions.

    Returns IntentResult determining whether to bypass LLM,
    which template to use, and what direct response to give.

    Classification logic is embedded inline (no external module dependency):
    - META_IDENTITY: "who are you", "whats your name", etc.
    - CONCEPTS: "what is cyber security", "explain zero trust", etc.
    - INCIDENT_TRIAGE: "analyze log", "pcap", "alert", etc.
    - GREETINGS: "hi", "hello", "kaise ho", etc.
    - OFF_TOPIC (Cyber mode): non-cyber queries like "what is trading"
    - GENERAL_CHAT: default fall-through.
    """
    lower = message.lower().strip()
    
    # --- Cyber-specific keywords for topic detection ---
    cyber_keywords = [
        "cyber", "security", "phishing", "malware", "ransomware", "spyware",
        "sql injection", "xss", "oauth", "credential", "password", "network",
        "dns", "tls", "siem", "event", "log", "incident", "zero trust",
        "active directory", "kerberos", "kerberoasting", "pass the hash",
        "psexec", "lateral movement", "privilege escalation", "persistence",
        "c2", "command control", "ioc", "indicator", "mitre", "att&ck",
        "vulnerability", "exploit", "patch", "cve", "cwe", "owasp",
        "web appsec", "api", "jwt", "token", "auth", "mfa", "2fa",
        "encryption", "tls", "ssl", "certificate", "pki", "ca",
        "firewall", "ids", "ips", "edr", "xdr", "soc", "blue team",
        "red team", "purple team", "threat hunting", "forensics",
        "memory dump", "volatility", "sysmon", "edr", "sentinel",
        "splunk", "sigma", "yara", "rules", "detection", "hunting",
        "cloud", "aws", "azure", "gcp", "iam", "s3", "bucket",
        "container", "kubernetes", "docker", "ci/cd", "devsecops",
        "supply chain", "sbom", "dependency", "container", "image",
        "email", "spam", "spoof", "dkim", "dmarc", "spf", "bec",
        "quishing", "vishing", "smishing", "spearphish", "whaling",
        "ransomware", "wiper", "ransom", "extortion", "leak",
        "data breach", "exfiltration", "collection", "discovery",
        "reconnaissance", "initial access", "execution", "persistence",
        "privilege escalation", "defense evasion", "credential access",
        "lateral movement", "command and control", "exfiltration",
        "impact", "wiper", "destruction", "inhibit recovery"
    ]
    
    # Check if query is cyber-related
    is_cyber_related = any(kw in lower for kw in cyber_keywords)
    
    # --- Greetings first ---
    greeting_keywords_en = ["hi", "hello", "hey", "good morning", "good afternoon", "good evening"]
    greeting_keywords_ur = ["salaam", "assalam o alikum"]
    greeting_keywords_hi = ["namaste", "hello"]
    greeting_keywords_pa = ["sat sri akal", "satnam"]
    
    is_greeting = (
        any(kw in lower for kw in greeting_keywords_en) or
        any(kw in lower for kw in greeting_keywords_ur) or
        any(kw in lower for kw in greeting_keywords_hi) or
        any(kw in lower for kw in greeting_keywords_pa)
    )
    
    if is_greeting:
        return IntentResult(
            intent=Intent.GREETINGS,
            bypass_llm=True,
            direct_response=(
                "I'm CyberGPT, a defensive cybersecurity learning assistant "
                "developed by Muhammad Umair. How can I assist your security studies today?"
            ),
            section_name=None,
            requires_telemetry=False,
        )
    
    # --- Identity/Meta questions ---
    meta_keywords_en = [
        "who are you", "what is your name", "your name is",
        "whats your name", "who made you", "created by", "developer"
    ]
    meta_keywords_ur = ["tera naam kya hai", "tum kaun ho", "ye bot kaun hai", "is ka developer kaun hai"]
    meta_keywords_hi = ["tum kaun ho", "mera naam kya hai", "iska developer kaun hai"]
    meta_keywords_pa = ["tuani kovan", "tusi kaun hai", "tun mere kitte da developer kaun hai"]
    
    is_meta = (
        any(kw in lower for kw in meta_keywords_en) or
        any(kw in lower for kw in meta_keywords_ur) or
        any(kw in lower for kw in meta_keywords_hi) or
        any(kw in lower for kw in meta_keywords_pa)
    )
    
    if is_meta:
        return IntentResult(
            intent=Intent.META_IDENTITY,
            bypass_llm=True,
            direct_response=(
                "I'm CyberGPT, a defensive cybersecurity learning assistant "
                "developed by Muhammad Umair. How can I assist your security studies today?"
            ),
            section_name=None,
            requires_telemetry=False,
        )
    
    # --- Concept questions ---
    concept_keywords_en = [
        "what is cyber security", "what is information security",
        "explain zero trust", "zero trust model",
        "explain defense in depth", "cia triad",
        "what is pass the hash", "explain pass the hash",
        "what is kerberoasting", "explain kerberoasting",
        "what is golden ticket", "explain golden ticket",
        "what is dcsync", "explain dcsync",
        "what is pass the ticket", "explain pass the ticket",
        "what is sql injection", "explain sql injection",
        "what is xss", "explain xss", "cross site scripting",
        "what is csrf", "explain csrf",
        "what is rce", "explain rce", "remote code execution",
        "what is lfi", "explain lfi", "local file inclusion",
        "what is rfi", "explain rfi", "remote file inclusion",
        "what is ssti", "explain ssti", "server side template injection",
        "what is xxe", "explain xxe", "xml external entity",
        "what is ssrf", "explain ssrf", "server side request forgery",
        "what is idor", "explain idor", "insecure direct object reference",
        "what is broken access control", "explain broken access control",
        "what is security misconfiguration", "explain security misconfiguration",
        "what is vulnerable components", "explain vulnerable components",
        "what is authentication failure", "explain authentication failure",
        "what is software integrity", "explain software integrity",
        "what is logging failure", "explain logging failure",
        "what is ssrf", "explain ssrf",
        "what is gmsa", "explain gmsa", "group managed service account",
        "what is ad cs", "explain ad cs", "active directory certificate services",
        "what is certificate template", "explain certificate template",
        "what is esc1", "explain esc1",
        "what is dns tunneling", "explain dns tunneling",
        "what is hsts", "explain hsts", "http strict transport security",
        "what is tls", "explain tls", "transport layer security",
        "what is certificate pinning", "explain certificate pinning",
        "what is password spraying", "explain password spraying",
        "what is brute force", "explain brute force",
        "what is credential stuffing", "explain credential stuffing",
        "what is mfa bypass", "explain mfa bypass",
        "what is password reuse", "explain password reuse",
        "what is entropy", "explain entropy", "shannon entropy",
        "what is argon2id", "explain argon2id", "what is bcrypt", "explain bcrypt"
    ]
    concept_keywords_ur = ["cyber security kya hai", "zero trust kya hai"]
    concept_keywords_hi = ["cyber security kya hai", "zero trust kya hai"]
    concept_keywords_pa = ["cyber security kya hai", "zero trust kya hai"]
    
    is_concept = (
        any(kw in lower for kw in concept_keywords_en) or
        any(kw in lower for kw in concept_keywords_ur) or
        any(kw in lower for kw in concept_keywords_hi) or
        any(kw in lower for kw in concept_keywords_pa)
    )
    
    if is_concept:
        # Extract suggested labs for this concept
        from services.scenario_manager import LAB_REPOSITORY
        suggested_labs = _extract_suggested_labs(lower, LAB_REPOSITORY)
        return IntentResult(
            intent=Intent.CONCEPTS,
            bypass_llm=True,
            direct_response=None,
            section_name="concept",
            requires_telemetry=False,
            suggested_labs=suggested_labs,
        )
    
    # --- Incident/Triage questions ---
    incident_keywords_en = [
        "analyze log", "pcap", "alert", "incident response", "forensic",
        "investigate", "triage", "hunt", "ioc", "indicators"
    ]
    incident_keywords_ur = ["log analyze", "pcap dekhna", "alert"]
    incident_keywords_hi = ["log analyze", "pcap dekhna", "alert"]
    incident_keywords_pa = ["log analyze", "pcap dekhna", "alert"]
    
    is_incident = (
        any(kw in lower for kw in incident_keywords_en) or
        any(kw in lower for kw in incident_keywords_ur) or
        any(kw in lower for kw in incident_keywords_hi) or
        any(kw in lower for kw in incident_keywords_pa)
    )
    
    if is_incident:
        from services.scenario_manager import LAB_REPOSITORY
        suggested_labs = _extract_suggested_labs(lower, LAB_REPOSITORY)
        return IntentResult(
            intent=Intent.INCIDENT_TRIAGE,
            bypass_llm=False,
            direct_response=None,
            section_name="incident",
            requires_telemetry=True,
            suggested_labs=suggested_labs,
        )
    
    # --- OFF_TOPIC in Cyber mode: non-cyber queries ---
    if mode == "cyber" and not is_cyber_related:
        return IntentResult(
            intent=Intent.OFF_TOPIC,
            bypass_llm=True,
            direct_response=(
                "I'm CyberGPT in Cyber mode — I specialize in defensive cybersecurity. "
                "For general topics, please switch to Normal mode."
            ),
            section_name=None,
            requires_telemetry=False,
            action="switch_mode",
            suggested_labs=[],
        )
    
    # --- Default: general chat ---
    from services.scenario_manager import LAB_REPOSITORY
    suggested_labs = _extract_suggested_labs(lower, LAB_REPOSITORY)
    return IntentResult(
        intent=Intent.GENERAL_CHAT,
        bypass_llm=False,
        direct_response=None,
        section_name=None,
        requires_telemetry=False,
        suggested_labs=suggested_labs,
    )
    
def _strip_lab_recommendations(text: str) -> str:
    """Remove inline CyberGPT Lab Recommendation strings from response text.
    
    Pattern: [CyberGPT Lab Recommendation: Test your skills live in ...]
    """
    import re
    return re.sub(r'\[CyberGPT Lab Recommendation:.*?\]', '', text).strip()


def _extract_suggested_labs(message: str, lab_repository: Dict) -> List[Dict]:
    """Extract up to 2 verified lab objects from catalog matching query keywords.
    
    Matches query keywords against lab titles/categories from the actual
    data/labs/*.json catalog, NOT inline text generation.
    """
    suggested = []
    lower = message.lower()
    
    # Category mapping for matching
    category_map = {
        "phishing": "phishing",
        "soc": "soc/endpoint", 
        "password": "password/auth",
        "web appsec": "web appsec",
        "cloud": "cloud/iam",
        "network": "network/dns-tls",
        "logs": "logs/siem",
        "active directory": "active directory",
    }
    
    # Score labs based on keyword matches
    scores = {}
    for lab_id, lab in lab_repository.items():
        score = 0
        title = lab.get("title", "").lower()
        category = lab.get("category", "").lower()
        learning = " ".join(lab.get("learning_objectives", [])).lower()
        
        # Match against query keywords
        keywords = ["phishing", "zero trust", "malware", "ransomware", 
                   "spyware", "sql injection", "xss", "oauth", "credential",
                   "password", "network", "dns", "tls", "siem", "event",
                   "log", "incident", "phishing", "malware"]
        
        for kw in keywords:
            if kw in lower:
                if kw in title or kw in learning:
                    score += 1
        
        # Also match by category
        for cat_kw, cat_name in category_map.items():
            if cat_kw in lower and cat_kw in category:
                score += 2
        
        if score > 0 and lab_id not in [s["id"] for s in suggested]:
            if len(suggested) < 2 or score >= 2:
                suggested.append({
                    "id": lab_id,
                    "title": lab.get("title", "Unknown Lab"),
                    "category": lab.get("category", "Unknown"),
                    "score": score
                })
    
    # Sort by score and return top 2
    suggested.sort(key=lambda x: x["score"], reverse=True)
    return [{"id": s["id"], "title": s["title"], "category": s["category"]} 
            for s in suggested[:2]]


def _inject_lab_recommendations(content: str, lab_repository: Dict) -> Tuple[str, List[Dict]]:
    """Inject lab recommendations based on content keywords using ACTUAL catalog data.
    
    Returns (cleaned_content, suggested_labs) where:
    - cleaned_content has [CyberGPT Lab Recommendation:...] stripped out
    - suggested_labs contains up to 2 verified lab objects from the catalog
    """
    # First, strip any existing inline recommendation strings
    cleaned = _strip_lab_recommendations(content)
    
    # Extract suggested labs from the actual catalog
    suggested_labs = _extract_suggested_labs(cleaned, lab_repository)
    
    return cleaned, suggested_labs
