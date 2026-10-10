"""
CyberGPT Password Analyzer - Shannon entropy, RockYou dictionary checks,
smart password transformation, Argon2id/bcrypt hardening guidance.
"""

import math
import re
import hashlib
import secrets
import string
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional

# Compact RockYou-derived common password blacklist (top entries + variants)
ROCKYOU_COMMON = frozenset([
    "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234",
    "111111", "1234567", "dragon", "123123", "baseball", "abc123", "football",
    "monkey", "letmein", "shadow", "master", "666666", "qwertyuiop", "123321",
    "mustang", "1234567890", "michael", "654321", "superman", "1qaz2wsx",
    "7777777", "121212", "000000", "qazwsx", "123qwe", "killer", "trustno1",
    "jordan", "jennifer", "zxcvbnm", "asdfgh", "hunter", "buster", "soccer",
    "harley", "batman", "andrew", "tigger", "sunshine", "iloveyou", "2000",
    "charlie", "robert", "thomas", "hockey", "ranger", "daniel", "starwars",
    "klaster", "112233", "george", "computer", "michelle", "jessica", "pepper",
    "1111", "zxcvbn", "555555", "11111111", "131313", "freedom", "777777",
    "pass", "maggie", "159753", "arsenal", "love", "secret", "andrea",
    "fuckyou", "joshua", "morgan", "admin", "welcome", "login", "root",
    "changeme", "password1", "password123", "p@ssw0rd", "p@ssword",
    "zacpaul0890", "zac", "paul", "test", "guest", "user", "oracle",
])

# Common patterns that reduce entropy
COMMON_PATTERNS = [
    (r"(.)\1{2,}", "repeated character run"),
    (r"12345|23456|34567|45678|56789|67890", "sequential digits"),
    (r"abcdefghij|qwerty|asdfgh|zxcvbn", "keyboard walk"),
    (r"^(19|20)\d{2}$", "birth year"),
    (r"(password|pass|pwd|secret)", "dictionary keyword"),
]

ARGON2ID_PARAMS = {"memory_mib": 64, "iterations": 3, "parallelism": 4}
BCRYPT_COST = 12


@dataclass
class PasswordAuditResult:
    original_password: str
    original_entropy_bits: float
    original_strength: str
    original_score: int  # 0-4 zxcvbn-style
    hardened_password: str
    hardened_entropy_bits: float
    hardened_strength: str
    hardened_score: int
    entropy_gain_bits: float
    in_rockyou: bool
    pattern_findings: List[str]
    crack_time_offline_argon2id: str
    crack_time_offline_bcrypt: str
    recommendations: List[str]
    argon2id_params: Dict
    bcrypt_cost: int

    def to_dict(self) -> Dict:
        return asdict(self)


CHARSET_SIZES = {
    "lower": 26,
    "upper": 26,
    "digits": 10,
    "symbols": 33,
}

STRENGTH_LABELS = {0: "Very Weak", 1: "Weak", 2: "Fair", 3: "Strong", 4: "Very Strong"}


def char_pool(password: str) -> int:
    """Compute effective charset size used by the password."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += CHARSET_SIZES["lower"]
    if re.search(r"[A-Z]", password):
        pool += CHARSET_SIZES["upper"]
    if re.search(r"[0-9]", password):
        pool += CHARSET_SIZES["digits"]
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += CHARSET_SIZES["symbols"]
    return max(pool, 1)


def shannon_entropy(password: str) -> float:
    """Compute Shannon entropy in bits over the character frequency distribution."""
    if not password:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in password:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(password)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    # Scale by length to approximate total bits: H_total = L * H_per_char
    return round(entropy * length, 2)


def charset_entropy(password: str) -> float:
    """Charset-based entropy: log2(pool^length)."""
    pool = char_pool(password)
    if pool <= 1:
        return 0.0
    return round(len(password) * math.log2(pool), 2)


def effective_entropy(password: str) -> float:
    """Blend Shannon and charset entropy; penalize pattern matches."""
    base = (shannon_entropy(password) + charset_entropy(password)) / 2.0
    penalty = 0.0
    for pattern, _label in COMMON_PATTERNS:
        if re.search(pattern, password, re.IGNORECASE):
            penalty += 8.0
    lower_pw = password.lower()
    if lower_pw in ROCKYOU_COMMON:
        penalty += 20.0
    return max(0.0, round(base - penalty, 2))


def score_password(password: str) -> int:
    """zxcvbn-style 0-4 score."""
    entropy = effective_entropy(password)
    if entropy < 28:
        return 0
    if entropy < 40:
        return 1
    if entropy < 55:
        return 2
    if entropy < 75:
        return 3
    return 4


def strength_label(score: int) -> str:
    return STRENGTH_LABELS.get(score, "Unknown")


def crack_time_estimate(entropy_bits: float, guesses_per_second: float = 1e10) -> str:
    """Estimate offline crack time given entropy and hash-rate."""
    if entropy_bits <= 0:
        return "instant"
    guesses = 2 ** entropy_bits / 2  # average case
    seconds = guesses / guesses_per_second
    if seconds < 1:
        return "instant"
    if seconds < 60:
        return f"{seconds:.0f} seconds"
    if seconds < 3600:
        return f"{seconds / 60:.1f} minutes"
    if seconds < 86400:
        return f"{seconds / 3600:.1f} hours"
    if seconds < 31536000:
        return f"{seconds / 86400:.0f} days"
    years = seconds / 31536000
    if years < 1000:
        return f"{years:.0f} years"
    if years < 1e6:
        return f"{years / 1000:.0f}K years"
    if years < 1e9:
        return f"{years / 1e6:.0f}M years"
    return f"{years / 1e9:.0f}B years"


def analyze_patterns(password: str) -> List[str]:
    findings = []
    for pattern, label in COMMON_PATTERNS:
        if re.search(pattern, password, re.IGNORECASE):
            findings.append(f"Detected {label}")
    if len(password) < 8:
        findings.append("Too short (< 8 characters)")
    if password.lower() in ROCKYOU_COMMON:
        findings.append("Found in RockYou breach corpus")
    if re.match(r"^[A-Za-z]+[0-9]+$", password):
        findings.append("Predictable word+digits structure")
    return findings


def generate_hardened_password(base_pwd: str, include_word: bool = True) -> str:
    """
    Transform a weak base password into a high-entropy enterprise variant.

    Strategy:
      1. Split base into alpha segments (e.g. 'ZacPaul0890' -> ['Zac', 'Paul']).
      2. Wrap with symbol clusters and internal symbol separators.
      3. Append a security suffix marker with random digits.

    Example: 'ZacPaul0890' -> '^%$Zac%Paul0890_#Sec99' style output.
    """
    if not base_pwd:
        base_pwd = "User"

    # Split into alpha / digit / symbol segments, further splitting
    # camelCase boundaries so 'ZacPaul' -> ['Zac', 'Paul'].
    segments = re.findall(
        r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|[0-9]+|[^A-Za-z0-9]+", base_pwd
    )
    segments = [s for s in segments if s]

    # Join alpha segments with '%', keep digits/symbols trailing
    alpha_segments = [s for s in segments if re.match(r"^[A-Za-z]+$", s)]
    non_alpha_tail = "".join(s for s in segments if not re.match(r"^[A-Za-z]+$", s))

    if alpha_segments:
        core = "%".join(alpha_segments)
    else:
        core = base_pwd

    prefix = "^%$"
    separator = "_"
    suffix_digits = secrets.choice(["99", "42", "77", "13", "88"])
    suffix = f"#Sec{suffix_digits}"

    hardened = f"{prefix}{core}{non_alpha_tail}{separator}{suffix}"

    # Ensure reasonable length; if too long, trim core
    if len(hardened) > 48:
        hardened = hardened[:48]

    # Guarantee it differs from original
    if hardened == base_pwd:
        hardened = f"^{core}_#Sec{secrets.choice(['99','42'])}"

    return hardened


def get_hash_guidance() -> Dict:
    return {
        "argon2id": {
            "memory_mib": ARGON2ID_PARAMS["memory_mib"],
            "iterations": ARGON2ID_PARAMS["iterations"],
            "parallelism": ARGON2ID_PARAMS["parallelism"],
            "note": "OWASP-recommended KDF for password hashing (m=64MB, t=3, p=4).",
        },
        "bcrypt": {
            "cost_factor": BCRYPT_COST,
            "note": "Minimum cost factor 12 (2^12 rounds). Increase to 14+ for high-value systems.",
        },
    }


def audit_password(base_pwd: str) -> PasswordAuditResult:
    """Full audit pipeline returning original vs. hardened analysis."""
    original = base_pwd or ""
    original_entropy = effective_entropy(original)
    original_score = score_password(original)
    original_strength = strength_label(original_score)

    hardened = generate_hardened_password(original)
    hardened_entropy = effective_entropy(hardened)
    hardened_score = score_password(hardened)
    hardened_strength = strength_label(hardened_score)

    in_rockyou = (original.lower() in ROCKYOU_COMMON) or (hardened.lower() in ROCKYOU_COMMON)
    pattern_findings = analyze_patterns(original)

    recommendations: List[str] = []
    if original_score < 2:
        recommendations.append("Original password is weak; adopt the hardened variant immediately.")
    if len(original) < 12:
        recommendations.append("Use at least 12-16 characters for production accounts.")
    if not re.search(r"[^a-zA-Z0-9]", original):
        recommendations.append("Add symbols to defeat dictionary and rule-based attacks.")
    if re.search(r"[0-9]{4}$", original):
        recommendations.append("Trailing 4-digit numbers are predictable; use random suffixes.")
    if in_rockyou:
        recommendations.append("Base password appears in breach corpora; rotate everywhere it is reused.")
    recommendations.append(
        f"Store hashes with Argon2id (m={ARGON2ID_PARAMS['memory_mib']}MB, "
        f"t={ARGON2ID_PARAMS['iterations']}, p={ARGON2ID_PARAMS['parallelism']}) "
        f"or bcrypt cost {BCRYPT_COST}."
    )
    recommendations.append("Never reuse the hardened variant across systems; use a password manager.")

    # Crack time estimates: Argon2id slows to ~1e3 guesses/s, bcrypt ~1e4 guesses/s
    crack_argon2 = crack_time_estimate(hardened_entropy, guesses_per_second=1e3)
    crack_bcrypt = crack_time_estimate(hardened_entropy, guesses_per_second=1e4)

    return PasswordAuditResult(
        original_password=original,
        original_entropy_bits=original_entropy,
        original_strength=original_strength,
        original_score=original_score,
        hardened_password=hardened,
        hardened_entropy_bits=hardened_entropy,
        hardened_strength=hardened_strength,
        hardened_score=hardened_score,
        entropy_gain_bits=round(hardened_entropy - original_entropy, 2),
        in_rockyou=in_rockyou,
        pattern_findings=pattern_findings,
        crack_time_offline_argon2id=crack_argon2,
        crack_time_offline_bcrypt=crack_bcrypt,
        recommendations=recommendations,
        argon2id_params=dict(ARGON2ID_PARAMS),
        bcrypt_cost=BCRYPT_COST,
    )


def client_entropy(password: str) -> Dict:
    """Lightweight entropy payload for instant client-side computation."""
    return {
        "entropy_bits": shannon_entropy(password),
        "charset_bits": charset_entropy(password),
        "length": len(password),
        "pool_size": char_pool(password),
    }


def analyze_password_strength(password: str) -> Dict:
    """Legacy-compatible strength snapshot (score, label, entropy)."""
    entropy = effective_entropy(password)
    score = score_password(password)
    return {
        "password": password,
        "entropy_bits": entropy,
        "score": score,
        "strength": strength_label(score),
        "length": len(password),
        "in_rockyou": password.lower() in ROCKYOU_COMMON,
        "pattern_findings": analyze_patterns(password),
    }


password_analyzer = {
    "audit": audit_password,
    "harden": generate_hardened_password,
    "client_entropy": client_entropy,
    "guidance": get_hash_guidance,
    "strength": analyze_password_strength,
}