"""
CyberGPT Flask Application - Enterprise SOC Training & AI Mentorship Platform.
API routes: chat, password audit, scenarios, evaluations, cheat sheets.
CSRF disabled for JSON routes; in-memory SERVER_CHAT_MEMORY (last 10 msgs).
Security: 6-pillar hardening via services/security.py
"""

import os
import json
import logging
from collections import OrderedDict, deque
from functools import wraps
from typing import Dict

from flask import Flask, request, jsonify, send_from_directory, render_template
from flask_cors import CORS

from services.llm_service import llm_service, ModelTier
from services.password_analyzer import password_analyzer
from services.scenario_manager import scenario_manager
from services.security import (
    configure_security,
    rate_limit,
    validate_chat_input,
    validate_analyzer_input,
    wrap_user_evidence,
    SecureErrorHandler,
    FileUploadValidator,
    MAX_CHAT_CHARS,
    MAX_ANALYZER_CHARS,
)

# ----------------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s :: %(message)s",
)
logger = logging.getLogger("cybergpt.app")

# ----------------------------------------------------------------------------
# Flask setup
# ----------------------------------------------------------------------------
app = Flask(
    __name__,
    template_folder="templates",
    static_folder="static",
)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2 MB body cap
app.config["JSON_SORT_KEYS"] = False

CORS(app, resources={r"/api/*": {"origins": "*"}})

# ----------------------------------------------------------------------------
# Security Configuration (6-pillar hardening)
# ----------------------------------------------------------------------------
configure_security(app)

# ----------------------------------------------------------------------------
# Server-side chat memory (in-memory, per-session, strict 10 msgs / 5 turns)
# Prevents cookie overflow by keeping state on the server only.
# ----------------------------------------------------------------------------
SERVER_CHAT_MEMORY: "OrderedDict[str, deque]" = OrderedDict()
MAX_TURNS = 5  # 5 user turns x 2 messages = 10 messages max
MAX_MESSAGES = MAX_TURNS * 2
MAX_SESSIONS = 512  # bound memory growth


def _get_session_memory(session_id: str) -> deque:
    """Retrieve or create a bounded per-session message deque."""
    if session_id not in SERVER_CHAT_MEMORY:
        if len(SERVER_CHAT_MEMORY) >= MAX_SESSIONS:
            # Evict oldest session to bound memory
            SERVER_CHAT_MEMORY.popitem(last=False)
        SERVER_CHAT_MEMORY[session_id] = deque(maxlen=MAX_MESSAGES)
    return SERVER_CHAT_MEMORY[session_id]


def _push_message(session_id: str, role: str, content: str) -> None:
    mem = _get_session_memory(session_id)
    mem.append({"role": role, "content": content})


def _get_history(session_id: str) -> list:
    return list(_get_session_memory(session_id))


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
def json_only(f):
    """Enforce JSON request bodies for state-changing routes."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not request.is_json:
            return jsonify({"success": False, "error": "Content-Type must be application/json"}), 415
        return f(*args, **kwargs)
    return wrapper


def _resolve_tier(tier_name: str) -> ModelTier:
    mapping = {
        "flash": ModelTier.FLASH,
        "balanced": ModelTier.BALANCED,
        "pro": ModelTier.PRO,
    }
    return mapping.get((tier_name or "balanced").lower(), ModelTier.BALANCED)


def _client_entropy_js():
    """Return the client-side entropy snippet for instant feedback."""
    return password_analyzer["client_entropy"]("")


# ----------------------------------------------------------------------------
# Static / SPA routes
# ----------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/favicon.ico")
def favicon():
    return "", 204


@app.route("/static/<path:filename>")
def static_files(filename):
    return send_from_directory(app.static_folder, filename)


# ----------------------------------------------------------------------------
# API: Health
# ----------------------------------------------------------------------------
@app.route("/api/health")
def health():
    from services.knowledge_engine import knowledge_engine

    return jsonify({
        "status": "ok",
        "platform": "CyberGPT",
        "subtitle": "Defensive Cyber Intelligence & SOC Operations Simulator",
        "version": "2.1.0",
        "llm_session": llm_service.get_token_stats(),
        "knowledge_engine": knowledge_engine.stats(),
    })


# ----------------------------------------------------------------------------
# API: Chat (dual-mode intelligence with BYOK + failover)
# ----------------------------------------------------------------------------
# BYOK keys travel per-request from the browser Settings modal (localStorage)
# and are NEVER logged or persisted server-side.
MAX_BYOK_KEY_CHARS = 200


def _sanitize_byok(data: Dict) -> Dict[str, str]:
    """Extract and bound user-supplied provider keys/models from the payload."""
    byok: Dict[str, str] = {}
    for field_name, key_name in (
        ("openai_api_key", "openai_api_key"),
        ("anthropic_api_key", "anthropic_api_key"),
        ("openai_model", "openai_model"),
        ("anthropic_model", "anthropic_model"),
    ):
        value = str(data.get(field_name, "") or "").strip()
        if value:
            byok[key_name] = value[:MAX_BYOK_KEY_CHARS]
    return byok


@app.route("/api/chat", methods=["POST"])
@json_only
@rate_limit
def api_chat():
    data = request.get_json(force=True, silent=True) or {}
    message = str(data.get("message", "")).strip()
    tier_name = str(data.get("tier", "balanced")).strip()
    session_id = str(data.get("session_id", "default"))
    mode = str(data.get("mode", "cyber")).strip().lower()
    mode = "normal" if mode == "normal" else "cyber"

    # Input validation
    valid, result = validate_chat_input(message)
    if not valid:
        return jsonify({"success": False, "error": result}), 400
    message = result  # sanitized message

    if not message:
        return jsonify({"success": False, "error": "Empty message"}), 400

    # Push user message into server memory (bounded)
    _push_message(session_id, "user", message)
    history = _get_history(session_id)

    tier = _resolve_tier(tier_name)

    # BYOK (user-supplied OpenAI / Anthropic credentials), sanitized + bounded.
    byok = _sanitize_byok(data)

    # Bridge to the async LLM service via the persistent
    # background event loop (safe from Flask request threads).
    response = llm_service.chat_sync(history, tier, mode, byok)

    # Push assistant reply into memory
    if response.success:
        _push_message(session_id, "assistant", response.content)

    payload = response.to_dict()
    payload["session_id"] = session_id
    payload["history_length"] = len(_get_history(session_id))
    payload["mode"] = mode
    return jsonify(payload)


# ----------------------------------------------------------------------------
# API: Clear History (session memory purge)
# ----------------------------------------------------------------------------
@app.route("/api/clear-history", methods=["POST"])
def api_clear_history():
    """Purge the in-memory chat history for a session (session memory flush).

    The server keeps conversation state in SERVER_CHAT_MEMORY keyed by
    session_id (never in cookies). This route drops that session's deque so a
    "Flush Session Memory" action genuinely clears server-side state; the
    client then rotates to a fresh session_id.
    """
    data = request.get_json(force=True, silent=True) or {}
    session_id = str(data.get("session_id", "default"))
    purged = SERVER_CHAT_MEMORY.pop(session_id, None)
    messages_removed = len(purged) if purged else 0
    return jsonify({
        "success": True,
        "session_id": session_id,
        "messages_removed": messages_removed,
        "message": f"Session memory flushed ({messages_removed} message(s) removed).",
    })


# ----------------------------------------------------------------------------
# API: Password Audit (explicit-click only; no keystroke hooks)
# ----------------------------------------------------------------------------
@app.route("/api/password/audit", methods=["POST"])
@json_only
@rate_limit
def api_password_audit():
    data = request.get_json(force=True, silent=True) or {}
    password = str(data.get("password", ""))

    if not password:
        return jsonify({"success": False, "error": "Password required"}), 400

    result = password_analyzer["audit"](password)
    guidance = password_analyzer["guidance"]()

    return jsonify({
        "success": True,
        "audit": result.to_dict(),
        "guidance": guidance,
    })


@app.route("/api/password/entropy", methods=["POST"])
@json_only
@rate_limit
def api_password_entropy():
    """Lightweight server-side entropy (used for verification; client computes instantly)."""
    data = request.get_json(force=True, silent=True) or {}
    password = str(data.get("password", ""))
    return jsonify({
        "success": True,
        "entropy": password_analyzer["client_entropy"](password),
    })


# ----------------------------------------------------------------------------
# API: Scenarios
# ----------------------------------------------------------------------------
@app.route("/api/scenarios")
def api_scenarios():
    lab = request.args.get("lab", "all")  # all | phishing | soc
    category = request.args.get("category", "All Labs")
    scenarios = scenario_manager["filter"](lab=lab, category=category)
    return jsonify({
        "success": True,
        "categories": scenario_manager["categories"](),
        "active_category": category,
        "lab": lab,
        "count": len(scenarios),
        "scenarios": scenarios,
    })


@app.route("/api/scenarios/<scenario_id>")
def api_scenario_detail(scenario_id):
    scenario = scenario_manager["get"](scenario_id)
    if not scenario:
        return jsonify({"success": False, "error": "Scenario not found"}), 404
    return jsonify({"success": True, "scenario": scenario})


@app.route("/api/scenarios/<scenario_id>/evaluate", methods=["POST"])
@json_only
def api_scenario_evaluate(scenario_id):
    data = request.get_json(force=True, silent=True) or {}
    selected = data.get("selected_index")
    if selected is None or not isinstance(selected, int):
        return jsonify({"success": False, "error": "selected_index (int) required"}), 400
    result = scenario_manager["evaluate"](scenario_id, selected)
    return jsonify({"success": result.pop("valid", False), "evaluation": result})


# ----------------------------------------------------------------------------
# API: Error Analyzer (security telemetry analysis)
# ----------------------------------------------------------------------------
@app.route("/api/error-analyzer", methods=["POST"])
@json_only
@rate_limit
def api_error_analyzer():
    data = request.get_json(force=True, silent=True) or {}
    problem_type = str(data.get("problem_type", "Auto-detect")).strip()
    environment = str(data.get("environment", "")).strip()
    evidence = str(data.get("evidence", "")).strip()

    # Input validation
    valid, result = validate_analyzer_input(evidence)
    if not valid:
        return jsonify({"success": False, "error": result}), 400
    evidence = result  # sanitized

    if not evidence:
        return jsonify({"success": False, "error": "Evidence required"}), 400

    # Wrap evidence in delimiter for LLM processing
    wrapped_evidence = wrap_user_evidence(evidence)

    # For now, return a structured analysis response
    # In a full implementation, this would call an LLM with the wrapped evidence
    analysis = {
        "problem_type": problem_type or "Auto-detect",
        "environment": environment or "Unknown",
        "evidence_received": True,
        "evidence_length": len(evidence),
        "note": "Security analysis would be performed here with wrapped evidence. The evidence is wrapped in delimiter tags to prevent injection.",
        "redaction_applied": True,
        "suggested_fixes": [
            "Review telemetry for sensitive data before submission",
            "Ensure delimiter tags are not present in raw evidence",
            "Use the Cyber Error Analyzer tab for detailed analysis"
        ],
        "severity": "INFO"
    }

    return jsonify({
        "success": True,
        "report": analysis
    })


# ----------------------------------------------------------------------------
# API: Cheat Sheets (multi-tier reference matrices)
# ----------------------------------------------------------------------------
CHEAT_SHEETS = {
    "beginner": {
        "tier": "Beginner",
        "matrices": [
            {
                "title": "Critical Ports Matrix",
                "headers": ["Port", "Service", "Protocol", "SOC Note"],
                "rows": [
                    ["21", "FTP", "TCP", "Cleartext creds — block; use SFTP"],
                    ["22", "SSH", "TCP", "Key-based auth only; disable root login"],
                    ["23", "Telnet", "TCP", "Legacy cleartext — eliminate"],
                    ["25", "SMTP", "TCP", "Mail relay; watch for open relays"],
                    ["53", "DNS", "TCP/UDP", "Tunneling vector; monitor query volume"],
                    ["80", "HTTP", "TCP", "Redirect to 443; inspect for SQLi"],
                    ["443", "HTTPS", "TCP", "TLS inspection at proxy"],
                    ["445", "SMB", "TCP", "Lateral movement; restrict ADMIN$"],
                    ["3389", "RDP", "TCP", "Brute-force target; gate behind VPN/MFA"],
                    ["8080", "HTTP-Alt", "TCP", "Often proxy/mgmt — audit access"],
                ],
            },
            {
                "title": "Linux Hardening & Permission Audit",
                "headers": ["Command", "Purpose"],
                "rows": [
                    ["chmod 700 /etc/shadow", "Restrict shadow file to root"],
                    ["chown root:root /etc/passwd", "Verify ownership of passwd"],
                    ["find / -perm -4000 -type f 2>/dev/null", "SUID discovery for privesc audit"],
                    ["ss -tulnp", "List listening sockets with owning process"],
                    ["netstat -tulnp", "Legacy listening-socket enumeration"],
                    ["passwd -S <user>", "Check password status/aging"],
                    ["chage -l <user>", "Review password expiry policy"],
                    ["ls -la /var/log", "Inspect log directory permissions"],
                ],
            },
            {
                "title": "Essential Nmap Reconnaissance Flags",
                "headers": ["Flag", "Meaning"],
                "rows": [
                    ["-sS", "SYN stealth scan (half-open)"],
                    ["-sV", "Service/version detection"],
                    ["-O", "OS fingerprinting"],
                    ["-p-", "Scan all 65535 ports"],
                    ["-T4", "Aggressive timing template"],
                    ["-A", "Aggressive: OS + version + scripts"],
                    ["--script vuln", "Run NSE vulnerability scripts"],
                    ["-Pn", "Treat host as online (skip ping)"],
                ],
            },
        ],
    },
    "intermediate": {
        "tier": "Intermediate",
        "matrices": [
            {
                "title": "OWASP Top 10 (2021) Mitigations",
                "headers": ["Risk", "Mitigation & Secure Coding"],
                "rows": [
                    ["A01 Broken Access Control", "Enforce deny-by-default; check authz on every endpoint"],
                    ["A02 Cryptographic Failures", "TLS everywhere; Argon2id/bcrypt for passwords"],
                    ["A03 Injection", "Parameterized queries; never string-concatenate SQL"],
                    ["A04 Insecure Design", "Threat-model; add rate limits and business-logic checks"],
                    ["A05 Security Misconfig", "Harden images; remove defaults; disable verbose errors"],
                    ["A06 Vulnerable Components", "SBOM + dependency scanning; patch promptly"],
                    ["A07 Auth Failures", "MFA; lockout; credential stuffing protection"],
                    ["A08 Software/Data Integrity", "Sign releases; verify deserialization inputs"],
                    ["A09 Logging Failures", "Centralize logs; alert on anomalies"],
                    ["A10 SSRF", "Allow-list egress; validate user-supplied URLs"],
                ],
            },
            {
                "title": "Windows Security Event IDs",
                "headers": ["Event ID", "Meaning", "Analyst Action"],
                "rows": [
                    ["4624", "Successful logon", "Baseline; spot anomalous LogonTypes"],
                    ["4625", "Failed logon", "Spraying/brute-force detection (0xC000006A)"],
                    ["4688", "Process creation", "Enable command-line auditing"],
                    ["4720", "User account created", "Watch for rogue accounts"],
                    ["4768", "Kerberos TGT request", "AS-REP roasting indicator"],
                    ["4769", "Kerberos service ticket", "Kerberoasting (0x17 RC4)"],
                    ["7045", "New service installed", "PsExec/PSEXESVC lateral movement"],
                ],
            },
            {
                "title": "Sysmon Critical Event IDs",
                "headers": ["Event ID", "Event", "Key Fields"],
                "rows": [
                    ["1", "Process Creation", "Image, CommandLine, ParentImage"],
                    ["3", "Network Connection", "Image, DestinationIp, DestinationPort"],
                    ["7", "Image Load", "Image, ImageLoaded (DLL hijack)"],
                    ["10", "Process Access", "SourceImage, TargetImage (LSASS access)"],
                    ["11", "File Created", "TargetFilename (drop artifacts)"],
                    ["22", "DNS Query", "QueryName (C2 domain detection)"],
                ],
            },
        ],
    },
    "advanced": {
        "tier": "Advanced",
        "matrices": [
            {
                "title": "Active Directory Attack & Defense Matrix",
                "headers": ["Attack", "Signature", "Defense"],
                "rows": [
                    ["Kerberoasting", "4769 with EncType 0x17 (RC4) spike", "gMSA; disable RC4; monitor TGS anomalies"],
                    ["Pass-the-Hash", "NTLM 4624 LogonType 3 + ADMIN$ writes", "LAPS; restrict local admin; constrain NTLM"],
                    ["DCSync", "4662/4672 on DC; replication rights abuse", "Protect Domain Admins; audit replication"],
                    ["AS-REP Roasting", "4768 failures RC4; pre-auth disabled", "Require pre-auth on all accounts"],
                    ["Golden Ticket", "Forged TGT with KRBTGT hash", "Monitor TGT lifetimes; rotate KRBTGT"],
                ],
            },
            {
                "title": "Splunk SPL & Sigma — Encoded Execution / LOLBins",
                "headers": ["Query", "Purpose"],
                "rows": [
                    ["index=sysmon EventCode=1 CommandLine=\"*-enc*\"", "Base64 PowerShell execution"],
                    ["index=sysmon EventCode=1 Image=*powershell*| stats count by host", "PS usage volume"],
                    ["index=sysmon EventCode=3 DestinationPort=4444", "Common C2 port beacon"],
                    ["sigma: powershell -enc with parent != explorer.exe", "Fileless download cradle"],
                    ["index=* certutil.exe -decode", "LOLBin certutil staging"],
                    ["index=sysmon EventCode=1 Image=*mshta*", "MSHTA execution (fileless)"],
                ],
            },
            {
                "title": "Volatility 3 Memory Forensics",
                "headers": ["Plugin", "Purpose"],
                "rows": [
                    ["windows.pslist", "Enumerate running processes"],
                    ["windows.malfind", "Detect injected/hollowed code"],
                    ["windows.netscan", "Network connections per process"],
                    ["windows.cmdline", "Recover command-line arguments"],
                    ["windows.filescan", "Locate file objects in memory"],
                    ["windows.hashdump", "Extract SAM password hashes"],
                    ["windows.psscan", "Find hidden/terminated processes"],
                ],
            },
        ],
    },
}


@app.route("/api/cheatsheets")
def api_cheatsheets():
    tiers = ["beginner", "intermediate", "advanced"]
    return jsonify({
        "success": True,
        "tiers": tiers,
        "sheets": CHEAT_SHEETS,
    })


@app.route("/api/cheatsheets/<tier>")
def api_cheatsheet_tier(tier):
    tier = (tier or "beginner").lower()
    sheet = CHEAT_SHEETS.get(tier)
    if not sheet:
        return jsonify({"success": False, "error": f"Tier '{tier}' not found"}), 404
    return jsonify({"success": True, "sheet": sheet})


# ----------------------------------------------------------------------------
# API: Token stats / session info
# ----------------------------------------------------------------------------
@app.route("/api/stats")
def api_stats():
    return jsonify({
        "success": True,
        "llm": llm_service.get_token_stats(),
        "active_sessions": len(SERVER_CHAT_MEMORY),
        "scenarios": len(scenario_manager["all"]()),
    })


# ----------------------------------------------------------------------------
# Error handlers
# ----------------------------------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    return jsonify({"success": False, "error": "Not found"}), 404


@app.errorhandler(500)
def server_error(e):
    logger.exception("Unhandled server error")
    return jsonify({"success": False, "error": "Internal server error"}), 500


def main():
    """Entry point — strictly local runtime (http://127.0.0.1:5000).

    Security Pillar 5: DEBUG defaults to False; Pillar 3: no secrets here.
    The bind address is loopback-only so the simulator is never exposed on
    LAN interfaces (classroom NAT safety).
    """
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="127.0.0.1", port=port, debug=debug, threaded=True)


if __name__ == "__main__":
    main()
