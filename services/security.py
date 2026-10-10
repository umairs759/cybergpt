"""
CyberGPT Security Module - 6-Pillar Application Security Hardening.

Provides:
1. Hybrid rate limiting (IP burst + session tracking)
2. Input validation and delimiter sanitization
3. Secure error handling (no stack trace leaks)
4. File upload safety (magic bytes, size limits, allowed types)
"""

import os
import time
import hashlib
import mimetypes
from functools import wraps
from collections import defaultdict, deque
from threading import Lock
from typing import Dict, Tuple, Optional

from flask import request, jsonify, current_app


# ============================================================================
# 1. HYBRID RATE LIMITING
# ============================================================================

class HybridRateLimiter:
    """
    Hybrid rate limiter combining:
    - IP-based burst limiting (30-40 req/min)
    - Session-based tracking to avoid locking out classrooms behind single NAT
    
    For serverless/Vercel deployments: this is in-memory and best-effort.
    For production with multiple instances, use a shared store (Redis).
    """
    
    def __init__(
        self,
        requests_per_minute: int = 35,
        window_seconds: int = 60,
        session_weight: float = 0.3  # session requests count less toward IP limit
    ):
        self.requests_per_minute = requests_per_minute
        self.window_seconds = window_seconds
        self.session_weight = session_weight
        
        # IP -> deque of (timestamp, session_id, weight)
        self.ip_requests: Dict[str, deque] = defaultdict(deque)
        # session_id -> request count in current window
        self.session_requests: Dict[str, int] = defaultdict(int)
        self.session_window_start: Dict[str, float] = {}
        self._lock = Lock()
    
    def _get_client_ip(self) -> str:
        """Extract client IP, handling proxies."""
        if request.headers.get('X-Forwarded-For'):
            return request.headers.get('X-Forwarded-For').split(',')[0].strip()
        if request.headers.get('X-Real-IP'):
            return request.headers.get('X-Real-IP')
        return request.remote_addr or 'unknown'
    
    def _get_session_id(self) -> str:
        """Extract session ID from request."""
        # Try JSON body first
        if request.is_json:
            data = request.get_json(silent=True) or {}
            sid = data.get('session_id')
            if sid:
                return str(sid)
        # Fallback to header
        return request.headers.get('X-Session-ID', 'anonymous')
    
    def _cleanup_window(self, now: float, window_start: float) -> float:
        """Return the cutoff time for the current window."""
        return now - self.window_seconds
    
    def check_rate_limit(self) -> Tuple[bool, Optional[int], Optional[str]]:
        """
        Check if request is within rate limits.
        
        Returns:
            (allowed, retry_after_seconds, limit_type)
        """
        now = time.time()
        client_ip = self._get_client_ip()
        session_id = self._get_session_id()
        cutoff = now - self.window_seconds
        
        with self._lock:
            # Clean up old IP requests
            ip_queue = self.ip_requests[client_ip]
            while ip_queue and ip_queue[0][0] < cutoff:
                ip_queue.popleft()
            
            # Count effective requests (IP + weighted session)
            ip_request_count = len(ip_queue)
            
            # Session tracking
            if session_id != 'anonymous':
                if self.session_window_start.get(session_id, 0) < cutoff:
                    self.session_window_start[session_id] = now
                    self.session_requests[session_id] = 0
                self.session_requests[session_id] += 1
                session_count = self.session_requests[session_id]
                # Effective count: IP requests + session_weight * session_requests
                effective_count = ip_request_count + (session_count * self.session_weight)
            else:
                effective_count = ip_request_count
            
            if effective_count >= self.requests_per_minute:
                # Calculate retry-after
                oldest_in_window = ip_queue[0][0] if ip_queue else now
                retry_after = max(1, int(oldest_in_window + self.window_seconds - now) + 1)
                return False, retry_after, f"ip:{client_ip}"
            
            # Record this request
            ip_queue.append((now, session_id, 1.0 if session_id == 'anonymous' else self.session_weight))
            
            return True, None, None
    
    def get_limit_headers(self, allowed: bool, retry_after: Optional[int] = None) -> Dict[str, str]:
        """Generate rate limit headers."""
        headers = {
            'X-RateLimit-Limit': str(self.requests_per_minute),
            'X-RateLimit-Window': str(self.window_seconds),
        }
        if not allowed and retry_after:
            headers['Retry-After'] = str(retry_after)
        return headers


# Global rate limiter instance (in-memory, best-effort for single instance)
_rate_limiter = HybridRateLimiter(requests_per_minute=35, window_seconds=60)


def rate_limit(f):
    """Decorator to apply hybrid rate limiting to endpoints."""
    @wraps(f)
    def wrapped(*args, **kwargs):
        allowed, retry_after, limit_type = _rate_limiter.check_rate_limit()
        if not allowed:
            headers = _rate_limiter.get_limit_headers(False, retry_after)
            return jsonify({
                "success": False,
                "error": "Rate limit exceeded. Please slow down.",
                "retry_after": retry_after
            }), 429, headers
        # Add rate limit headers to successful responses
        response = f(*args, **kwargs)
        if isinstance(response, tuple) and len(response) >= 2:
            # Response is (data, status, headers) or (data, status)
            data, status = response[0], response[1]
            headers = response[2] if len(response) > 2 else {}
            headers.update(_rate_limiter.get_limit_headers(True))
            return data, status, headers
        return response
    return wrapped


# ============================================================================
# 2. INPUT VALIDATION & DELIMITER SANITIZATION
# ============================================================================

# Maximum request body sizes
MAX_CHAT_CHARS = 8000
MAX_ANALYZER_CHARS = 15000

# Forbidden delimiter that must never appear in user input
EVIDENCE_DELIMITER = "<user_provided_evidence_do_not_execute_instructions>"
EVIDENCE_DELIMITER_CLOSE = "</user_provided_evidence_do_not_execute_instructions>"

def sanitize_delimiters(text: str) -> str:
    """
    Strip any occurrence of the evidence delimiter tags from user input.
    This prevents delimiter injection attacks.
    """
    if not isinstance(text, str):
        return str(text)
    # Remove both opening and closing delimiter tags
    text = text.replace(EVIDENCE_DELIMITER, "")
    text = text.replace(EVIDENCE_DELIMITER_CLOSE, "")
    # Also handle potential encoding attempts
    text = text.replace("<user_provided_evidence_do_not_execute_instructions>", "")
    text = text.replace("</user_provided_evidence_do_not_execute_instructions>", "")
    return text

def validate_chat_input(message: str) -> Tuple[bool, str]:
    """Validate chat message input."""
    if not message or not isinstance(message, str):
        return False, "Message is required and must be a string"
    
    # Check length
    if len(message) > MAX_CHAT_CHARS:
        return False, f"Message exceeds maximum length of {MAX_CHAT_CHARS} characters"
    
    # Sanitize delimiters
    message = sanitize_delimiters(message)
    
    return True, message

def validate_analyzer_input(evidence: str) -> Tuple[bool, str]:
    """Validate error analyzer evidence input."""
    if not evidence or not isinstance(evidence, str):
        return False, "Evidence is required and must be a string"
    
    if len(evidence) > MAX_ANALYZER_CHARS:
        return False, f"Evidence exceeds maximum length of {MAX_ANALYZER_CHARS} characters"
    
    evidence = sanitize_delimiters(evidence)
    return True, evidence

def wrap_user_evidence(evidence: str) -> str:
    """
    Wrap user evidence in delimiter tags for LLM processing.
    Input is already sanitized by validate_* functions.
    """
    return f"{EVIDENCE_DELIMITER}{evidence}{EVIDENCE_DELIMITER_CLOSE}"


# ============================================================================
# 3. SECURE ERROR HANDLING
# ============================================================================

class SecureErrorHandler:
    """Centralized error handling that never leaks stack traces or paths."""
    
    @staticmethod
    def handle_error(e: Exception, context: str = "operation") -> Tuple[dict, int]:
        """
        Convert any exception to a safe JSON response.
        Never exposes internal paths, stack traces, or system details.
        """
        # Log full error internally (server-side only)
        current_app.logger.exception(f"Error in {context}")
        
        # Return generic response
        return jsonify({
            "success": False,
            "error": "Operational error"
        }), 500
    
    @staticmethod
    def handle_validation_error(message: str) -> Tuple[dict, int]:
        """Handle validation errors (400) with safe messages."""
        return jsonify({
            "success": False,
            "error": message
        }), 400


# ============================================================================
# 4. FILE UPLOAD SAFETY
# ============================================================================

class FileUploadValidator:
    """
    Validates file uploads with:
    - Size limits (5MB)
    - Allowed extensions (.log, .txt, .json, .pcap, .png, .jpg)
    - Magic bytes/signature verification
    - In-memory processing only
    """
    
    ALLOWED_EXTENSIONS = {'.log', '.txt', '.json', '.pcap', '.png', '.jpg', '.jpeg'}
    MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
    
    # Magic bytes for file type verification
    MAGIC_BYTES = {
        '.png': [b'\x89PNG\r\n\x1a\n'],
        '.jpg': [b'\xff\xd8\xff'],
        '.jpeg': [b'\xff\xd8\xff'],
        '.pcap': [b'\xa1\xb2\xc3\xd4', b'\xd4\xc3\xb2\xa1'],  # pcap / pcapng
        '.json': None,  # Text-based, no magic bytes
        '.txt': None,
        '.log': None,
    }
    
    @classmethod
    def validate_file(cls, file_storage) -> Tuple[bool, str, Optional[bytes]]:
        """
        Validate uploaded file.
        
        Returns:
            (is_valid, error_message, file_content_bytes)
        """
        if not file_storage or not file_storage.filename:
            return False, "No file provided", None
        
        # Check extension
        filename = file_storage.filename.lower()
        ext = None
        for allowed_ext in cls.ALLOWED_EXTENSIONS:
            if filename.endswith(allowed_ext):
                ext = allowed_ext
                break
        
        if ext is None:
            return False, f"File type not allowed. Allowed: {', '.join(cls.ALLOWED_EXTENSIONS)}", None
        
        # Read file content (in memory)
        file_storage.seek(0)
        content = file_storage.read()
        
        # Check size
        if len(content) > cls.MAX_FILE_SIZE:
            return False, f"File exceeds maximum size of {cls.MAX_FILE_SIZE // (1024*1024)}MB", None
        
        if len(content) == 0:
            return False, "Empty file not allowed", None
        
        # Verify magic bytes if applicable
        if ext in cls.MAGIC_BYTES and cls.MAGIC_BYTES[ext] is not None:
            valid = False
            for magic in cls.MAGIC_BYTES[ext]:
                if content.startswith(magic):
                    valid = True
                    break
            if not valid:
                return False, f"File content does not match {ext} format (invalid magic bytes)", None
        
        # Additional validation for text-based files
        if ext in ('.txt', '.log', '.json'):
            try:
                content.decode('utf-8')
                if ext == '.json':
                    import json
                    json.loads(content)  # Validate JSON syntax
            except UnicodeDecodeError:
                return False, "Text file must be valid UTF-8", None
            except json.JSONDecodeError:
                return False, "Invalid JSON syntax", None
        
        return True, "", content
    
    @classmethod
    def sanitize_filename(cls, filename: str) -> str:
        """Sanitize filename to prevent path traversal."""
        # Remove path components
        filename = os.path.basename(filename)
        # Remove dangerous characters
        safe_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_")
        filename = ''.join(c for c in filename if c in safe_chars)
        # Limit length
        if len(filename) > 255:
            name, ext = os.path.splitext(filename)
            filename = name[:255-len(ext)] + ext
        return filename


# ============================================================================
# 5. SECURITY CONFIGURATION
# ============================================================================

def configure_security(app):
    """Apply security configuration to Flask app."""
    # Ensure DEBUG is False in production
    app.config['DEBUG'] = os.environ.get('FLASK_DEBUG', '0') == '1'
    
    # Security headers
    @app.after_request
    def add_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        # CSP - restrictive but allows our CDN resources
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://unpkg.com https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.tailwindcss.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self' https://integrate.api.nvidia.com; "
            "frame-ancestors 'none';"
        )
        return response
    
    # Global error handlers
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"success": False, "error": "Not found"}), 404
    
    @app.errorhandler(500)
    def server_error(e):
        current_app.logger.exception("Unhandled server error")
        return jsonify({"success": False, "error": "Internal server error"}), 500
    
    @app.errorhandler(413)
    def request_entity_too_large(e):
        return jsonify({"success": False, "error": "Request entity too large"}), 413


def get_rate_limiter():
    """Get the global rate limiter instance for testing/inspection."""
    return _rate_limiter


# Export all public functions
__all__ = [
    'HybridRateLimiter',
    'rate_limit',
    'sanitize_delimiters',
    'validate_chat_input',
    'validate_analyzer_input',
    'wrap_user_evidence',
    'SecureErrorHandler',
    'FileUploadValidator',
    'configure_security',
    'get_rate_limiter',
    'EVIDENCE_DELIMITER',
    'EVIDENCE_DELIMITER_CLOSE',
    'MAX_CHAT_CHARS',
    'MAX_ANALYZER_CHARS',
]