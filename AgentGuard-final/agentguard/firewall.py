"""Small, deterministic outbound checks for the AgentGuard demo gateway.

Inspired by the linked agent-firewall project. This implementation is tailored
to AgentGuard's synthetic support records and does not copy its source.
"""
import base64
import binascii
import math
import re
from collections import Counter
from urllib.parse import unquote

from .data import CUSTOMERS

_CREDENTIAL_PATTERNS = (
    ("OPENAI_KEY", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("AWS_KEY", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GITHUB_TOKEN", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")),
    ("SLACK_TOKEN", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("PRIVATE_KEY", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
)
_OPAQUE_TOKEN = re.compile(r"[A-Za-z0-9+/_-]{32,}={0,2}")


def _looks_like_random_token(value):
    if len(value) < 32 or not all(re.search(pattern, value) for pattern in (r"[a-z]", r"[A-Z]", r"\d")):
        return False
    counts = Counter(value)
    entropy = -sum(count / len(value) * math.log2(count / len(value)) for count in counts.values())
    return entropy >= 4.0


def decoded_views(text):
    """Return bounded URL/base64/hex-decoded forms to catch simple encoding bypasses."""
    seen = {text}
    pending = [text]
    for _ in range(3):
        current = pending
        pending = []
        for value in current:
            candidates = [unquote(value)]
            candidates.extend(re.findall(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/])", value))
            candidates.extend(re.findall(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{16,}(?![A-Fa-f0-9])", value))
            compact = re.sub(r"\s+", "", value)
            if len(compact) >= 16 and len(compact) % 4 == 0 and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact):
                try:
                    candidates.append(base64.b64decode(compact, validate=True).decode("utf-8"))
                except (binascii.Error, UnicodeDecodeError, ValueError):
                    pass
            for encoded in list(candidates):
                normalized = re.sub(r"\s+", "", encoded)
                if len(normalized) >= 16 and len(normalized) % 4 == 0 and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", normalized):
                    try:
                        candidates.append(base64.b64decode(normalized, validate=True).decode("utf-8"))
                    except (binascii.Error, UnicodeDecodeError, ValueError):
                        pass
                if len(normalized) >= 16 and len(normalized) % 2 == 0 and re.fullmatch(r"[A-Fa-f0-9]+", normalized):
                    try:
                        candidates.append(bytes.fromhex(normalized).decode("utf-8"))
                    except (UnicodeDecodeError, ValueError):
                        pass
            if len(compact) >= 16 and len(compact) % 2 == 0 and re.fullmatch(r"[A-Fa-f0-9]+", compact):
                try:
                    candidates.append(bytes.fromhex(compact).decode("utf-8"))
                except (UnicodeDecodeError, ValueError):
                    pass
            for candidate in candidates:
                if candidate != value and candidate not in seen and len(candidate) <= 24000:
                    seen.add(candidate)
                    pending.append(candidate)
    return seen


def secret_reason(text):
    """Return a stable rule name when a message contains a known secret."""
    views = decoded_views(text)
    for customer in CUSTOMERS.values():
        if any(customer["private_note"] in value for value in views):
            return "PRIVATE_CANARY"
    for value in views:
        for rule, pattern in _CREDENTIAL_PATTERNS:
            if pattern.search(value):
                return rule
    for value in views:
        if any(_looks_like_random_token(token) for token in _OPAQUE_TOKEN.findall(value)):
            return "HIGH_ENTROPY_TOKEN"
    return None


def check_outbound(recipient, message, ticket):
    """Apply exact destination binding and DLP before the gateway records a reply."""
    if recipient != ticket["sender"]:
        return {"allowed": False, "rule": "RECIPIENT_BINDING",
                "reason": "Reply destination must exactly match the trusted ticket sender."}
    reason = secret_reason(message)
    if reason:
        return {"allowed": False, "rule": reason,
                "reason": "Outbound firewall found a known private marker or credential pattern in the reply."}
    return None
