"""Agent firewall: a deterministic policy layer between an AI agent and the outside world.

It inspects actions, not models: it has no idea which LLM, SDK, or app is calling it.
Standard library only.

    fw = Firewall(policy)
    decision = fw.check(tool_name, args)   # before every tool call: None = allow
    fw.after(tool_name)                    # after a tool ran (untrusted tools taint the context)
    reply = fw.scan_reply(text)            # before the final reply reaches the user

Rules (each one can be switched off in the policy):
  egress_dlp        secrets in any outbound field: raw, base64, hex, URL-encoded, or inside a URL
  attachment_dlp    secrets hidden inside outbound attachments (PDF text, OCR'd images, text files),
                    using POLICY["attachment_reader"]; optionally fail closed on unreadable attachments
  domain_allowlist  outbound recipients must be on an allowed domain, exact match
                    (so "team@acme.com.evil.io" is NOT acme.com)
  taint             once untrusted content is in context, only allowlisted recipients
  generic_secrets   catch secrets nobody registered: sk-..., AKIA..., private keys, high-entropy tokens
  output_scan       a final reply containing a secret is replaced before the user sees it
  confirm_mode      risky tool calls return NEEDS_APPROVAL (human in the loop) instead of BLOCKED

firewall.py imports only the standard library. Attachment reading (PDF/OCR, heavy deps) is
injected as POLICY["attachment_reader"]; documents.extract_text is a ready-made one.
"""
import base64
import binascii
import math
import re
from collections import Counter
from dataclasses import dataclass
from urllib.parse import unquote_plus, urlparse

DEFAULT_POLICY = {
    "untrusted_tools": set(),       # tools whose output is untrusted (e.g. reading a doc or web page)
    "outbound_tools": {},           # tool name -> argument holding the recipient (email or URL), or None
    "allowed_recipients": set(),    # exact addresses allowed after the context is tainted
    "allowed_domains": set(),       # exact domains outbound tools may reach (empty = rule off)
    "secrets": [],                  # known secrets to protect, in any encoding
    "attachment_fields": (),        # arg names that carry file attachments (e.g. "attachments")
    "attachment_reader": None,      # callable(attachment) -> text | None; None text = unreadable
    "block_outside_after_taint": True,
    "scan_egress": True,
    "scan_attachments": True,       # open PDF/image attachments and scan their text for secrets
    "block_unscannable_attachments": False,  # fail closed when an attachment can't be read (no OCR, etc.)
    "enforce_domain_allowlist": True,
    "detect_generic_secrets": True,
    "scan_output": True,
    "confirm_mode": False,
}

REPLY_BLOCKED = "[reply blocked: it contained a secret]"


@dataclass
class Decision:
    """Why a tool call was stopped. A Decision is truthy; an allowed call gets None."""
    verdict: str   # "BLOCKED" or "NEEDS_APPROVAL"
    rule: str      # which rule fired
    severity: str  # "critical", "high", or "medium"
    reason: str    # one line a person can read

    def __str__(self):
        return f"{self.verdict} by policy: {self.reason}"


# ---------------- secret detection ----------------
SECRET_FORMATS = [
    ("API key (sk-...)", re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}")),
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}")),
    ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]
TOKEN = re.compile(r"[A-Za-z0-9+/_\-]{16,}={0,2}")   # anything that could be base64 / an opaque token
HEX = re.compile(r"\b(?:[0-9a-fA-F]{2}){8,}\b")


def entropy(s):
    """Shannon entropy in bits per character. Random keys score high, words score low."""
    return -sum(n / len(s) * math.log2(n / len(s)) for n in Counter(s).values())


def readable(raw):
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return text if text and all(c.isprintable() or c.isspace() for c in text) else None


def views(text):
    """The text as written, plus every decoding that might be hiding something in it."""
    out = [("raw", text)]
    unquoted = unquote_plus(text)
    if unquoted != text:
        out.append(("URL-encoded", unquoted))
    for source in (text, unquoted):
        for tok in HEX.findall(source):
            decoded = readable(bytes.fromhex(tok))
            if decoded:
                out.append(("hex-encoded", decoded))
        for tok in TOKEN.findall(source):
            tok = tok.rstrip("=").replace("+", "-").replace("/", "_")
            try:
                decoded = readable(base64.urlsafe_b64decode(tok + "=" * (-len(tok) % 4)))
            except (binascii.Error, ValueError):
                continue
            if decoded:
                out.append(("base64", decoded))
    return out


def find_secret(text, known=(), generic=True):
    """Describe the first secret hiding in text (e.g. "known secret, base64"), or None."""
    all_views = views(text)
    for encoding, view in all_views:
        if any(s and s in view for s in known):
            return f"known secret, {encoding}"
    if not generic:
        return None
    for encoding, view in all_views:
        for name, pattern in SECRET_FORMATS:
            if pattern.search(view):
                return f"{name}, {encoding}"
    for encoding, view in all_views[:2]:  # raw and URL-decoded only
        for tok in TOKEN.findall(view):
            mixed = all(re.search(c, tok) for c in (r"[a-z]", r"[A-Z]", r"\d"))  # random keys mix all three
            if len(tok) >= 32 and mixed and entropy(tok) >= 4.0:
                return f"high-entropy token, {encoding}"
    return None


def string_fields(value, path=""):
    """Every string inside a tool's arguments, with where it lives (e.g. 'body', 'headers.auth')."""
    if isinstance(value, str):
        yield path or "value", value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from string_fields(v, f"{path}.{k}" if path else str(k))
    elif isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            yield from string_fields(v, f"{path}[{i}]")


def _attachment_name(attachment):
    """A short label for an attachment (path / bytes / {filename|path,...}) for the log."""
    if isinstance(attachment, dict):
        return attachment.get("filename") or attachment.get("path") or "attachment"
    if isinstance(attachment, (bytes, bytearray)):
        return "attachment"
    return str(attachment).replace("\\", "/").rsplit("/", 1)[-1]


def domain_of(recipient):
    """'Team@Acme.com' -> 'acme.com';  'https://evil.io/x?k=1' -> 'evil.io'."""
    r = recipient.strip().lower()
    if "://" in r:
        return urlparse(r).hostname or ""
    return r.rpartition("@")[2]


# ---------------- firewall ----------------
class Firewall:
    def __init__(self, policy=None, enabled=True):
        self.policy = {**DEFAULT_POLICY, **(policy or {})}
        self.enabled = enabled
        self.tainted = False
        self.log = []  # one entry per stopped action: action, rule, severity, verdict, reason

    def _stop(self, action, rule, severity, reason):
        verdict = "NEEDS_APPROVAL" if self.policy["confirm_mode"] else "BLOCKED"
        self.log.append({"action": action, "rule": rule, "severity": severity, "verdict": verdict, "reason": reason})
        return Decision(verdict, rule, severity, reason)

    def _trusted(self, recipient):
        p = self.policy
        return recipient in p["allowed_recipients"] or domain_of(recipient) in p["allowed_domains"]

    def _secret(self, text):
        return find_secret(text, self.policy["secrets"], self.policy["detect_generic_secrets"])

    def check(self, tool_name, args):
        """Before a tool call. Returns None to allow, or a Decision saying why not."""
        p = self.policy
        if not self.enabled or tool_name not in p["outbound_tools"]:
            return None
        field = p["outbound_tools"][tool_name]
        to = str(args.get(field, "")).strip().lower() if field else ""
        action = f"{tool_name} to {to}" if to else tool_name

        attachment_names = set(p["attachment_fields"])
        if p["scan_egress"]:
            for name, value in string_fields(args):
                if name.split(".")[0].split("[")[0] in attachment_names:
                    continue  # attachments are binary; scan them separately below, not as strings
                found = self._secret(value)
                if found:
                    severity = "high" if to and self._trusted(to) else "critical"
                    return self._stop(action, "egress_dlp", severity,
                                      f"egress DLP: {found} in '{name}' going to {to or tool_name}")
        if p["scan_attachments"]:
            decision = self._scan_attachments(args, to, tool_name, action)
            if decision:
                return decision
        if p["enforce_domain_allowlist"] and p["allowed_domains"] and domain_of(to) not in p["allowed_domains"]:
            return self._stop(action, "domain_allowlist", "high",
                              f"domain allowlist: '{domain_of(to)}' is not an allowed domain (exact match required)")
        if p["block_outside_after_taint"] and self.tainted and to not in p["allowed_recipients"]:
            return self._stop(action, "taint", "medium",
                              f"taint: untrusted content is in context, and {to or 'this destination'} is not allowlisted")
        return None

    def _scan_attachments(self, args, to, tool_name, action):
        """Open each outbound attachment, read its text, and scan for secrets. None = allow."""
        p = self.policy
        reader = p["attachment_reader"]
        for field in p["attachment_fields"]:
            value = args.get(field)
            for att in value if isinstance(value, (list, tuple)) else [value] if value else []:
                label = _attachment_name(att)
                text = reader(att) if reader else None
                if text is None:
                    if p["block_unscannable_attachments"]:
                        return self._stop(action, "attachment_dlp", "high",
                                          f"attachment DLP: could not read attachment '{label}' to scan it")
                    continue
                found = self._secret(text)
                if found:
                    severity = "high" if to and self._trusted(to) else "critical"
                    return self._stop(action, "attachment_dlp", severity,
                                      f"attachment DLP: {found} inside attachment '{label}' going to {to or tool_name}")
        return None

    def after(self, tool_name):
        """After a tool ran: output from untrusted tools taints the context."""
        if tool_name in self.policy["untrusted_tools"]:
            self.tainted = True

    def scan_reply(self, text):
        """Before the final reply reaches the user. Returns the text to show."""
        if self.enabled and self.policy["scan_output"]:
            found = self._secret(text)
            if found:
                self.log.append({"action": "final reply", "rule": "output_scan", "severity": "high",
                                 "verdict": "BLOCKED", "reason": f"output scan: reply contained a {found}"})
                return REPLY_BLOCKED
        return text


__all__ = ["DEFAULT_POLICY", "REPLY_BLOCKED", "Decision", "Firewall", "find_secret", "domain_of"]
