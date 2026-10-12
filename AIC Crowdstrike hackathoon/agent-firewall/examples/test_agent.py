"""Tests for the demo agent (examples/). Run: pytest -q   (offline; the live scan is in test_scanner.py)."""
import os as _os, sys as _sys
_here = _os.path.dirname(_os.path.abspath(__file__))
for _p in (_here, _os.path.dirname(_here)):  # import the firewall library from the repo root
    if _p not in _sys.path:
        _sys.path.insert(0, _p)

from types import SimpleNamespace

import agentfw
from agentfw import run_agent
from payloads import ATTACKS, DOCS, IMAGE_DOCS


def test_every_attack_doc_names_an_outside_address():
    """Each attack needs an outside address for the key to be sent to."""
    for atk in ATTACKS:
        text = DOCS[atk] if atk in DOCS else IMAGE_DOCS[atk]["hidden"]
        assert "@" in text, atk


class FakeClient:
    """Shaped like openai.OpenAI(): asks to read the image doc once, then stops. Records every request."""

    def __init__(self):
        self.requests = []
        self.chat = SimpleNamespace(completions=self)

    def create(self, **kwargs):
        self.requests.append(list(kwargs["messages"]))
        if len(self.requests) == 1:
            fn = SimpleNamespace(name="read_doc", arguments='{"name": "atk_image_memo"}')
            msg = SimpleNamespace(content=None, tool_calls=[SimpleNamespace(id="t1", function=fn)])
        else:
            msg = SimpleNamespace(content="It's an office move memo.", tool_calls=None)
        return SimpleNamespace(choices=[SimpleNamespace(message=msg)])


def test_image_doc_is_sent_to_model_as_image(monkeypatch):
    fake = FakeClient()
    monkeypatch.setattr(agentfw, "get_client", lambda: fake)
    r = run_agent("Summarize the document 'atk_image_memo' for me.", defense=True)
    *_, tool_msg, image_msg = fake.requests[1]
    assert tool_msg["role"] == "tool" and tool_msg["tool_call_id"] == "t1"
    image = image_msg["content"][1]
    assert image["type"] == "image_url"
    assert image["image_url"]["url"].startswith("data:image/png;base64,")
    assert r["reply"] == "It's an office move memo."
