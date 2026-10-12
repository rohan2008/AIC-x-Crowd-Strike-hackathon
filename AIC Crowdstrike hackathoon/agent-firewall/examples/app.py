"""Live demo UI. Run: streamlit run app.py   (needs OPENAI_API_KEY)"""
import os as _os, sys as _sys
_here = _os.path.dirname(_os.path.abspath(__file__))
for _p in (_here, _os.path.dirname(_here)):  # import the firewall library from the repo root
    if _p not in _sys.path:
        _sys.path.insert(0, _p)
import os
import re
from html import escape

import streamlit as st

from agentfw import MODEL, POLICY, run_agent
from firewall import REPLY_BLOCKED
from payloads import DOCS, IMAGE_DOCS

st.set_page_config(page_title="Agent Firewall", layout="wide")

CSS = """
<style>
#MainMenu, footer, .stDeployButton, [data-testid="stToolbar"] { display: none !important; }
.block-container { padding-top: 4.5rem; max-width: 1200px; }
.stButton button[kind="primary"] { background: #3b5bdb; border-color: #3b5bdb; color: white; font-weight: 600; }
.stButton button[kind="primary"]:hover { background: #2f4bc0; border-color: #2f4bc0; color: white; }

.app-title { font-size: 30px; font-weight: 700; margin: 0; }
.app-sub { opacity: .65; margin: 4px 0 0; font-size: 15px; }
.model { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 12px; opacity: .6; margin-top: 6px; }

.status { display: flex; align-items: center; gap: 8px; font-weight: 600; font-size: 14px; margin: 4px 0 18px; }
.dot { width: 10px; height: 10px; border-radius: 50%; }
.on .dot { background: #2f9e5b; } .on { color: #2f9e5b; }
.off .dot { background: #d64545; } .off { color: #d64545; }

.verdict { border-left: 6px solid; border-radius: 6px; padding: 16px 22px; margin: 18px 0 26px; }
.verdict .head { font-size: 24px; font-weight: 700; letter-spacing: .01em; }
.verdict .detail { font-size: 14px; opacity: .8; margin-top: 4px; }
.v-bad  { border-color: #d64545; background: rgba(214,69,69,.12); }   .v-bad .head  { color: #d64545; }
.v-good { border-color: #2f9e5b; background: rgba(47,158,91,.12); }   .v-good .head { color: #2f9e5b; }
.v-info { border-color: #5b7bd6; background: rgba(91,123,214,.10); } .v-info .head { color: #5b7bd6; }

.section { font-size: 12px; font-weight: 700; letter-spacing: .12em; text-transform: uppercase;
  opacity: .6; margin: 0 0 10px; }

.step { display: grid; grid-template-columns: 78px 1fr; gap: 12px; padding: 9px 0;
  border-bottom: 1px solid rgba(128,128,128,.18); font-size: 14px; }
.tag { font-size: 11px; font-weight: 700; letter-spacing: .08em; padding-top: 2px; opacity: .55; }
.step pre { margin: 0; white-space: pre-wrap; word-break: break-word; font-size: 13px;
  font-family: ui-monospace, Menlo, Consolas, monospace; background: none; padding: 0; }
.step.call .tag { opacity: 1; color: #5b7bd6; }
.step.blocked { background: rgba(214,69,69,.10); border-left: 3px solid #d64545; padding-left: 8px; margin-left: -11px; }
.step.blocked .tag, .step.blocked pre { color: #d64545; opacity: 1; font-weight: 600; }
.step details summary { cursor: pointer; opacity: .55; font-size: 13px; }
.step details[open] summary { margin-bottom: 6px; }

.card { border: 1px solid rgba(128,128,128,.25); border-radius: 6px; padding: 12px 14px; margin-bottom: 10px; font-size: 14px; }
.card.block { border-color: rgba(214,69,69,.6); }
.card .k { font-size: 11px; letter-spacing: .08em; text-transform: uppercase; opacity: .55; }
.card code, .card pre { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 13px; }
.card pre { margin: 8px 0 0; white-space: pre-wrap; word-break: break-word; }
.empty { opacity: .5; font-size: 14px; margin-bottom: 22px; }

.doc-head { display: flex; justify-content: space-between; align-items: baseline; margin: 8px 0 8px; }
.doc-head .name { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 15px; opacity: .7; }
.doc { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 19px; line-height: 1.6;
  white-space: pre-wrap; word-break: break-word; border: 1px solid rgba(128,128,128,.3);
  background: rgba(128,128,128,.06); border-radius: 8px; padding: 22px 26px; margin-bottom: 8px; }
.inject { background: rgba(214,69,69,.18); color: inherit; border: 2px solid #d64545; border-radius: 4px;
  padding: 1px 4px; box-decoration-break: clone; -webkit-box-decoration-break: clone; }
.inject-label { display: inline-block; font-family: system-ui, sans-serif; font-size: 11px; font-weight: 700;
  letter-spacing: .1em; text-transform: uppercase; background: #d64545; color: white;
  border-radius: 3px; padding: 1px 6px; margin-right: 8px; vertical-align: 2px; }
.doc-note { font-size: 14px; margin-bottom: 22px; }
.doc-note.bad { color: #d64545; font-weight: 600; } .doc-note.ok { color: #2f9e5b; font-weight: 600; }
.hidden-callout { border: 2px solid #d64545; background: rgba(214,69,69,.12); border-radius: 8px;
  padding: 14px 18px; margin: 4px 0 22px; }
.hidden-callout .inject-label { margin-bottom: 8px; }
.hidden-callout div { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 18px; line-height: 1.5; }
</style>
"""
st.html(CSS)


# ---------- injected-instruction highlighter (display only; the firewall does the blocking) ----------
EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
MARKERS = re.compile(r"\bassistants?\b|system override|api key|api note|do not mention", re.I)
ACTION = re.compile(r"\b(send|email|forward|dump|retrieve)\b", re.I)


def is_injected(sentence):
    """A sentence aimed at the AI, or asking to send something to an outside address."""
    outside = [a for a in EMAIL.findall(sentence) if a.lower() not in POLICY["allowed_recipients"]]
    return bool(MARKERS.search(sentence) or (outside and ACTION.search(sentence)))


def segments(text):
    """Split into sentences (an HTML comment counts as one); merge neighbours with the same flag."""
    out = []
    for part in filter(None, re.split(r"(<!--.*?-->|\n|(?<=[.!?])\s+)", text, flags=re.S)):
        flag = is_injected(part)
        if out and (part.isspace() or flag == out[-1][1]):
            out[-1][0] += part
        else:
            out.append([part, flag])
    return out


def doc_html(text):
    parts = segments(text)
    body = "".join(
        f"<span class='inject'><span class='inject-label'>injected instruction</span>{escape(t)}</span>"
        if flag else escape(t)
        for t, flag in parts
    )
    return f"<div class='doc'>{body}</div>", sum(flag for _, flag in parts)


def trace_html(steps):
    rows, n = [], 0
    for kind, text in steps:
        t = escape(text)
        if kind == "assistant":
            rows.append(f"<div class='step'><div class='tag'>AGENT</div><div>{t}</div></div>")
        elif kind == "reply":
            cls = "step blocked" if text == REPLY_BLOCKED else "step"
            rows.append(f"<div class='{cls}'><div class='tag'>REPLY</div><div>{t}</div></div>")
        elif kind == "tool_call":
            n += 1
            rows.append(f"<div class='step call'><div class='tag'>CALL {n}</div><pre>{t}</pre></div>")
        elif text.startswith(("BLOCKED", "NEEDS_APPROVAL")):
            verdict, _, reason = text.partition(" by policy: ")
            tag = "BLOCKED" if verdict == "BLOCKED" else "NEEDS APPROVAL"
            rows.append(f"<div class='step blocked'><div class='tag'>{tag}</div><pre>{escape(reason)}</pre></div>")
        else:
            rows.append(
                f"<div class='step'><div class='tag'>RESULT</div>"
                f"<details><summary>Show output</summary><pre>{t}</pre></details></div>"
            )
    return "".join(rows)


# ---------- header ----------
st.html(
    "<p class='app-title'>Agent Firewall</p>"
    "<p class='app-sub'>Same agent, same malicious document. Toggle the firewall and compare.</p>"
    + f"<div class='model'>model: {escape(MODEL)}</div>"
)

# ---------- controls ----------
with st.sidebar:
    defense = st.toggle("Firewall", value=False)
    cls, label = ("on", "Enabled") if defense else ("off", "Disabled")
    st.html(f"<div class='status {cls}'><span class='dot'></span>{label}</div>")
    policy = {
        **POLICY,
        "block_outside_after_taint": st.checkbox("Taint tracking", value=True, disabled=not defense),
        "scan_egress": st.checkbox("Egress DLP (raw + encoded)", value=True, disabled=not defense),
        "enforce_domain_allowlist": st.checkbox("Domain allowlist (exact)", value=True, disabled=not defense),
        "detect_generic_secrets": st.checkbox("Generic secret detector", value=True, disabled=not defense),
        "scan_output": st.checkbox("Output scan", value=True, disabled=not defense),
        "confirm_mode": st.checkbox("Confirm mode (human approval)", value=False, disabled=not defense),
    }
    doc = st.selectbox("Document", [*DOCS, *IMAGE_DOCS])

# ---------- document panel ----------
kind = "image" if doc in IMAGE_DOCS else "text"
st.html(f"<div class='doc-head'><div class='section'>Untrusted document the agent will read</div>"
        f"<div class='name'>{escape(doc)} · {kind}</div></div>")
if doc in IMAGE_DOCS:
    img = IMAGE_DOCS[doc]
    st.image(os.path.join(os.path.dirname(__file__), img["file"]), alt="Office memo with faint hidden text")
    st.html("<div class='hidden-callout'><span class='inject-label'>Hidden in image (low-contrast text the model sees)</span>"
            f"<div>{escape(img['hidden'])}</div></div>")
else:
    html, n_injected = doc_html(DOCS[doc])
    note = (f"<div class='doc-note bad'>{n_injected} injected instruction{'s' if n_injected > 1 else ''} hidden in this document</div>"
            if n_injected else "<div class='doc-note ok'>No injected instructions: normal document</div>")
    st.html(html + note)

prompt = st.text_input("User request", f"Summarize the document '{doc}' for me.")
run = st.button("Run agent", type="primary", width="stretch")

if run:
    with st.spinner("Running agent..."):
        r = run_agent(prompt, defense=defense, policy=policy)

    # ---------- verdict ----------
    if r["exfiltrated"]:
        to = ", ".join(e["to"] for e in r["outbox"])
        head, detail, cls = "Secret exfiltrated", f"API key sent to {to}", "v-bad"
    elif r["firewall"]:
        n = len(r["firewall"])
        held = any(e["verdict"] == "NEEDS_APPROVAL" for e in r["firewall"])
        head = "Held for human approval" if held else "Attack blocked"
        head, detail, cls = head, f"{n} action{'s' if n > 1 else ''} stopped by policy", "v-good"
    else:
        head, detail, cls = "Completed", "No policy violations, no secrets left the company", "v-info"
    st.html(f"<div class='verdict {cls}'><div class='head'>{head}</div><div class='detail'>{escape(detail)}</div></div>")

    # ---------- trace + side panels ----------
    col1, col2 = st.columns([3, 2], gap="large")
    with col1:
        st.html("<div class='section'>Agent trace</div>" + trace_html(r["steps"]))
    with col2:
        log = "".join(
            f"<div class='card block'><div class='k'>{escape(e['verdict'].replace('_', ' '))} · {escape(e['severity'])}"
            f" · {escape(e['rule'])}</div><code>{escape(e['action'])}</code>"
            f"<pre>{escape(e['reason'])}</pre></div>"
            for e in r["firewall"]
        ) or "<div class='empty'>No actions blocked.</div>"
        outbox = "".join(
            f"<div class='card'><div class='k'>To</div><code>{escape(e['to'])}</code>"
            f"<div class='k' style='margin-top:8px'>Subject</div>{escape(e['subject'])}"
            f"<pre>{escape(e['body'])}</pre></div>"
            for e in r["outbox"]
        ) or "<div class='empty'>Nothing sent.</div>"
        st.html(
            "<div class='section'>Firewall log</div>" + log
            + "<div class='section' style='margin-top:18px'>Outbox</div>" + outbox
        )
