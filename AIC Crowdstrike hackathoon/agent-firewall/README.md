# Agent Firewall

A small, deterministic policy layer that sits between an AI agent and the outside world and stops
prompt-injection-driven data exfiltration. It **inspects actions, not models**: it has no idea which
LLM, SDK, or framework is calling it, so it drops into any agent.

The library is two files at the repo root:

- **`firewall.py`** — the `Firewall` class. Standard library only; no model SDK, no app code.
- **`documents.py`** — an optional helper that reads PDF/image/text attachments so the firewall can
  scan inside them. Only this file pulls in `pypdf` / `pillow` (and `pytesseract` for image OCR).

Everything under **`examples/`** is a demo and test harness, not part of the library.

## Install

```bash
pip install -r requirements.txt     # pypdf + pillow for attachments; the rest is for the examples
```

`firewall.py` on its own needs nothing but the Python standard library.

## Use it

Build a `Firewall` from a policy that describes *your* tools, then call `check()` before every tool
call, `after()` once a tool has run, and `scan_reply()` before the model's reply reaches the user.

```python
import os
from firewall import Firewall
import documents   # provides the attachment reader; omit if you don't scan attachments

POLICY = {
    # which tools do what
    "untrusted_tools": {"read_email", "read_doc"},   # their output taints the context
    "outbound_tools": {"send_email": "to"},          # tool -> the arg holding the recipient
    "attachment_fields": ("attachments",),           # args on those tools that carry files

    # what's allowed out
    "allowed_recipients": {"alice@acme.com", "security@acme.com"},
    "allowed_domains": {"acme.com"},                 # exact match; acme.com.evil.io does NOT match

    # what to protect
    "secrets": [os.environ["PROD_API_KEY"]],         # known secrets, caught in any encoding
    "attachment_reader": documents.extract_text,     # opens PDFs/images to scan them

    # fail closed on attachments you can't read (e.g. images with no OCR engine)
    "block_unscannable_attachments": False,
}

fw = Firewall(POLICY)

# in your agent loop:
decision = fw.check("send_email", {"to": to, "subject": subj, "body": body, "attachments": files})
if decision:                       # truthy = stop. None = allow.
    return str(decision)           # "BLOCKED by policy: ..."  (or "NEEDS_APPROVAL ..." in confirm mode)
else:
    actually_send(...)
    fw.after("send_email")

reply = fw.scan_reply(model_reply)  # secrets in the reply become a safe placeholder
```

`check()` returns `None` to allow, or a `Decision` with `.verdict` (`"BLOCKED"` / `"NEEDS_APPROVAL"`),
`.rule`, `.severity` (`critical` / `high` / `medium`), and `.reason`. Every stop is also appended to
`fw.log` as a dict with those fields, so you can show or audit them.

The firewall is not email-specific. An HTTP tool whose destination arg holds a URL works the same way:
`"outbound_tools": {"http_post": "url"}`, `"allowed_domains": {"api.internal"}`.

## Rules

Every rule is deterministic, logs a reason + severity, and can be switched off in the policy.

| Rule | Policy switch | What it stops |
|---|---|---|
| **Egress DLP** | `scan_egress` | A secret in any outbound field — raw, base64, hex, URL-encoded, or inside a URL / query string. It decodes anything that looks encoded, then looks for secrets. |
| **Attachment DLP** | `scan_attachments` | A secret hidden inside an outbound **PDF, image, or text attachment**. Uses `attachment_reader` to extract the text (PDF text, OCR for images and scanned PDFs). Large files are page- and size-capped. With `block_unscannable_attachments`, a file it can't read is failed closed. |
| **Domain allowlist** | `enforce_domain_allowlist` | Lookalike domains: `team@acme.com.evil.io`, `acme.co`, `evil-acme.com`, `acme.com@evil.io`. Exact domain match. |
| **Taint tracking** | `block_outside_after_taint` | Once untrusted content (a read email/doc) is in context, only `allowed_recipients` can be contacted. |
| **Generic secrets** | `detect_generic_secrets` | Secrets you never registered: `sk-...`, AWS `AKIA...`, GitHub/Slack tokens, private keys, long high-entropy tokens. |
| **Output scan** | `scan_output` | A secret in the final reply is replaced with `[reply blocked: it contained a secret]`. |
| **Confirm mode** | `confirm_mode` | Risky calls return `NEEDS_APPROVAL` for a human instead of being blocked outright. |

Secret detection is shared by egress, attachment, and output scanning, so a key is caught the same way
whether it's in the body, a PDF, or the reply. It decodes base64 / hex / URL-encoding before matching,
so encoding a secret to sneak it out doesn't help.

### Massive PDFs and images

`documents.extract_text` is bounded so a huge attachment never exhausts memory or context:
PDFs are scanned up to `DLP_MAX_PDF_PAGES` pages and `DLP_MAX_CHARS` characters; images are downscaled
to `MAX_IMAGE_PX` on the longest side before OCR; a decompression-bomb ceiling (`MAX_IMAGE_PIXELS`)
rejects malicious images. All limits are env-var overridable. Image OCR needs the Tesseract binary; if
it isn't installed, images read as "unscannable" — set `block_unscannable_attachments` to fail closed.

## Test

```bash
python -m pytest -q
```

- `test_firewall.py` — the firewall rules, in isolation (no demo, no network).
- `test_attachments.py` — attachment DLP: secrets in PDF / text / image attachments, bounds, fail-closed.
- `examples/test_agent.py`, `examples/test_scanner.py` — the demo agent and scanner. The live scan
  tests call a model and are skipped unless `OPENAI_API_KEY` is set.

## Examples (`examples/`)

A runnable demo of the firewall protecting a toy OpenAI agent against a suite of prompt-injection docs.
Needs `OPENAI_API_KEY` (set `MODEL` to override the default `gpt-4.1-mini`).

```bash
cd examples
python make_pdf.py                  # build sample PDFs and show attachment DLP blocking a leak
python scanner.py                   # scan the agent: exposure score + scan_report.md
python -m streamlit run app.py      # single-attack demo with firewall toggle + policy switches
python -m streamlit run scan_app.py # the scan dashboard
```

- `firewall.py`, `documents.py` *(root)* — the library.
- `examples/agentfw.py` — a toy agent (read_doc, search_notes, send_email) wired through the firewall.
- `examples/payloads.py` — benign + prompt-injection documents, the attack suite.
- `examples/scanner.py` — runs every attack N times, rates severity, computes a 0-100 exposure score,
  and includes `detect_exploit(trace)`, which replays a run through the firewall read-only.
- `examples/app.py`, `examples/scan_app.py` — Streamlit demos.
- `examples/make_image.py`, `examples/make_pdf.py` — generate the image/PDF test documents.
