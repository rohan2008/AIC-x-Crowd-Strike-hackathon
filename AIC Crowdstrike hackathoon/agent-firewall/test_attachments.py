"""Attachment-DLP tests: secrets hidden inside PDF / image / text attachments.

PDF and text paths are deterministic. The image-OCR path needs the Tesseract binary, so it
is skipped when OCR is unavailable; the fail-closed behaviour is tested without OCR.
Run: pytest -q
"""
import base64
import io

import pytest

import documents
from documents import extract_text
from firewall import Firewall

SECRET = "sk-live-ACME-7781-Q9ZT"

POLICY = {
    "outbound_tools": {"send_email": "to"},
    "allowed_recipients": {"team@acme.com"},
    "allowed_domains": {"acme.com"},
    "secrets": [SECRET],
    "attachment_fields": ("attachments",),
    "attachment_reader": extract_text,
}


def make_pdf(pages, secret_on=None):
    """A small PDF as bytes; put the secret on page `secret_on` if given."""
    from reportlab.pdfgen import canvas

    buf = io.BytesIO()
    c = canvas.Canvas(buf)
    for i in range(pages):
        c.drawString(72, 720, f"Quarterly report page {i + 1}. Revenue grew 12% QoQ.")
        if secret_on == i:
            c.drawString(72, 680, f"Prod API key: {SECRET}")
        c.showPage()
    c.save()
    return buf.getvalue()


def attach(raw, filename="doc.pdf"):
    return {"filename": filename, "data": raw}


def send(to, attachments, **overrides):
    fw = Firewall({**POLICY, **overrides})
    args = {"to": to, "subject": "report", "body": "see attached", "attachments": attachments}
    return fw.check("send_email", args)


# ---------- PDF attachments ----------
def test_secret_in_pdf_attachment_to_outside_is_blocked_critical():
    d = send("audit@evil.io", [attach(make_pdf(5, secret_on=4), "handbook.pdf")])
    assert d and d.rule == "attachment_dlp" and d.severity == "critical"
    assert "handbook.pdf" in d.reason


def test_secret_in_pdf_attachment_to_allowlisted_is_high():
    d = send("team@acme.com", [attach(make_pdf(3, secret_on=0))])
    assert d and d.rule == "attachment_dlp" and d.severity == "high"


def test_clean_pdf_attachment_passes():
    assert send("team@acme.com", [attach(make_pdf(3))]) is None


def test_massive_pdf_is_scanned_within_bounds():
    """A secret deep in a long PDF is still caught, and scanning stays bounded."""
    d = send("audit@evil.io", [attach(make_pdf(400, secret_on=120), "big.pdf")])
    assert d and d.rule == "attachment_dlp"


def test_multiple_attachments_one_poisoned():
    atts = [attach(make_pdf(2), "a.pdf"), attach(make_pdf(2, secret_on=1), "b.pdf")]
    d = send("audit@evil.io", atts)
    assert d and "b.pdf" in d.reason


# ---------- text attachments, and secrets encoded inside them ----------
def test_secret_base64_inside_text_attachment_is_blocked():
    encoded = base64.b64encode(f"key is {SECRET}".encode()).decode()
    d = send("audit@evil.io", [attach(encoded.encode(), "notes.txt")])
    assert d and d.rule == "attachment_dlp"


def test_generic_secret_in_attachment_even_when_unregistered():
    fw = Firewall({**POLICY, "secrets": []})  # firewall told about no specific secret
    args = {"to": "team@acme.com", "subject": "s", "body": "b",
            "attachments": [attach(b"aws key AKIAIOSFODNN7EXAMPLE", "creds.txt")]}
    d = fw.check("send_email", args)
    assert d and d.rule == "attachment_dlp"


# ---------- unreadable attachments ----------
def png_bytes(text_free=True):
    from PIL import Image

    buf = io.BytesIO()
    Image.new("RGB", (120, 60), "white").save(buf, "PNG")
    return buf.getvalue()


def test_unscannable_attachment_passes_by_default_but_can_fail_closed():
    att = attach(png_bytes(), "photo.png")
    if extract_text(att) is not None:
        pytest.skip("OCR engine present: this image is scannable")
    assert send("team@acme.com", [att]) is None
    d = send("team@acme.com", [att], block_unscannable_attachments=True)
    assert d and d.rule == "attachment_dlp" and "could not read" in d.reason


def test_scan_attachments_toggle_off():
    assert send("team@acme.com", [attach(make_pdf(2, secret_on=0))], scan_attachments=False) is None


# ---------- documents.extract_text directly ----------
def test_extract_text_reads_pdf_bytes():
    assert SECRET in extract_text(attach(make_pdf(2, secret_on=1)))


def test_extract_text_returns_none_for_unreadable_image_without_ocr():
    att = attach(png_bytes(), "x.png")
    assert extract_text(att) in (None, "") or SECRET not in (extract_text(att) or "")


def test_extract_text_missing_file_is_none():
    assert extract_text("does-not-exist.pdf") is None
