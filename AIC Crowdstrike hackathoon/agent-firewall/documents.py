"""Read documents and attachments of any size, for two callers.

The firewall (firewall.py) stays dependency-free and format-agnostic; this module is the
optional helper it leans on, injected as POLICY["attachment_reader"]. It has two jobs:

  extract_text(attachment)   -> str | None   (for the FIREWALL's egress DLP)
      Pulls every readable character out of a file so secrets can't hide in an attachment:
      PDF text, OCR of images and scanned PDFs, or plain text. Returns None when the file
      cannot be read at all (e.g. an image but no OCR engine) so the firewall can decide
      whether to fail closed. Bounded so a massive file never exhausts memory or context.

  load_document(path)        -> {"text", "images", "note"}   (for the demo AGENT)
      Turns a file into model-ready content: PDF -> text, image -> downscaled vision input.

Bounds (override with env vars): large files are capped, not rejected.
"""
import base64
import io
import os

MAX_PDF_PAGES = int(os.getenv("MAX_PDF_PAGES", "50"))            # pages the agent reads for context
DLP_MAX_PDF_PAGES = int(os.getenv("DLP_MAX_PDF_PAGES", "300"))   # pages the firewall scans for secrets
MAX_DOC_CHARS = int(os.getenv("MAX_DOC_CHARS", "20000"))         # characters kept for the agent
DLP_MAX_CHARS = int(os.getenv("DLP_MAX_CHARS", "200000"))        # characters scanned by the firewall
MAX_IMAGE_PX = int(os.getenv("MAX_IMAGE_PX", "1568"))            # longest side of an image we process
MAX_SCAN_PAGES = int(os.getenv("MAX_SCAN_PAGES", "5"))           # pages rendered when a PDF has no text
MAX_IMAGE_PIXELS = int(os.getenv("MAX_IMAGE_PIXELS", str(80_000_000)))  # decompression-bomb ceiling

IMAGE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tiff"}


def kind_of(name):
    ext = os.path.splitext(name)[1].lower()
    return "pdf" if ext == ".pdf" else "image" if ext in IMAGE_EXT else "text"


# ---------------- low-level readers ----------------
def _open_image(raw):
    from PIL import Image

    Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS  # guards against decompression bombs
    img = Image.open(io.BytesIO(raw))
    if max(img.size) > MAX_IMAGE_PX:
        img = img.copy()
        img.thumbnail((MAX_IMAGE_PX, MAX_IMAGE_PX))  # shrink in place, keep aspect ratio
    return img


def image_part_from_bytes(raw, media_type="image/png"):
    """A base64 image part for the model, downscaled if larger than the model needs."""
    img = _open_image(raw)
    buf = io.BytesIO()
    fmt = "PNG" if img.mode in ("RGBA", "P", "LA") else "JPEG"
    img.convert("RGB" if fmt == "JPEG" else img.mode).save(buf, format=fmt)
    data = base64.standard_b64encode(buf.getvalue()).decode()
    return {"type": "image_url", "image_url": {"url": f"data:image/{fmt.lower()};base64,{data}"}}


def image_ocr(raw):
    """Read any text rendered inside an image. None if no OCR engine is available."""
    try:
        import pytesseract

        return pytesseract.image_to_string(_open_image(raw)) or ""
    except Exception:
        return None  # pytesseract missing, Tesseract binary missing, or an unreadable image


def _pdf_text(path_or_bytes, max_pages):
    from pypdf import PdfReader

    reader = PdfReader(io.BytesIO(path_or_bytes) if isinstance(path_or_bytes, bytes) else path_or_bytes)
    pages = min(len(reader.pages), max_pages)
    out = []
    for i in range(pages):
        try:
            out.append(reader.pages[i].extract_text() or "")
        except Exception:
            out.append("")
    return "\n".join(out).strip(), len(reader.pages), pages


def _pdf_page_images(path_or_bytes, limit):
    import fitz  # PyMuPDF

    stream = path_or_bytes if isinstance(path_or_bytes, bytes) else open(path_or_bytes, "rb").read()
    out = []
    with fitz.open(stream=stream, filetype="pdf") as doc:
        for i in range(min(len(doc), limit)):
            out.append(doc[i].get_pixmap(dpi=120).tobytes("png"))
    return out


# ---------------- firewall-facing: extract every readable character ----------------
def _as_bytes_and_name(attachment):
    """Normalize a path / bytes / {path|filename, data} into (raw_bytes_or_path, name)."""
    if isinstance(attachment, dict):
        name = attachment.get("filename") or attachment.get("path") or "attachment"
        if "data" in attachment:
            data = attachment["data"]
            raw = data if isinstance(data, bytes) else base64.b64decode(data)
            return raw, name
        return attachment.get("path", ""), name
    if isinstance(attachment, bytes):
        return attachment, "attachment"
    return attachment, os.path.basename(attachment)  # a path string


def extract_text(attachment):
    """All readable text in an attachment, or None if it cannot be read. For firewall DLP."""
    source, name = _as_bytes_and_name(attachment)
    if isinstance(source, str):
        if not source or not os.path.exists(source):
            return None
        source = open(source, "rb").read()
    kind = kind_of(name)
    try:
        if kind == "pdf":
            text, _, _ = _pdf_text(source, DLP_MAX_PDF_PAGES)
            if not text:  # scanned PDF: OCR the rendered pages
                parts = [image_ocr(p) for p in _pdf_page_images(source, MAX_SCAN_PAGES)]
                text = "\n".join(p for p in parts if p)
                if not any(p is not None for p in parts):
                    return None  # no text layer and no OCR engine
            return text[:DLP_MAX_CHARS]
        if kind == "image":
            text = image_ocr(source)
            return None if text is None else text[:DLP_MAX_CHARS]
        return source.decode("utf-8", errors="replace")[:DLP_MAX_CHARS]
    except Exception:
        return None


# ---------------- agent-facing: model-ready content ----------------
def _cap(text):
    return (text, "") if len(text) <= MAX_DOC_CHARS else (text[:MAX_DOC_CHARS], f"text truncated to {MAX_DOC_CHARS} chars")


def load_document(path):
    """{"text", "images", "note"} for the agent. PDF -> text, image -> downscaled vision input."""
    if not os.path.exists(path):
        return {"text": "Document not found.", "images": [], "note": ""}
    try:
        kind = kind_of(path)
        if kind == "image":
            with open(path, "rb") as f:
                part = image_part_from_bytes(f.read(), f"image/{os.path.splitext(path)[1].lstrip('.') or 'png'}")
            return {"text": f"[image document: {os.path.basename(path)}]", "images": [part], "note": ""}
        if kind == "pdf":
            text, total, read = _pdf_text(path, MAX_PDF_PAGES)
            if text:
                text, cap = _cap(text)
                note = "; ".join(filter(None, [f"read {read} of {total} pages" if read < total else "", cap]))
                return {"text": text, "images": [], "note": note}
            imgs = [image_part_from_bytes(p, "image/png") for p in _pdf_page_images(path, MAX_SCAN_PAGES)]
            return {"text": f"[scanned PDF: {os.path.basename(path)}]", "images": imgs,
                    "note": f"no text layer; rendered {len(imgs)} of {total} pages"}
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            text, note = _cap(f.read())
        return {"text": text, "images": [], "note": note}
    except Exception as e:
        return {"text": f"[could not read document: {type(e).__name__}]", "images": [], "note": str(e)[:200]}
