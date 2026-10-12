"""Extract PDF text locally in a short-lived, time-limited worker."""
import io
import json
import subprocess
import sys
from pathlib import Path

MAX_PDF_BYTES = 3 * 1024 * 1024
MAX_PAGES = 50
MAX_TEXT = 12000


def extract_pdf(data):
    if not data or len(data) > MAX_PDF_BYTES:
        raise ValueError("Choose a PDF between 1 byte and 3 MB.")
    if not data.startswith(b"%PDF-"):
        raise ValueError("The uploaded file is not a PDF.")
    try:
        result = subprocess.run(
            [sys.executable, "-m", "agentguard.pdf_ingest"], input=data,
            capture_output=True, timeout=15, check=False,
            cwd=Path(__file__).resolve().parent.parent,
        )
    except subprocess.TimeoutExpired as exc:
        raise ValueError("PDF extraction timed out. Try a smaller or simpler PDF.") from exc
    if result.returncode:
        raise ValueError("Could not read this PDF. Try exporting it again.")
    response = json.loads(result.stdout)
    if "error" in response:
        raise ValueError(response["error"])
    return response


def read_pdf(data):
    try:
        from pypdf import PdfReader
    except ImportError:
        return {"error": "PDF support requires pypdf. Install requirements.txt and restart the server."}
    try:
        reader = PdfReader(io.BytesIO(data))
        if reader.is_encrypted:
            return {"error": "Password-protected PDFs are not supported. Upload an unlocked copy."}
        if len(reader.pages) > MAX_PAGES:
            return {"error": "Choose a PDF with 50 pages or fewer."}
        parts = []
        for page in reader.pages:
            parts.append((page.extract_text() or "").strip())
            if len("\n\n".join(parts)) > MAX_TEXT:
                return {"error": "PDF text exceeds 12,000 characters. Upload a shorter excerpt."}
        text = "\n\n".join(part for part in parts if part).strip()
        if not text:
            return {"error": "No readable text found. Scanned PDFs need OCR before import."}
        return {"text": text, "pages": len(reader.pages)}
    except Exception:
        return {"error": "Could not read this PDF. Try exporting it again."}


if __name__ == "__main__":
    print(json.dumps(read_pdf(sys.stdin.buffer.read(MAX_PDF_BYTES + 1))))
