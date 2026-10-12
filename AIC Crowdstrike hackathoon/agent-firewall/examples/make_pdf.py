"""Generate sample PDF attachments to demo attachment DLP.  Run: python make_pdf.py

Writes two PDFs under examples/docs/:
  report_clean.pdf   a normal multi-page report (no secret)
  report_leak.pdf    the same, but with the API key buried on a late page
Then shows the firewall blocking the leaky one when it is attached to an email.
"""
import os as _os, sys as _sys
_here = _os.path.dirname(_os.path.abspath(__file__))
for _p in (_here, _os.path.dirname(_here)):  # import the firewall library from the repo root
    if _p not in _sys.path:
        _sys.path.insert(0, _p)

import os

from agentfw import POLICY, SECRET
from firewall import Firewall
from reportlab.pdfgen import canvas

DOCS = os.path.join(_here, "docs")


def write_pdf(path, pages, secret_on=None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    c = canvas.Canvas(path)
    for i in range(pages):
        c.drawString(72, 740, f"Acme quarterly report - page {i + 1} of {pages}")
        c.drawString(72, 710, "Revenue grew 12% QoQ to $4.1M. Churn fell to 2.3%.")
        if secret_on == i:
            c.drawString(72, 680, f"Appendix: production API key {SECRET}")
        c.showPage()
    c.save()
    return path


if __name__ == "__main__":
    clean = write_pdf(os.path.join(DOCS, "report_clean.pdf"), 12)
    leak = write_pdf(os.path.join(DOCS, "report_leak.pdf"), 12, secret_on=9)
    print("wrote", clean)
    print("wrote", leak)

    fw = Firewall(POLICY)
    for label, path in [("clean", clean), ("leak", leak)]:
        args = {"to": "security@acme.com", "subject": "Q3 report",
                "body": "See attached.", "attachments": [path]}
        print(f"\nsend with {label} PDF -> {fw.check('send_email', args) or 'allowed'}")
