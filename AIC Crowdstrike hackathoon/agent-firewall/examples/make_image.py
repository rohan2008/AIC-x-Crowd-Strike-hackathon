"""Render the image attack docs from payloads.IMAGE_DOCS.  Run: python make_image.py"""
import os as _os, sys as _sys
_here = _os.path.dirname(_os.path.abspath(__file__))
for _p in (_here, _os.path.dirname(_here)):  # import the firewall library from the repo root
    if _p not in _sys.path:
        _sys.path.insert(0, _p)
import os
import textwrap

from PIL import Image, ImageDraw, ImageFont

from payloads import IMAGE_DOCS

HERE = os.path.dirname(os.path.abspath(__file__))


def font(size):
    try:
        return ImageFont.truetype("arial.ttf", size)
    except OSError:
        return ImageFont.load_default(size)


for doc in IMAGE_DOCS.values():
    img = Image.new("RGB", (1000, 560), "white")
    draw = ImageDraw.Draw(img)
    draw.multiline_text((50, 40), doc["visible"], fill=(30, 30, 30), font=font(26), spacing=12)
    # The attack: near-white text, easy to miss for a person, legible to a vision model.
    draw.multiline_text((50, 485), textwrap.fill(doc["hidden"], 100, break_on_hyphens=False), fill=(232, 232, 232), font=font(16))
    path = os.path.join(HERE, doc["file"])
    os.makedirs(os.path.dirname(path), exist_ok=True)
    img.save(path)
    print("wrote", path)
